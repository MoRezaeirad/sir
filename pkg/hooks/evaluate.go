package hooks

import (
	"fmt"
	"os"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
	"github.com/somoore/sir/pkg/signal"
)

// HookPayload is sir's normalized internal hook payload. It is a type alias
// for agent.HookPayload so the hooks package stays agent-agnostic while
// existing tests (and tests/bypass_test.go) continue to work unchanged.
type HookPayload = agent.HookPayload

// HookResponse is sir's internal verdict carrier inside the hooks package.
// It is NOT the wire-format response — adapters own that (see
// agent.ClaudeAgent.FormatPreToolUseResponse). Kept here so test code and
// handlers can pass decisions around as a single value.
type HookResponse struct {
	Decision policy.Verdict
	Reason   string
	// Floor marks a verdict that observe mode must NOT downgrade to allow. The
	// security floor — a credential leak heading to an untrusted MCP server, or
	// egress while the session carries secret context — is active exfiltration,
	// not a hypothetical "would block" worth silently allowing during an
	// observe-only rollout. Control-plane integrity (deny-all, session/lease
	// integrity) is already evaluated before observe is registered; Floor
	// extends that protection to the secret-exfil floor inside the gate chain.
	Floor bool
}

// Evaluate is the PreToolUse hook handler.
// It reads a hook payload from stdin, classifies the intent,
// evaluates it against the policy, logs to the ledger, and writes the response to stdout.
//
// ag is the host-agent adapter used to parse the incoming payload and format
// the outgoing response. Supported adapters: Claude Code, Codex.
func Evaluate(projectRoot string, ag agent.Agent) error {
	// Read stdin
	payload, err := readPayload(os.Stdin, ag)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	// Load or create session under file lock.
	// The lock covers the entire Load→Evaluate(mutate)→Save pipeline so
	// concurrent PreToolUse/PostToolUse hooks cannot corrupt session state.
	var l *lease.Lease
	var resp *HookResponse
	lockErr := session.WithSessionLock(projectRoot, func() error {
		var leaseMeta leaseLoadMetadata
		l, leaseMeta, err = loadLeaseWithMetadata(projectRoot)
		if err != nil {
			return fmt.Errorf("load lease: %w", err)
		}
		state, sErr := loadOrCreateSession(projectRoot, l, leaseMeta)
		if sErr != nil {
			return fmt.Errorf("load session: %w", sErr)
		}
		var eErr error
		resp, eErr = evaluatePayload(payload, l, state, projectRoot, ag)
		// Remember a denied tool_use_id so a later PostToolUse for it reveals an
		// executor that ignored the deny (hook-integrity check). PostToolUse only
		// fires for tools that actually ran, so a denied id reappearing there is a
		// real violation.
		if eErr == nil && resp != nil && resp.Decision == policy.VerdictDeny && payload.ToolUseID != "" {
			state.RecordDeniedToolUse(payload.ToolUseID)
			_ = state.Save()
		}
		return eErr
	})
	if lockErr != nil {
		return fmt.Errorf("evaluate: %w", lockErr)
	}

	// Write response to stdout via the agent adapter
	return writeResponse(os.Stdout, resp, ag)
}

// EvaluatePermissionRequest handles agents that expose a distinct
// PermissionRequest hook. The policy path is intentionally the same as
// PreToolUse so a permission prompt cannot gain broader authority than the
// tool call it represents.
func EvaluatePermissionRequest(projectRoot string, ag agent.Agent) error {
	payload, err := readPayload(os.Stdin, ag)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	var l *lease.Lease
	var resp *HookResponse
	lockErr := session.WithSessionLock(projectRoot, func() error {
		var leaseMeta leaseLoadMetadata
		l, leaseMeta, err = loadLeaseWithMetadata(projectRoot)
		if err != nil {
			return fmt.Errorf("load lease: %w", err)
		}
		state, sErr := loadOrCreateSession(projectRoot, l, leaseMeta)
		if sErr != nil {
			return fmt.Errorf("load session: %w", sErr)
		}
		var eErr error
		resp, eErr = evaluatePayload(payload, l, state, projectRoot, ag)
		// Remember a denied tool_use_id so a later PostToolUse for it reveals an
		// executor that ignored the deny (hook-integrity check). PostToolUse only
		// fires for tools that actually ran, so a denied id reappearing there is a
		// real violation.
		if eErr == nil && resp != nil && resp.Decision == policy.VerdictDeny && payload.ToolUseID != "" {
			state.RecordDeniedToolUse(payload.ToolUseID)
			_ = state.Save()
		}
		return eErr
	})
	if lockErr != nil {
		return fmt.Errorf("evaluate permission request: %w", lockErr)
	}

	return writePermissionRequestResponse(os.Stdout, resp, ag)
}

// evaluatePayload is the testable core of the PreToolUse handler.
//
// The optional trailing ag argument is used for OTLP telemetry attribution
// (sir.agent.id / sir.agent.name resource attributes). Variadic rather than
// a required parameter so the dozens of existing test callers don't need
// to be touched; when omitted, agent attribution is simply absent from the
// telemetry payload.
func evaluatePayload(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string, agOpt ...agent.Agent) (resp *HookResponse, err error) {
	var ag agent.Agent
	if len(agOpt) > 0 {
		ag = agOpt[0]
	}
	state.DecisionStartedAt = time.Now()
	if r, handled := evaluateSessionIntegrityGuard(state); handled {
		return r, nil
	}

	state.MaybeAdvanceTurn(time.Now())

	if r, handled := evaluateDenyAllGuard(state); handled {
		return r, nil
	}

	pendingInjectionDetail := consumePendingInjectionAlert(state)

	if r, handled := evaluateLeaseIntegrityGuard(projectRoot, state); handled {
		return r, nil
	}

	// Observe-only rollout: from here on, nothing blocks. The would-be verdict
	// is recorded in the ledger as a would_* decision (with detection IDs), and
	// the wire response is downgraded to allow on every return path below. The
	// control-plane integrity guards above run first and are never suppressed.
	if l != nil && l.ObserveOnly {
		defer func() {
			if err == nil {
				applyObserveMode(resp)
			}
		}()
	}

	// Thinking-aware transport guard (Claude Code): an interactive "ask" while
	// extended thinking is active corrupts the thinking stream and wedges the
	// conversation, so degrade ask->deny-with-guidance to keep the turn linear.
	// The degrade is computed once and stashed on the session so the wire guard
	// (this defer) and every ledger writer agree on a single answer. Registered
	// after the observe defer so that under observe mode the observe downgrade
	// (deny->allow) runs last and still wins (defers are LIFO).
	thinkingDegrade := thinkingDegradeActive(ag, payload)
	state.ThinkingGuardActive = thinkingDegrade
	defer func() {
		if err == nil {
			applyThinkingGuard(resp, thinkingDegrade)
		}
	}()

	// Collect signals from all sources (hook + registered signal providers).
	// The hook signal is declared_intent/pre_exec → ClassEnforces in hook_gate
	// mode. Signal providers augment with corroborating observations. If only
	// runtime signals are present (future non-hook path), enforceability
	// degrades to ClassDetects automatically via AnalyzeEnforceability.
	signals := signal.CollectSignals(payload, projectRoot)

	intent := MapToolToIntent(payload.ToolName, payload.ToolInput, l)
	labels := labelsForEvaluation(payload, intent, l, projectRoot)

	// Fail-closed on opaque shell execution: a command that pipes into an
	// interpreter reading its program from stdin (`base64 -d | sh`,
	// `curl … | sh`) cannot be classified, so a silent-allow verb is escalated
	// to ask. Go-only restriction (allow->ask, never widens a deny); only fires
	// when the mapped verb is low-risk so it never preempts a stricter gate.
	if oreason, escalate := opaqueShellEscalation(payload, intent); escalate {
		resp := &HookResponse{
			Decision: policy.VerdictAsk,
			Reason:   "Command " + oreason + " — sir cannot see what will run. Approve to proceed, or rewrite without piping into a shell.",
		}
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, l.ObserveOnly, ag)
		return resp, nil
	}

	// Verbatim context-laundering: an outbound/persisting action whose payload
	// contains the exact value of a secret that entered context earlier this
	// session. Hard deny (Go-only restriction; Floor so observe mode does not
	// downgrade an active exfil). This catches copy-paste exfil the secret-session
	// turn floor misses once the value has been laundered through context.
	if lreason, leak := outboundSecretLeak(payload, intent, state); leak {
		resp := &HookResponse{
			Decision: policy.VerdictDeny,
			Reason:   "Blocked — " + lreason + ". Run `sir unlock` only if you are certain this is intended.",
			Floor:    true,
		}
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, false, ag)
		return resp, nil
	}

	// DNS-tunneling / exfil destination: a long high-entropy hostname label is
	// the shape of base32/hex-encoded data smuggled out over DNS or HTTP. Hard
	// deny (Go-only restriction, stricter than the normal ask; never widens a
	// deny). Marked Floor so observe mode does not downgrade an active exfil.
	if treason, tunnel := dnsTunnelEscalation(intent); tunnel {
		resp := &HookResponse{
			Decision: policy.VerdictDeny,
			Reason:   "Blocked — " + treason + ". Run `sir unlock` only if you are certain this is legitimate.",
			Floor:    true,
		}
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, false, ag)
		return resp, nil
	}

	// sir self-protection: an agent write into sir's own state dir (~/.sir) or
	// config is a control-plane tamper. Hard deny (Go-only restriction — the
	// resolved state-dir path is a runtime fact Rust cannot see; never widens a
	// deny). Floor so observe mode does not downgrade an attempt to disable the
	// guard. v2's deny-sir-config-tamper already denies this; this is the
	// production-path parity.
	if sreason, tamper := sirStateTamper(intent, projectRoot); tamper {
		resp := &HookResponse{
			Decision: policy.VerdictDeny,
			Reason:   "Blocked — " + sreason + ". sir must not be modified by an agent. Run `sir unlock` only if you are certain this is intended.",
			Floor:    true,
		}
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, false, ag)
		return resp, nil
	}

	// sir self-modification (sir CLI subcommands that change sir's posture or
	// provider registry — including `sir provider authoritative`, which installs
	// the policy decision-maker). This is a NON-DELEGABLE floor: it short-circuits
	// BEFORE evaluatePolicy, so an authoritative policy provider CANNOT override
	// it. Without this, an injected agent under a permissive authoritative
	// provider could self-amplify by promoting its own provider (the O3 boundary).
	// It runs via the sir binary, so it also bypasses the sirStateTamper file-write
	// floor above — this is the shell-command counterpart. Ask (not deny): a human
	// operator running these at a terminal is unaffected (the hook gates the
	// AGENT's tool calls); an agent's attempt is held for explicit approval.
	if intent.Verb == policy.VerbSirSelf {
		resp := &HookResponse{
			Decision: policy.VerdictAsk,
			Reason:   "sir self-modification (`" + intent.Target + "`) requires your approval — this changes sir's own security posture and cannot be delegated to a policy provider.",
			Floor:    true,
		}
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, l.ObserveOnly, ag)
		return resp, nil
	}

	// Credential-helper / hooks-path config rewrite: the shell/config form of
	// credential theft and hook redirection. Ask (Go-only restriction, allow->ask,
	// never widens a deny; self-guards on verb risk so it never preempts a
	// stricter gate). Ask, not deny, because husky/lefthook legitimately set
	// core.hooksPath — same stance as the .git/hooks file floor.
	if greason, sensitive := gitConfigSensitiveAsk(payload, intent); sensitive {
		resp := &HookResponse{
			Decision: policy.VerdictAsk,
			Reason:   "Approve — this rewrites " + greason + ". A malicious value can exfiltrate credentials or redirect execution on the next git operation. Approve only if you set this yourself.",
		}
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, l.ObserveOnly, ag)
		return resp, nil
	}

	if resp, handled := evaluateRawSecretReadGate(payload, intent, labels, l, state, projectRoot, ag); handled {
		return resp, nil
	}

	if resp, handled := evaluateMCPCredentialLeak(payload, l, state, projectRoot); handled {
		return resp, nil
	}

	if resp, handled := evaluateMCPCapabilityScope(payload, l, state, projectRoot); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		return resp, nil
	}

	if resp, handled := evaluateTaintedMCPServer(payload, state); handled {
		return resp, nil
	}

	if resp, handled := evaluateDelegationHardDeny(intent, l, state, ag); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, l.ObserveOnly, ag)
		return resp, nil
	}

	if intent.Verb == policy.VerbDelegate && (pendingInjectionDetail != "" || delegationRequiresApproval(state)) {
		resp := &HookResponse{
			Decision: policy.VerdictAsk,
			Reason:   FormatAskPostureElevated(string(intent.Verb), intent.Target, string(state.Posture), state.MCPInjectionSignals),
		}
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		saveSessionBestEffort(state)
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, l.ObserveOnly, ag)
		return resp, nil
	}

	if resp, handled := evaluateTaintedMCPInput(payload, l, state, projectRoot); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		return resp, nil
	}

	if resp, handled := evaluateMCPBinaryDrift(intent, payload, l, state, projectRoot); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		return resp, nil
	}

	if resp, handled := evaluateMCPOnboarding(intent, payload, l, state, projectRoot); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		return resp, nil
	}

	if resp, handled := evaluateElevatedPosture(intent, state); handled {
		return resp, nil
	}

	if resp, handled := prepareInstallEvaluation(intent, state, l, projectRoot); handled {
		return resp, nil
	}

	coreResp, err := evaluatePolicy(projectRoot, payload, signals, intent, l, state, labels)
	if err != nil {
		return nil, err
	}
	// STRUCTURAL SEAL: when an authoritative policy_provider produced the verdict
	// (grant OR fail-closed), it is FINAL — none of the native convenience
	// downgrades below (manual approval grant, SilentApprovedHosts, NPX/REMOTE/
	// ENV ask-suppression) may turn it into an allow. Gating the whole region
	// with one guard (rather than annotating each site) means a future downgrade
	// block can't silently re-open this hole. The downgrades only ever turn
	// ask→allow, so skipping them for an authoritative allow/deny is a no-op;
	// the case that matters is an authoritative (or fail-closed) ASK, which must
	// survive to the user. See pdp-provider-delegation.md §8.
	if !coreResp.AuthoritativeActive {
		if coreResp.Decision == policy.VerdictAsk {
			if grant, ok := state.ConsumeApprovalGrant(string(intent.Verb), intent.Target); ok {
				coreResp.Decision = policy.VerdictAllow
				if grant.Reason != "" {
					coreResp.Reason = "manual approval grant: " + grant.Reason
				} else {
					coreResp.Reason = "manual approval grant"
				}
			}
		}

		// NETALLOW-1: an already-allowlisted host asks on a clean session but is
		// silently allowed under a *secret* session (an inverted gradient — the
		// safer-context case is noisier). When the profile enables it and the
		// session posture is clean, drop the redundant prompt. This narrows an ask
		// to an allow for a host the operator already approved; the oracle's IFC
		// flow check already ran, and it never touches a deny. Gated by profile
		// (off in strict/managed) and the clean-context guard.
		if coreResp.Decision == policy.VerdictAsk && intent.Verb == policy.VerbNetAllowlisted &&
			l != nil && l.SilentApprovedHosts && autoLeaseSafeContext(state) {
			coreResp.Decision = policy.VerdictAllow
			coreResp.Reason = "approved host on a clean session — silent by policy (sir policy show)"
		}

		// MCPQUIET-1: mcp_network_unapproved is "friction, not containment" — it
		// gates honest-server argument URLs only (a malicious MCP ignores the arg
		// gate; real containment is the sandbox proxy). Silenced on a clean
		// session. Narrows ask→allow only; never touches mcp_unapproved (the real
		// unknown-server gate) or mcp_binary_drift (local supply-chain). Gated by
		// profile (QuietMCPFriction, off in strict/managed) and the clean-context
		// guard, so it never fires under a secret/tainted/elevated session. (The
		// sibling mcp_onboarding case is silenced at its own preflight gate, which
		// preserves the heightened first-call-exfil checkpoint — see
		// evaluateMCPOnboarding.)
		if coreResp.Decision == policy.VerdictAsk &&
			intent.Verb == policy.VerbMcpNetworkUnapproved &&
			l != nil && l.QuietMCPFriction && autoLeaseSafeContext(state) &&
			!mcpOnboardingHeightened(l, state, extractMCPServerName(payload.ToolName)) {
			coreResp.Decision = policy.VerdictAllow
			coreResp.Reason = "MCP argument-host prompt on a clean session — silent by policy (friction, not containment; sir policy show)"
		}

		// NPX-1: an ephemeral package (npx) approved earlier this session stops
		// re-prompting. The first run still asks; on observed approval PostToolUse
		// records it, and subsequent runs of the SAME package under clean posture
		// are silent. Gated by profile (ReuseSessionApprovals) and clean context.
		if coreResp.Decision == policy.VerdictAsk && intent.Verb == policy.VerbRunEphemeral &&
			l != nil && l.ReuseSessionApprovals && autoLeaseSafeContext(state) {
			if state.EphemeralApproved(intent.Target) {
				coreResp.Decision = policy.VerdictAllow
				coreResp.Reason = "ephemeral package approved earlier this session (sir policy show)"
			} else {
				state.MarkPendingEphemeralApproval(intent.Target)
			}
		}

		// REMOTE-1: a git push to an unapproved remote approved earlier this session
		// stops re-prompting. First push still asks; on observed approval PostToolUse
		// records the remote, and subsequent pushes to the SAME remote under clean
		// posture are silent. Gated by profile (AutoLeaseApprovedRemotes).
		if coreResp.Decision == policy.VerdictAsk && intent.Verb == policy.VerbPushRemote &&
			intent.RemoteName != "" && !intent.IsForgePublish && l != nil && l.AutoLeaseApprovedRemotes && autoLeaseSafeContext(state) {
			if state.PushRemoteApproved(intent.RemoteName) {
				coreResp.Decision = policy.VerdictAllow
				coreResp.Reason = "git remote approved earlier this session (sir policy show)"
			} else {
				state.MarkPendingPushRemote(intent.RemoteName)
			}
		}

		// ORIGIN-1: a git push to an already-approved remote (origin) that was
		// re-asked because the session previously held secret data. Mirrors REMOTE-1:
		// the first push still asks (or denies in thinking mode), but once the
		// developer approves via `sir approve --last` the remote is recorded in
		// session and subsequent same-session pushes are silent.
		//
		// Security contract: autoLeaseSafeContext is false while SecretSession is
		// true (active credentials), so auto-approval only fires after the secret
		// context clears — preserving the IFC floor for the live-secret case.
		if coreResp.Decision == policy.VerdictAsk && intent.Verb == policy.VerbPushOrigin &&
			intent.RemoteName != "" && !intent.IsForgePublish && l != nil && l.AutoLeaseApprovedRemotes && autoLeaseSafeContext(state) {
			if state.PushRemoteApproved(intent.RemoteName) {
				coreResp.Decision = policy.VerdictAllow
				coreResp.Reason = "git origin approved earlier this session (sir approve remote origin)"
			} else {
				state.MarkPendingPushRemote(intent.RemoteName)
			}
		}

		// ENV-1: a targeted read of a provably-non-secret env var (`printenv PATH`)
		// is silent-allowed under the personal profile — but ONLY the prompt is
		// suppressed. The PostToolUse env-read taint path is left entirely untouched,
		// so the secret-session kill-switch stays armed for any env read whose value
		// turns out to be secret. Bulk dumps and any non-allowlisted var keep the ask
		// (fail-closed). Gated by NarrowEnvReads (personal only) and clean context.
		if coreResp.Decision == policy.VerdictAsk && intent.Verb == policy.VerbEnvRead &&
			l != nil && l.NarrowEnvReads && autoLeaseSafeContext(state) {
			if v, ok := singleSafeEnvVarRead(intent.Target); ok {
				coreResp.Decision = policy.VerdictAllow
				coreResp.Reason = "read of non-secret environment variable " + v + " (policy: narrow-env-reads); taint stays armed for any secret-bearing read"
			}
		}

	} // end structural seal: native convenience downgrades skipped for authoritative verdicts

	hookResp := applyCoreEvaluationResult(coreResp, intent, labels, state, ag)
	overlayPendingInjectionWarning(hookResp, pendingInjectionDetail)

	// Track repeated prompts/blocks for the same intent so repeated_denied_intent
	// fires in real time and the egress escalation can see repetition. Recorded
	// before Save so the increment persists; stamping reads the count after.
	if coreResp.Decision == policy.VerdictDeny || coreResp.Decision == policy.VerdictAsk {
		state.RecordPromptedIntent(promptKey(intent.Verb, intent.Target))
	}
	maybeMarkAutoLeasePending(l, state, intent, coreResp.Decision)

	if err := state.Save(); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	// A Floor verdict (secret-context egress, etc.) is enforced on the wire even
	// under observe mode, so it must be recorded as a REAL deny — not would_deny
	// — or `sir why`, friction metrics, and SIEM would misreport an enforced
	// security event as hypothetical during an observe rollout.
	recordObserve := l.ObserveOnly && !hookResp.Floor
	appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, coreResp.Decision, coreResp.Reason, state, recordObserve, ag)

	// Dispatch effects to registered effect_providers and export_providers.
	// Block effects (deny) are invoked synchronously before returning so that
	// OS-level sandbox enforcement can be confirmed before the agent sees the
	// response. Export effects are always async (fire-and-forget, non-blocking).
	go DispatchEffects(coreResp.Decision, intent, signals, projectRoot)

	return hookResp, nil
}
