package hooks

import (
	"fmt"
	"io"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/detect"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// PostHookPayload is sir's normalized PostToolUse payload. Type alias to
// agent.HookPayload so the hooks package stays agent-agnostic while existing
// tests continue to work.
type PostHookPayload = agent.HookPayload

// PostEvaluate is the PostToolUse hook handler.
// It checks for sentinel file mutations after installs,
// posture file tampering via Bash, and updates session state.
//
// ag is the host-agent adapter that owns BOTH parse (stdin) and format
// (stdout). Each adapter decides its own PostToolUse wire contract:
//
//   - Claude Code: returns nil bytes from FormatPostToolUseResponse — the
//     PostToolUse hook doesn't honor permissionDecision, so sir writes
//     non-allow reasons to stderr instead.
//   - Codex: returns a real {"decision":"block","reason":...,
//     "hookSpecificOutput":{...}} JSON body because Codex DOES process
//     PostToolUse responses.
//
// The handler always writes reasons to stderr as a human-visible fallback;
// this is additive, not mutually exclusive, with the adapter's stdout.
func PostEvaluate(projectRoot string, ag agent.Agent) error {
	// Read stdin with size limit
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	payload, err := ag.ParsePostToolUse(data)
	if err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Load session and evaluate under file lock.
	// The lock covers Load→PostEvaluate(mutate)→Save so concurrent hooks
	// cannot corrupt session state.
	var resp *HookResponse
	lockErr := session.WithSessionLock(projectRoot, func() error {
		l, leaseMeta, err := loadLeaseWithMetadata(projectRoot)
		if err != nil {
			return fmt.Errorf("load lease: %w", err)
		}
		state, err := loadOptionalLifecycleSession(projectRoot, "post-evaluate")
		if err != nil {
			return err
		}
		if state == nil {
			// No session — nothing to check.
			return nil
		}
		if err := syncSessionLeaseHashAfterSirRefresh(state, leaseMeta); err != nil {
			return fmt.Errorf("sync refreshed lease hash into session: %w", err)
		}
		var pErr error
		resp, pErr = postEvaluatePayload(payload, l, state, projectRoot, ag)
		if pErr != nil {
			return pErr
		}
		if saveErr := state.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
		}
		return nil
	})
	if lockErr != nil {
		return fmt.Errorf("post-evaluate: %w", lockErr)
	}

	// Write the adapter-owned response to stdout (Codex uses this; Claude
	// returns nil and falls through to stderr). Human-visible reason also
	// goes to stderr regardless, so the developer sees alerts inline.
	if resp != nil && resp.Decision != policy.VerdictAllow {
		if respBytes, fmtErr := ag.FormatPostToolUseResponse(string(resp.Decision), resp.Reason); fmtErr == nil && len(respBytes) > 0 {
			os.Stdout.Write(respBytes) //nolint:errcheck
		}
		fmt.Fprintln(os.Stderr, resp.Reason)
	}
	return nil
}

// postEvaluatePayload is the testable core of the PostToolUse handler.
// The optional trailing ag argument provides OTLP agent attribution; nil
// when omitted (test callers) so telemetry resource attrs are simply
// absent.
func postEvaluatePayload(payload *PostHookPayload, l *lease.Lease, state *session.State, projectRoot string, agOpt ...agent.Agent) (*HookResponse, error) {
	var ag agent.Agent
	if len(agOpt) > 0 {
		ag = agOpt[0]
	}
	// Verify session integrity — detect external tampering of session.json
	if !session.VerifySessionIntegrity(state) {
		state.SetDenyAll("session.json modified outside sir")
		if saveErr := state.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
		}
		return &HookResponse{
			Decision: "deny",
			Reason:   FormatSessionIntegrityFatal(),
		}, nil
	}

	// If session is already in deny-all, return the fatal message on every call.
	if state.DenyAll {
		return &HookResponse{
			Decision: "deny",
			Reason:   FormatDenyAll(state.DenyAllReason),
		}, nil
	}

	// Hook-integrity check: a PostToolUse for a tool_use_id sir DENIED at
	// PreToolUse means the host executor ran the call anyway — it ignored sir's
	// deny. A hook layer cannot prevent that one call, but it can detect it and
	// lock the session down so nothing further proceeds.
	if payload.ToolUseID != "" && state.WasToolUseDenied(payload.ToolUseID) {
		state.SetDenyAll("a denied tool call executed anyway — the host executor ignored sir's deny")
		if saveErr := state.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
		}
		entry := &ledger.Entry{
			ToolName:    payload.ToolName,
			Verb:        "hook_integrity_violation",
			Target:      payload.ToolUseID,
			Decision:    "deny",
			Reason:      "denied tool call executed anyway; host executor ignored sir's deny — session set to deny-all",
			DetectionID: string(detect.HookIntegrityViolation),
			Severity:    "HIGH",
		}
		if err := ledger.Append(projectRoot, entry); err != nil {
			fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
		}
		emitTelemetryEvent(entry, state, ag)
		return &HookResponse{Decision: "deny", Reason: FormatDenyAll(state.DenyAllReason)}, nil
	}

	rebaselinePostureHashesAfterWrite(payload, state, l, projectRoot)

	// If a Read or Grep of a sensitive path just completed, mark the session as secret.
	// This fires AFTER the user approved the ask prompt, so the read actually happened.
	// Use IsSensitivePathResolvedIn so symlinked paths and absolute paths are caught.
	sensitiveTarget := recordSensitiveTargetFromPostPayload(payload, l, projectRoot)
	if sensitiveTarget != "" && !state.SecretSession {
		recordSensitiveReadEvidence(state, sensitiveTarget)
		// Default to turn scope: the secret flag clears when the next turn begins.
		state.MarkSecretSession() // defaults to "turn" scope
		fmt.Fprintf(os.Stderr, "sir: credentials file read (%s). External network requests are now restricted.\n", sensitiveTarget)
		fmt.Fprintf(os.Stderr, "sir: this is turn-scoped — clears when the agent finishes responding.\n")
		fmt.Fprintf(os.Stderr, "sir: to clear now: sir unlock\n")
	} else if sensitiveTarget != "" {
		recordSensitiveReadEvidence(state, sensitiveTarget)
	}

	alertFired := applyPostEvaluateOutputCredentialAnalysis(payload, state, projectRoot, ag)
	propagateBashLineageMutationWithLease(projectRoot, state, l, payload)

	// Check 1: If we had a pending install, compare sentinel hashes
	if state.PendingInstall != nil && payload.ToolName == "Bash" {
		changed := checkPendingInstall(state, l, projectRoot)
		if len(changed) > 0 {
			entry := sentinelMutationEntry(payload, state.PendingInstall.Command, changed)
			// When the install mutated a posture/control-plane file (not just a
			// lockfile or .env), this is the higher-signal supply-chain
			// detection — a package install rewriting the agent's future
			// behavior — so stamp it explicitly over the generic tamper class.
			if anyInstalledPostureFile(projectRoot, changed, l) {
				entry.DetectionID = string(detect.PackageInstallPostureMutation)
				entry.Severity = "HIGH"
			}
			if err := ledger.Append(projectRoot, entry); err != nil {
				fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
			} else {
				alertFired = true
			}
			emitTelemetryEvent(entry, state, ag)
		}
		state.ClearPendingInstall()
	}

	if resp, handled := handleBashPostEvaluateChecks(payload, l, state, projectRoot, ag); handled {
		return resp, nil
	}

	if applyPostEvaluateMCPOutputAnalysis(payload, state, projectRoot, ag) {
		alertFired = true
	}

	// Verbatim context-laundering backstop: when secret values entered context
	// (an approved sensitive read whose output is the secret file, or credentials
	// detected in the output by EITHER the generic or the MCP scanner), record
	// one-way fingerprints of those values so a later verbatim re-emission in an
	// outbound payload is caught. Placed AFTER the MCP credential scan so an
	// MCP-returned secret is also fingerprinted. Raw values are never stored.
	if payload.ToolOutput != "" && (sensitiveTarget != "" || alertFired) {
		captureSecretFingerprints(payload.ToolOutput, state)
	}

	// Weak, turn-scoped untrusted-content signal. Any MCP tool response or
	// fetched web content is untrusted input; marking it here (regardless of
	// whether the heuristic injection scanner flagged anything) lets the
	// integrity-flow egress wall gate the dangerous *same-turn* untrusted->egress
	// shape — catching injections the ~50-pattern scanner missed — while clearing
	// at the next turn boundary so cross-turn MCP/web coding stays quiet.
	if payload.ToolOutput != "" && isUntrustedContentTool(payload.ToolName) {
		state.MarkUntrustedContentThisTurn()
	}

	if payload.ToolName == "Write" || payload.ToolName == "Edit" {
		attachLineageToWriteTarget(projectRoot, state, payload)
	}

	if !alertFired {
		applyAutoLeaseOnApproval(payload, l, state, projectRoot, ag)
		promoteSessionApprovalsOnPost(payload, l, state)
		applyPostEvaluateAllowTrace(payload, state, projectRoot, ag, sensitiveTarget != "")
	}

	return &HookResponse{Decision: policy.VerdictAllow}, nil
}

// promoteSessionApprovalsOnPost redeems the per-session reuse markers when a
// previously-asked action is observed to have executed (a PostToolUse only
// fires if the developer approved). It backs MCPDRIFT-1 (an acknowledged MCP
// binary-drift hash) and NPX-1 (an approved ephemeral package), so the same
// action stops re-prompting for the rest of the session. Gated by the profile
// (ReuseSessionApprovals) and a clean posture — never under secret/tainted
// context, mirroring auto-lease.
func promoteSessionApprovalsOnPost(payload *PostHookPayload, l *lease.Lease, state *session.State) {
	if l == nil || !autoLeaseSafeContext(state) {
		return
	}
	if l.ReuseSessionApprovals && isToolMCP(payload.ToolName) {
		state.PromotePendingMCPDriftAck(extractMCPServerName(payload.ToolName))
	}
	intent := MapToolToIntent(payload.ToolName, payload.ToolInput, l)
	if l.ReuseSessionApprovals && intent.Verb == policy.VerbRunEphemeral {
		state.PromotePendingEphemeralApproval(intent.Target)
	}
	if l.AutoLeaseApprovedRemotes && intent.RemoteName != "" && !intent.IsForgePublish &&
		(intent.Verb == policy.VerbPushRemote || intent.Verb == policy.VerbPushOrigin) {
		state.PromotePendingPushRemote(intent.RemoteName)
	}
}

// isUntrustedContentTool reports whether a tool's output should be treated as
// untrusted external content for the turn-scoped integrity signal. MCP tool
// responses and web fetches/searches are the common indirect-injection carriers
// for coding agents (malicious READMEs, issues, web pages, MCP tool output).
func isUntrustedContentTool(toolName string) bool {
	if isToolMCP(toolName) {
		return true
	}
	switch toolName {
	case "WebFetch", "WebSearch", "web_fetch", "web_search", "fetch":
		return true
	}
	return false
}

// checkPendingInstall re-hashes sentinel files after an install and returns changed files.
func checkPendingInstall(state *session.State, l *lease.Lease, projectRoot string) []string {
	if state.PendingInstall == nil {
		return nil
	}
	afterHashes := HashSentinelFiles(projectRoot, l.SentinelFilesForInstall)
	return CompareSentinelHashes(state.PendingInstall.SentinelHashes, afterHashes)
}

// anyInstalledPostureFile reports whether any changed install-sentinel file is
// a posture/control-plane file (CLAUDE.md, .mcp.json, hook config, …) rather
// than a benign lockfile or .env.
func anyInstalledPostureFile(projectRoot string, changed []string, l *lease.Lease) bool {
	for _, f := range changed {
		if IsPostureFileResolvedIn(projectRoot, f, l) {
			return true
		}
	}
	return false
}
