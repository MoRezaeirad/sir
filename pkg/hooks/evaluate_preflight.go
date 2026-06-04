package hooks

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/config"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	mcppkg "github.com/somoore/sir/pkg/mcp"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func evaluateMCPCredentialLeak(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if l.IsTrustedMCPServer(serverName) {
		return nil, false
	}
	found, patternHint := ScanMCPArgsForCredentials(payload.ToolInput)
	if !found {
		return nil, false
	}

	entry := &ledger.Entry{
		ToolName: payload.ToolName,
		Verb:     string(policy.VerbMcpCredentialLeak),
		Target:   serverName,
		// Always a real deny — a credential leak is a Floor that observe mode
		// never downgrades (OBSERVE-1), so the ledger records the enforced deny,
		// not would_deny, even during an observe rollout.
		Decision:  string(policy.VerdictDeny),
		Reason:    fmt.Sprintf("credential pattern in MCP args: %s", patternHint),
		Severity:  "HIGH",
		AlertType: "mcp_credential",
	}
	if EnvLogToolContent() {
		entry.Evidence = marshalMCPEvidence(payload.ToolInput)
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}
	if err := state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", err)
	}

	return &HookResponse{
		Decision: policy.VerdictDeny,
		Reason:   FormatDenyMCPCredential(payload.ToolName, serverName, patternHint),
		// A raw credential heading to an untrusted MCP server is active
		// exfiltration; observe mode must never silently allow it (OBSERVE-1).
		Floor: true,
	}, true
}

func evaluateTaintedMCPServer(payload *HookPayload, state *session.State) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !state.IsMCPServerTainted(serverName) || state.IsTaintedMCPServerAcknowledged(serverName) {
		return nil, false
	}
	if err := state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", err)
	}
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason:   FormatAskPostureElevated("mcp_call", payload.ToolName, string(state.Posture), state.MCPInjectionSignals),
	}, true
}

// Approved MCP calls still need a gate when the payload points at a file
// already carrying secret lineage.
func evaluateTaintedMCPInput(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !isApprovedMCPServer(serverName, l) {
		return nil, false
	}

	targets := derivedSecretLineageTargets(payload.ToolInput, projectRoot, state)
	if len(targets) == 0 {
		return nil, false
	}
	target := targets[0]
	saveSessionBestEffort(state)
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason:   fmt.Sprintf("MCP call touching %s requires approval because it carries secret lineage.", target),
	}, true
}

func derivedSecretLineageTargets(input any, projectRoot string, state *session.State) []string {
	seen := make(map[string]struct{})
	var targets []string
	var walk func(any, string)
	walk = func(value any, key string) {
		switch typed := value.(type) {
		case string:
			if typed == "" || !isPathBearingMCPKey(key) {
				return
			}
			if _, ok := seen[typed]; ok {
				return
			}
			for _, label := range state.DerivedLabelsForPath(ResolveTarget(projectRoot, typed)) {
				if label.Sensitivity != "secret" {
					continue
				}
				seen[typed] = struct{}{}
				targets = append(targets, typed)
				return
			}
		case []interface{}:
			for _, item := range typed {
				walk(item, key)
			}
		case map[string]any:
			for childKey, item := range typed {
				walk(item, childKey)
			}
		}
	}
	walk(input, "")
	return targets
}

func isPathBearingMCPKey(key string) bool {
	normalized := normalizeMCPArgKey(key)
	switch {
	case strings.HasSuffix(normalized, "path"), strings.HasSuffix(normalized, "paths"):
		return true
	case normalized == "file", normalized == "files":
		return true
	case normalized == "artifact", normalized == "artifacts":
		return true
	case normalized == "attachment", normalized == "attachments":
		return true
	default:
		return false
	}
}

func normalizeMCPArgKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// evaluateMCPOnboarding fires when an approved MCP server is within its
// onboarding window — a per-session speed bump on calls that would
// otherwise silently allow. The gate ends when EITHER the wall-clock
// window or the per-session call count is crossed.
//
// Scope honesty: this is friction, not containment. A patient attacker
// can burn the counter with 20 harmless calls in seconds, and a 24h wait
// clears the window. The value is surfacing early MCP activity to the
// user when a server is unfamiliar, NOT stopping a malicious MCP. That
// containment story belongs to `sir mcp-proxy`.
//
// Verdict: always Ask. Never Deny.
//
// Gate is skipped when:
//   - tool is not mcp__*
//   - server is not approved
//   - intent.Verb is not VerbExecuteDryRun (something stronger already fires)
//   - approval record is missing or ApprovedAt is zero (grandfathered)
//   - config cannot be loaded (fail open — friction only)
//   - config disables onboarding (both knobs must be positive)
//   - age >= window OR call count >= threshold
func evaluateMCPOnboarding(intent Intent, payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	if intent.Verb != policy.VerbExecuteDryRun {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !isApprovedMCPServer(serverName, l) {
		return nil, false
	}
	record, ok := l.MCPApprovals[serverName]
	if !ok || record.ApprovedAt.IsZero() {
		return nil, false
	}
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sir: onboarding: config load error, skipping gate: %v\n", err)
		return nil, false
	}

	window := time.Duration(cfg.MCPOnboardingWindowHours) * time.Hour
	age := time.Since(record.ApprovedAt)
	count := state.MCPOnboardingCallCount(serverName)
	withinWindow := age < window

	// MCPONBOARD-1: the configurable per-call counter is friction-not-containment
	// and OFF by default. What we keep, independent of that counter:
	//   - a first-touch checkpoint: the FIRST call this session from a still-new
	//     (within-window) approved server always surfaces — this is the only
	//     interactive surface on a freshly-approved server's earliest activity
	//     (the first-call-exfil checkpoint the red-team flagged), and
	//   - a heightened floor: when the session carries secret context or a
	//     pending injection alert, or the server has NO configured capability
	//     scope, force a few early checkpoints even if the counter is disabled.
	heightened := mcpOnboardingHeightened(l, state, serverName)

	// MCPQUIET-1: onboarding is "friction, not containment" — a visibility
	// heads-up on a newly-approved server. When QuietMCPFriction is on, the case
	// is NOT heightened (a scoped server, no secret/injection — preserving the
	// first-call-exfil checkpoint the red-team flagged), AND the session is in a
	// safe context, skip the prompt. autoLeaseSafeContext is REQUIRED in addition
	// to !heightened: `heightened` omits untrusted-ingestion (RecentlyReadUntrusted
	// / UntrustedContentThisTurn), elevated posture, and tainted MCP — exactly the
	// prompt-injection contexts every sibling reduction (NETALLOW-1/REUSE/ENV-1)
	// refuses to silence in. Off in strict/managed via the profile gradient.
	if l.QuietMCPFriction && !heightened && autoLeaseSafeContext(state) {
		return nil, false
	}

	effectiveCallCount := cfg.MCPOnboardingCallCount
	if heightened && effectiveCallCount < onboardingHeightenedFloor {
		effectiveCallCount = onboardingHeightenedFloor
	}

	shouldAsk := withinWindow && (count == 0 || count < effectiveCallCount)
	if !shouldAsk {
		return nil, false
	}

	newCount := state.BumpMCPOnboardingCall(serverName)
	saveSessionBestEffort(state)

	why := "first call this session from a newly-approved server"
	if effectiveCallCount > 0 {
		why = fmt.Sprintf("session call %d/%d", newCount, effectiveCallCount)
	}
	if heightened {
		why += " (heightened: secret/injection or no capability scope)"
	}

	entry := &ledger.Entry{
		ToolName: payload.ToolName,
		Verb:     string(policy.VerbMcpOnboarding),
		Target:   serverName,
		Decision: recordedDecisionFor(l, thinkingDegradedLedgerDecision(state, policy.VerdictAsk)),
		Reason: fmt.Sprintf(
			"MCP onboarding: server %q within window (age=%s, %s)",
			serverName, age.Round(time.Second), why,
		),
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append (onboarding): %v\n", err)
	}

	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason: fmt.Sprintf(
			"MCP server %q was approved %s ago and this is its %s. Surfacing its early activity for visibility — approve to continue. Friction only, not a security block.",
			serverName, age.Round(time.Second), why,
		),
	}, true
}

// onboardingHeightenedFloor is the minimum number of early MCP calls that are
// surfaced for an approved server when the session is heightened (secret
// context, a pending injection alert, or the server has no configured
// capability scope) — even when the per-call onboarding counter is disabled.
const onboardingHeightenedFloor = 3

// mcpOnboardingHeightened reports whether an approved MCP server is in a
// "heightened" state where the first-call-exfil checkpoint must surface: a
// secret session, a pending injection alert, or NO configured capability scope
// (an unfamiliar server). This is the single source of truth shared by the
// onboarding gate AND the MCPQUIET-1 mcp_network_unapproved downgrade, so a
// network-bearing first call can't bypass the checkpoint that non-network calls
// preserve (the two MCPQUIET-1 silences must agree on what "heightened" means).
func mcpOnboardingHeightened(l *lease.Lease, state *session.State, serverName string) bool {
	_, hasScope := l.FindMCPCapabilityScope(serverName)
	return state.SecretSession || state.PendingInjectionAlert || !hasScope
}

// evaluateMCPBinaryDrift detects that the MCP command binary has changed
// since approval. Fast-path: stat for mtime; if mtime matches the
// recorded value, skip. Otherwise rehash the binary and compare against
// the stored hash. Mismatch → Ask via VerbMcpBinaryDrift.
//
// Only fires when:
//   - tool is mcp__*
//   - server is approved
//   - intent.Verb is VerbExecuteDryRun (silent-allow path) — earlier
//     verbs like VerbMcpNetworkUnapproved or VerbMcpUnapproved already
//     surfaced a more specific concern with its own remediation hint
//     (`sir allow-host <host>`), so drift must not short-circuit them
//   - MCPApprovals[name] carries a non-empty CommandHash
//     (empty hash means "could not pin at approval time" — documented
//     limitation, honest about what we cannot verify)
//
// Scope honesty: this catches local binary substitution post-approval
// (supply-chain replacement, malicious package upgrade). It does not
// catch content-equivalent-but-different binaries (e.g., recompile with
// same output), and it does not apply to npx/uvx/PATH-only servers
// whose binary identity cannot be pinned.
func evaluateMCPBinaryDrift(intent Intent, payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	if intent.Verb != policy.VerbExecuteDryRun {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !isApprovedMCPServer(serverName, l) {
		return nil, false
	}
	record, ok := l.MCPApprovals[serverName]
	if !ok || record.CommandHash == "" || record.Command == "" {
		return nil, false
	}

	// Fast-path: if mtime matches, skip rehash.
	currentModTime, currentHash, err := mcppkg.StatCommand(record.Command)
	if err != nil {
		// Transient stat errors should not break policy evaluation; log
		// and fail-open (friction only).
		fmt.Fprintf(os.Stderr, "sir: binary-drift stat error for %s: %v\n", serverName, err)
		return nil, false
	}

	// If the binary is gone entirely, treat that as drift. A deleted
	// binary that MCP is allegedly still running must be surfaced to
	// the user — something is wrong with their approval.
	if currentHash == "" && record.CommandHash != "" {
		return driftAsk(payload, serverName, record, "binary not found at recorded path", l, state, projectRoot), true
	}

	if !record.CommandModTime.IsZero() && currentModTime.Equal(record.CommandModTime) && currentHash == record.CommandHash {
		return nil, false
	}
	if currentHash == record.CommandHash {
		// mtime changed but content is the same (touch, chmod, etc.).
		// No drift; do not ask. We deliberately do NOT persist the new
		// mtime here — doing so from a read-mostly evaluation path is
		// not worth the lock contention for a cosmetic refresh.
		return nil, false
	}

	// MCPDRIFT-1: if the developer already approved this EXACT drifted hash this
	// session (under clean posture), don't re-ask — a routine `npm update`/`brew
	// upgrade` shouldn't prompt on every subsequent call. A new/different hash is
	// not acknowledged and still asks; binary-not-found (empty hash) still asks.
	if l != nil && l.ReuseSessionApprovals && autoLeaseSafeContext(state) && state.MCPDriftAcknowledged(serverName, currentHash) {
		return nil, false
	}
	if l != nil && l.ReuseSessionApprovals && autoLeaseSafeContext(state) {
		state.MarkPendingMCPDriftAck(serverName, currentHash)
	}
	return driftAsk(payload, serverName, record, fmt.Sprintf("hash mismatch (approved=%s, now=%s)",
		shortHash(record.CommandHash), shortHash(currentHash)), l, state, projectRoot), true
}

// driftAsk builds the Ask response for the binary-drift gate and
// appends a ledger entry capturing the mismatch detail.
func driftAsk(payload *HookPayload, serverName string, record lease.MCPApproval, detail string, l *lease.Lease, state *session.State, projectRoot string) *HookResponse {
	// Mark the trust-footing change so a later privileged action in this
	// session is correlated into mcp_change_then_privileged_use.
	state.RecordMCPAuthorityChange()
	saveSessionBestEffort(state)
	entry := &ledger.Entry{
		ToolName:  payload.ToolName,
		Verb:      string(policy.VerbMcpBinaryDrift),
		Target:    serverName,
		Decision:  recordedDecisionFor(l, thinkingDegradedLedgerDecision(state, policy.VerdictAsk)),
		Reason:    fmt.Sprintf("binary drift: %s", detail),
		Severity:  "MEDIUM",
		AlertType: "mcp_binary_drift",
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append (binary-drift): %v\n", err)
	}
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason: fmt.Sprintf(
			"MCP server %q command binary changed since approval (%s). Approve once to continue, or run `sir mcp revoke %s && sir mcp approve %s` after confirming the new binary is intended. Approved %s; command=%s.",
			serverName, detail, serverName, serverName,
			record.ApprovedAt.Format(time.RFC3339), record.Command,
		),
	}
}

// shortHash returns the first 12 hex chars of a sha256, enough to
// disambiguate in an ask message without overwhelming it.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func evaluateElevatedPosture(intent Intent, state *session.State) (*HookResponse, bool) {
	if state.Posture != policy.PostureStateElevated && state.Posture != policy.PostureStateCritical {
		return nil, false
	}
	// Elevated posture stays visible in status/compact output and still gates
	// delegation plus repeated calls back into the tainted MCP server, but it
	// should not degrade ordinary local Bash/Edit traffic into endless prompts.
	_ = intent
	_ = state
	return nil, false
}
