package hooks

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/detect"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

var jsonMarshal = json.Marshal

func buildCoreRequest(projectRoot string, payload *HookPayload, intent Intent, l *lease.Lease, state *session.State, labels core.Label) (*core.Request, error) {
	leaseJSON, err := marshalCoreLease(l)
	if err != nil {
		return nil, err
	}

	derivedLabels := derivedLabelsForIntent(projectRoot, payload, intent, state)
	return &core.Request{
		ToolName:  payload.ToolName,
		LeaseJSON: leaseJSON,
		Intent: core.Intent{
			Verb:          intent.Verb,
			Target:        intent.Target,
			Labels:        []core.Label{labels},
			DerivedLabels: derivedLabels,
			IsPosture:     intent.IsPosture,
			IsSensitive:   intent.IsSensitive,
			IsDelegation:  payload.ToolName == "Agent",
			IsTripwire:    false,
		},
		Session: core.SessionInfo{
			SecretSession:            state.SecretSession,
			WasSecret:                state.SessionEverSecret,
			RecentlyReadUntrusted:    state.RecentlyReadUntrusted,
			UntrustedContentThisTurn: state.UntrustedContentThisTurn,
			DenyAll:                  state.DenyAll,
			ApprovalScope:            string(state.ApprovalScope),
			TurnCounter:              state.TurnCounter,
		},
	}, nil
}

func marshalCoreLease(v interface{}) ([]byte, error) {
	data, err := jsonMarshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal lease: %w", err)
	}
	return data, nil
}

// promptKey is the stable session-counter key for a verb/target intent. The
// NUL separator avoids collisions between a verb and a target that share text.
func promptKey(verb policy.Verb, target string) string {
	return string(verb) + "\x00" + target
}

func appendEvaluationLedgerEntry(projectRoot string, payload *HookPayload, intent Intent, labels core.Label, decision policy.Verdict, reason string, state *session.State, observe bool, ag agent.Agent) {
	// Fold in the thinking-guard degrade (ask -> deny) so the recorded decision
	// matches the agent-visible wire decision when the guard fired.
	if degraded := thinkingDegradedLedgerDecision(state, decision); degraded != decision {
		decision = degraded
		reason = ThinkingGuardLedgerReason
	}
	recorded := decision
	if observe {
		recorded = observeRecordedDecision(decision)
	}
	preview := ledger.RedactPreview(intent.Target, labels.Sensitivity == "secret")
	entry := &ledger.Entry{
		ToolName:    payload.ToolName,
		Verb:        string(intent.Verb),
		Target:      intent.Target,
		Sensitivity: labels.Sensitivity,
		Trust:       labels.Trust,
		Provenance:  labels.Provenance,
		Decision:    string(recorded),
		Reason:      reason,
		Preview:     preview,
	}
	if isToolMCP(payload.ToolName) && EnvLogToolContent() {
		entry.Evidence = marshalMCPEvidence(payload.ToolInput)
	}
	// Attach policy-provider verdicts and fail-open failures collected during
	// this evaluation (item 4/8). They reach the ledger separately from native
	// policy rules. The holder is populated by evaluatePolicy and reset at the
	// start of each evaluation, so it is empty on paths that never call Rust
	// (e.g. the secret-read gate short-circuit).
	verdicts, failures, base := takeLastProviderEvaluation()
	// base is non-empty only when an advisory provider escalated the verdict
	// (evaluatePolicy already compared it against the composed decision). Record
	// it so `sir why` can show the base→final transition.
	entry.BaseVerdict = base
	entry.ProviderVerdicts = providerVerdictRecords(verdicts, string(decision), base)
	// A PDP authoritative override (if any) is recorded as a distinct verdict
	// record carrying the forensic audit fields (final=provider, native base,
	// floors-bypassed). It is appended after the advisory records so `sir why`
	// shows the override explicitly.
	if auth := takeLastAuthoritativeRecord(); auth != nil {
		entry.ProviderVerdicts = append(entry.ProviderVerdicts, *auth)
	}
	entry.ProviderFailures = providerFailureRecords(failures)
	entry.LatencyMs = decisionLatencyMs(state)
	stampStatefulDetection(projectRoot, payload, intent, labels, recorded, state, entry)
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}
	emitTelemetryEvent(entry, state, ag)
}

// stampStatefulDetection sets a detection ID that depends on session context
// the bare ledger entry cannot see (secret-session egress, secret-derived
// lineage, MCP taint). It runs only for blocked verdicts on the relevant
// verbs, so normal allow-path commits and pushes never pay for the lineage
// lookup. Entry-local detections (alerts, drift, onboarding) are stamped
// later inside ledger.Append.
// mcpAuthorityChangeWindow bounds how long after an MCP trust change a
// privileged action is correlated into mcp_change_then_privileged_use.
const mcpAuthorityChangeWindow = 30 * time.Minute

func stampStatefulDetection(projectRoot string, payload *HookPayload, intent Intent, labels core.Label, decision policy.Verdict, state *session.State, entry *ledger.Entry) {
	// Allowed actions normally carry no stateful detection — except a
	// privileged use shortly after an MCP trust change, which is the compound
	// supply-chain signal and must surface even when the action is allowed.
	if decision == policy.VerdictAllow && !state.RecentMCPAuthorityChange(mcpAuthorityChangeWindow) {
		return
	}
	derivedFromSecret := false
	if !state.SecretSession {
		for _, l := range derivedLabelsForIntent(projectRoot, payload, intent, state) {
			if l.Sensitivity == "secret" {
				derivedFromSecret = true
				break
			}
		}
	}
	priorRepeats := state.PromptCount(promptKey(intent.Verb, intent.Target)) - 1
	if priorRepeats < 0 {
		priorRepeats = 0
	}
	sig := detect.Signal{
		Verb:              string(intent.Verb),
		Verdict:           string(decision),
		Sensitivity:       labels.Sensitivity,
		SecretSession:     state.SecretSession,
		DerivedFromSecret: derivedFromSecret,
		MCPTaint:          len(state.TaintedMCPServers) > 0,
		InjectionAlert:    state.PendingInjectionAlert,
		DenyAll:           state.DenyAll,
		RepeatedCount:     priorRepeats,
		RecentMCPChange:   state.RecentMCPAuthorityChange(mcpAuthorityChangeWindow),
		Suspicious:        state.IsSuspicious(),
	}
	d, ok := detect.Classify(sig)
	if !ok {
		return
	}
	entry.DetectionID = string(d.ID)
	entry.DetectionRoute = d.Route.String()
	entry.SignalIDs = detectIDsToStrings(detect.Signals(sig))
	if entry.Severity == "" {
		entry.Severity = string(d.Severity)
	}
}

// providerVerdictRecords maps collected policy-provider verdicts to their
// ledger record form (policy metadata only — no secrets, no IsAdvisory flag).
func providerVerdictRecords(verdicts []policy.PolicyVerdict, finalDecision, baseVerdict string) []ledger.ProviderVerdictRecord {
	if len(verdicts) == 0 {
		return nil
	}
	out := make([]ledger.ProviderVerdictRecord, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, ledger.ProviderVerdictRecord{
			Provider:     v.Provider,
			Verdict:      v.Verdict,
			RulesMatched: v.RulesMatched,
			Reason:       v.Reason,
			Used:         providerVerdictWasUsed(v, finalDecision, baseVerdict),
		})
	}
	return out
}

func providerVerdictWasUsed(v policy.PolicyVerdict, finalDecision, baseVerdict string) bool {
	if baseVerdict != string(policy.VerdictAllow) || finalDecision != string(policy.VerdictAsk) {
		return false
	}
	return v.Verdict == string(policy.VerdictAsk) || v.Verdict == string(policy.VerdictDeny)
}

// providerFailureRecords maps collected provider failures to their ledger
// record form.
func providerFailureRecords(failures []core.ProviderFailure) []ledger.ProviderFailureRecord {
	if len(failures) == 0 {
		return nil
	}
	out := make([]ledger.ProviderFailureRecord, 0, len(failures))
	for _, f := range failures {
		out = append(out, ledger.ProviderFailureRecord{
			Provider: f.Provider,
			Kind:     f.Kind,
			Status:   f.Status,
			Reason:   f.Reason,
			Behavior: f.Behavior,
			TimedOut: f.TimedOut,
		})
	}
	return out
}

// detectIDsToStrings converts detection IDs to strings for the transient
// entry.SignalIDs / sir.signal_ids telemetry field.
func detectIDsToStrings(ids []detect.ID) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}
