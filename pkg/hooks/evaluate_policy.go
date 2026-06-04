package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/sdk"
	"github.com/somoore/sir/pkg/session"
	"github.com/somoore/sir/pkg/signal"
)

func evaluatePolicy(projectRoot string, payload *HookPayload, signals []sdk.Signal, intent Intent, l *lease.Lease, state *session.State, labels core.Label) (*core.Response, error) {
	// Clear any stale provider evaluation from a prior call so the ledger never
	// attributes a previous tool call's provider verdicts to this one.
	resetLastProviderEvaluation()

	req, err := buildCoreRequest(projectRoot, payload, intent, l, state, labels)
	if err != nil {
		return nil, fmt.Errorf("build core request: %w", err)
	}

	// Build a fully-populated PolicyRequest. Every field is populated so that
	// OPA/Cedar providers receive complete context — they should not have to
	// handle empty strings for attribution_confidence, enforceability, or mode.
	actorKind := signal.ActorKindFromSignals(signals)
	if actorKind == "unknown" && payload != nil && payload.AgentID != "" {
		actorKind = "ai_coding_agent"
	}
	policyReq := policy.PolicyRequest{
		Action:          string(intent.Verb),
		Target:          intent.Target,
		ResolvedActor:   actorKind,
		AttributionConf: signal.AttributionConfidence(signals),
		Taint:           sessionTaintList(state),
		Enforceability:  signal.EnforceabilityForSignals(signals),
		Mode:            leaseMode(l),
	}
	// v1 session/integrity signals: the explicit inputs an authoritative provider
	// needs to re-implement the native floors it may bypass under PDP delegation
	// (the coarse Taint list collapses these). See pdp-provider-delegation.md §2b.
	if state != nil {
		policyReq.SessionSecret = state.SecretSession
		policyReq.SessionWasSecret = state.SessionEverSecret
		policyReq.SessionUntrustedRead = state.RecentlyReadUntrusted
		policyReq.SessionUntrustedThisTurn = state.UntrustedContentThisTurn
	}

	verdicts, failures := collectPolicyVerdicts(policyReq)
	req.PolicyVerdicts = verdicts

	if _, lookErr := exec.LookPath(core.CoreBinaryPath); lookErr != nil {
		fmt.Fprintf(os.Stderr, "sir WARNING: mister-core binary not found — using Go fallback. Policy enforcement is degraded. Reinstall sir to restore full protection.\n")
	}
	coreResp, err := core.Evaluate(req)
	if err != nil {
		return nil, fmt.Errorf("core evaluate: %w", err)
	}

	// Record the pre-composition base verdict so `sir why` can show whether an
	// advisory provider actually changed the outcome. The only ambiguous case is
	// a final "ask" with active providers: it could be a native ask, or an
	// allow that an advisory escalated. Resolve it by re-running the SAME engine
	// (mister-core or the Go fallback) with the verdicts removed — authoritative
	// by construction, no cross-engine guess. Every other case (no providers, or
	// final allow/deny) has base == final, so we skip the extra evaluation and
	// keep the hot path single-shot.
	//
	// We stash the base only when it actually differs from the COMPOSED verdict
	// (an escalation occurred), comparing against coreResp.Decision here — not
	// against the ledger's post-fold `recorded` value, which observe-mode and the
	// thinking-guard can change for reasons unrelated to provider composition.
	coreResp.BaseVerdict = coreResp.Decision
	if len(verdicts) > 0 && coreResp.Decision == policy.VerdictAsk {
		req.PolicyVerdicts = nil
		if baseResp, baseErr := core.Evaluate(req); baseErr == nil {
			coreResp.BaseVerdict = baseResp.Decision
		}
	}
	var escalatedBase string
	if coreResp.BaseVerdict != coreResp.Decision {
		escalatedBase = string(coreResp.BaseVerdict)
	}

	// PDP authoritative override. At this point coreResp.Decision is the native +
	// advisory verdict (floors executed). If an authoritative policy_provider is
	// active, its verdict REPLACES that decision — including granting what native
	// would have gated ("policy is the whole truth"). The native verdict we just
	// computed becomes the audit base (native_base_verdict). Fail-closed and
	// most-restrictive-reduction are handled inside resolveAuthoritative; this
	// only applies the result. The compose functions stay untouched: the
	// substitution is a Go-orchestrator override, so parity is unaffected.
	// See docs/research/pdp-provider-delegation.md §8.
	reg, regErr := loadProviderRegistryChecked()
	if regErr != nil {
		// CORRUPT control-plane state: providers.json is unreadable/malformed (a
		// MISSING file is a nil error and falls through to the normal no-provider
		// path). We cannot tell whether an authoritative provider was configured,
		// so we must assume it was and fail closed — never silently fall back to
		// native and risk allowing what the provider would have denied (#3).
		coreResp.AuthoritativeActive = true
		coreResp.AuthoritativeFailClosed = true
		coreResp.AuthoritativeProvider = "(registry)"
		coreResp.AuthoritativeNativeBase = string(coreResp.Decision)
		failVerdict := policy.VerdictAsk
		if leaseIsManaged(l) {
			failVerdict = policy.VerdictDeny
		}
		coreResp.BaseVerdict = coreResp.Decision
		coreResp.Decision = failVerdict
		coreResp.Reason = "Provider registry is corrupt or unreadable — held for safety (fail closed). Run `sir doctor`."
		setLastAuthoritativeRecord(&ledger.ProviderVerdictRecord{
			Provider:          "(registry)",
			Verdict:           string(failVerdict),
			Reason:            coreResp.Reason,
			Used:              true,
			Authoritative:     true,
			NativeBaseVerdict: string(coreResp.BaseVerdict),
			FailClosed:        true,
		})
	} else if entry, ok := activeAuthoritativePolicyProvider(reg); ok {
		nativeVerdict := string(coreResp.Decision)
		outcome := resolveAuthoritative(entry, policyReq, leaseIsManaged(l))
		coreResp.AuthoritativeActive = true // verdict is FINAL — seal it downstream
		coreResp.AuthoritativeProvider = outcome.Provider
		coreResp.AuthoritativeNativeBase = nativeVerdict
		coreResp.AuthoritativeFloorsBypassed = !outcome.FailClosed
		coreResp.AuthoritativeFailClosed = outcome.FailClosed
		coreResp.Decision = policy.Verdict(outcome.Verdict)
		// ALWAYS replace the reason on override: the native reason describes the
		// native verdict, which no longer holds. Leaving it would render e.g.
		// "ALLOWED … because: external network requests are blocked" — the
		// native-deny reason stapled to an authoritative allow. Synthesize a
		// coherent reason when the provider gives none.
		if outcome.Reason != "" {
			coreResp.Reason = outcome.Reason
		} else {
			coreResp.Reason = authoritativeReason(outcome)
		}
		// The native verdict is now the base; the authoritative verdict is final.
		coreResp.BaseVerdict = policy.Verdict(nativeVerdict)
		// Stash the forensic audit record (O4) for the ledger at the override
		// point, so it reflects the override — not a stale native explanation.
		setLastAuthoritativeRecord(&ledger.ProviderVerdictRecord{
			Provider:          outcome.Provider,
			Verdict:           outcome.Verdict,
			RulesMatched:      outcome.RulesMatched,
			Reason:            outcome.Reason,
			Used:              true,
			Authoritative:     true,
			NativeBaseVerdict: nativeVerdict,
			FloorsBypassed:    !outcome.FailClosed,
			FailClosed:        outcome.FailClosed,
		})
	}

	// Attach the provider verdicts/failures Go collected (pre-Rust) to the
	// response so they reach the ledger and `sir why`, attributed separately
	// from native policy rules. These are NOT decoded from the Rust wire — Go
	// already holds them. Stashing them in a package-level holder bridges to
	// appendEvaluationLedgerEntry, which is called from evaluate.go with only
	// scalar verdict/reason and cannot take the *core.Response.
	coreResp.ProviderVerdicts = verdicts
	coreResp.ProviderFailures = failures
	setLastProviderEvaluation(verdicts, failures, escalatedBase)
	return coreResp, nil
}

// lastProviderEvaluation bridges provider verdicts/failures from evaluatePolicy
// to appendEvaluationLedgerEntry within a single `sir guard` process. Each
// guard invocation evaluates exactly one tool call, so a process-scoped holder
// is unambiguous. It mirrors the providerRegistryVal caching pattern. It is
// reset at the start of every evaluation so a long-lived or test process never
// reads stale verdicts from a prior call.
var (
	lastProviderMu       sync.Mutex
	lastProviderVerdicts []policy.PolicyVerdict
	lastProviderFailures []core.ProviderFailure
	lastProviderBase     string
	lastAuthoritative    *ledger.ProviderVerdictRecord // nil = no authoritative override this eval
)

func setLastProviderEvaluation(verdicts []policy.PolicyVerdict, failures []core.ProviderFailure, base string) {
	lastProviderMu.Lock()
	defer lastProviderMu.Unlock()
	lastProviderVerdicts = verdicts
	lastProviderFailures = failures
	lastProviderBase = base
}

// setLastAuthoritativeRecord stashes the authoritative-override audit record so
// appendEvaluationLedgerEntry can persist it alongside the advisory verdicts.
func setLastAuthoritativeRecord(rec *ledger.ProviderVerdictRecord) {
	lastProviderMu.Lock()
	defer lastProviderMu.Unlock()
	lastAuthoritative = rec
}

// takeLastAuthoritativeRecord returns and clears the authoritative override
// record from the most recent evaluation.
func takeLastAuthoritativeRecord() *ledger.ProviderVerdictRecord {
	lastProviderMu.Lock()
	defer lastProviderMu.Unlock()
	rec := lastAuthoritative
	lastAuthoritative = nil
	return rec
}

func resetLastProviderEvaluation() {
	setLastProviderEvaluation(nil, nil, "")
	setLastAuthoritativeRecord(nil)
}

// takeLastProviderEvaluation returns the verdicts/failures/base verdict from the
// most recent evaluatePolicy call and CLEARS the holder, so a subsequent
// short-circuit path (deny-all, posture, secret-read gate) that calls
// appendEvaluationLedgerEntry without going through evaluatePolicy never
// inherits a prior call's verdicts.
func takeLastProviderEvaluation() ([]policy.PolicyVerdict, []core.ProviderFailure, string) {
	lastProviderMu.Lock()
	defer lastProviderMu.Unlock()
	verdicts, failures, base := lastProviderVerdicts, lastProviderFailures, lastProviderBase
	lastProviderVerdicts, lastProviderFailures, lastProviderBase = nil, nil, ""
	return verdicts, failures, base
}

// leaseMode returns the lease's operating mode for the PolicyRequest.
func leaseMode(l *lease.Lease) string {
	if l == nil {
		return ""
	}
	if l.ObserveOnly {
		return "observe"
	}
	if l.Mode != "" {
		return l.Mode
	}
	return "guard"
}

// leaseIsManaged reports whether the lease is in managed mode, where an
// authoritative provider that cannot decide must fail closed to DENY (a missing
// PDP in managed mode is a control failure, not a friction nuisance).
func leaseIsManaged(l *lease.Lease) bool {
	return l != nil && l.Mode == "managed"
}

// sessionTaintList builds the taint string slice for a PolicyRequest from
// session state flags that indicate prior credential or untrusted-content exposure.
func sessionTaintList(state *session.State) []string {
	if state == nil {
		return nil
	}
	var taint []string
	if state.SessionEverSecret {
		taint = append(taint, "credential_access")
	}
	if state.RecentlyReadUntrusted {
		taint = append(taint, "untrusted_content")
	}
	if len(state.TaintedMCPServers) > 0 {
		taint = append(taint, "mcp_injection")
	}
	return taint
}
