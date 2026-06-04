package hooks

import (
	"fmt"

	"github.com/somoore/sir/pkg/policy"
	providerreg "github.com/somoore/sir/pkg/provider"
)

// Authoritative policy-provider resolution (PDP delegation, Chunk 2).
//
// When an operator marks the active policy_provider as authoritative
// (Entry.Authority == "authoritative"), its verdict REPLACES the native
// decision — including granting actions native would gate. This file resolves
// that verdict in the Go orchestrator, ABOVE the pure compose functions, which
// stay untouched (so Go/Rust parity and the differential test remain valid by
// construction). See docs/research/pdp-provider-delegation.md §8.
//
// SAFETY MODEL — fail closed. "Policy is the whole truth" governs what happens
// when the provider ANSWERS; it never changes what happens when the provider
// CANNOT answer. Every way an authoritative provider fails to produce a usable
// decision (unreachable, spawn error, timeout, malformed output, AND — the
// deadliest — empty stdout, which parsePolicyVerdicts reports as (nil,nil) with
// NO error) resolves to a fail-closed verdict (ask or deny per the entry's
// on_failure), NEVER a silent grant.
//
// AUTHORITY IS REGISTRY-ONLY (O3). A provider's authority comes solely from the
// operator's registry entry (entry.IsAuthoritative()). The wire is_advisory flag
// is irrelevant to authority: an authoritative entry decides even if it sets
// is_advisory:true, and a non-authoritative entry can NEVER self-promote by
// setting is_advisory:false.

// authoritativeOutcome is the result of resolving the active authoritative
// policy provider for one request.
type authoritativeOutcome struct {
	// Active is true when an authoritative policy_provider is configured+enabled.
	// When false, the caller proceeds with native + advisory composition unchanged.
	Active bool

	// Provider is the authoritative provider's name (for the ledger/audit).
	Provider string

	// Verdict is the resolved final verdict ("allow", "ask", or "deny") that must
	// REPLACE the native decision. Always set when Active is true.
	Verdict string

	// FailClosed is true when the verdict is a fail-closed substitute because the
	// provider could not produce a decision (vs. a real provider verdict).
	FailClosed bool

	// Reason is a human-readable explanation (provider rule reason, or the
	// fail-closed reason). Never contains raw secret values.
	Reason string

	// RulesMatched carries the provider's matched rule IDs when it decided.
	RulesMatched []string
}

// activeAuthoritativePolicyProvider returns the single authoritative
// policy_provider entry if one is active, else (zero, false). The registry
// already enforces at most one active policy_provider (exclusiveKind), so there
// is at most one authoritative entry; if more than one is somehow present we
// fail closed by treating the FIRST as authoritative (deterministic) — the
// registry invariant should prevent this, but we never silently pick "none".
func activeAuthoritativePolicyProvider(reg *providerreg.Registry) (providerreg.Entry, bool) {
	if reg == nil {
		return providerreg.Entry{}, false
	}
	for _, e := range reg.Active(providerreg.KindPolicy) {
		if e.IsAuthoritative() {
			return e, true
		}
	}
	return providerreg.Entry{}, false
}

// resolveAuthoritative invokes the authoritative provider and reduces its output
// to a single final verdict, applying the fail-closed model. managedMode forces
// deny-on-failure regardless of the entry's on_failure setting (a missing PDP in
// managed mode is a control failure).
//
// This is the safety core. The grant (success) path is intentionally the LAST
// branch: every failure mode above it is fail-closed first.
func resolveAuthoritative(entry providerreg.Entry, req policy.PolicyRequest, managedMode bool) authoritativeOutcome {
	failVerdict := entry.FailureVerdict() // "ask" (default) or "deny"
	if managedMode {
		failVerdict = providerreg.OnFailureDeny
	}
	failClosed := func(reason string) authoritativeOutcome {
		return authoritativeOutcome{
			Active:     true,
			Provider:   entry.Name,
			Verdict:    failVerdict,
			FailClosed: true,
			Reason: fmt.Sprintf("authoritative policy provider %q did not return a usable decision (%s) — %s",
				entry.Name, reason, failClosedAction(failVerdict)),
		}
	}

	verdicts, err := invokePolicyProvider(entry, req)
	if err != nil {
		// Unreachable / spawn error / timeout / malformed output all surface here.
		return failClosed(err.Error())
	}
	if len(verdicts) == 0 {
		// THE DEADLIEST CASE. parsePolicyVerdicts returns (nil,nil) on empty
		// stdout — no error. For an ADVISORY provider that means "quiet allow,
		// defer to native". For an AUTHORITATIVE provider, silence cannot mean
		// grant: there is no native floor behind it to catch the action.
		return failClosed("empty response (no verdict)")
	}

	// Reduce multiple verdicts to one: MOST RESTRICTIVE wins, so a provider that
	// emits several verdicts can never accidentally grant. A verdict with an
	// unrecognized value is itself a fail-closed signal (malformed decision).
	final := policy.VerdictAllow
	var rules []string
	var reason string
	for _, v := range verdicts {
		pv := policy.Verdict(v.Verdict)
		if pv != policy.VerdictAllow && pv != policy.VerdictAsk && pv != policy.VerdictDeny {
			return failClosed(fmt.Sprintf("unrecognized verdict %q", v.Verdict))
		}
		if verdictRank(pv) > verdictRank(final) {
			final = pv
		}
		rules = append(rules, v.RulesMatched...)
		if v.Reason != "" {
			reason = v.Reason
		}
	}

	// SUCCESS / GRANT path — the authoritative provider decided. This verdict
	// REPLACES the native decision (it may grant what native would have gated).
	return authoritativeOutcome{
		Active:       true,
		Provider:     entry.Name,
		Verdict:      string(final),
		FailClosed:   false,
		Reason:       reason,
		RulesMatched: rules,
	}
}

// verdictRank orders verdicts by restrictiveness: allow < ask < deny. Used for
// the most-restrictive reduction and never-grant-by-accident guarantee.
func verdictRank(v policy.Verdict) int {
	switch v {
	case policy.VerdictAllow:
		return 0
	case policy.VerdictAsk:
		return 1
	case policy.VerdictDeny:
		return 2
	}
	return 3 // unknown — most restrictive; callers treat as fail-closed upstream
}

func failClosedAction(verdict string) string {
	if verdict == providerreg.OnFailureDeny {
		return "blocked (fail closed)"
	}
	return "held for approval (fail closed)"
}

// authoritativeReason synthesizes a coherent reason for an override when the
// provider supplied none, so the ledger/`sir why` never staples the stale native
// reason onto an authoritative verdict.
func authoritativeReason(o authoritativeOutcome) string {
	switch policy.Verdict(o.Verdict) {
	case policy.VerdictAllow:
		return fmt.Sprintf("Allowed by authoritative policy provider %q.", o.Provider)
	case policy.VerdictDeny:
		return fmt.Sprintf("Denied by authoritative policy provider %q.", o.Provider)
	default:
		return fmt.Sprintf("Approval required by authoritative policy provider %q.", o.Provider)
	}
}
