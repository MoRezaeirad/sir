package hooks

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/policy"
	providerreg "github.com/somoore/sir/pkg/provider"
)

// providerRegistryOnce loads the registry once per process. Each `sir guard`
// invocation is a short-lived process (one tool-call evaluation), so this
// provides per-invocation caching with no staleness risk.
var (
	providerRegistryOnce   sync.Once
	providerRegistryVal    *providerreg.Registry
	providerRegistryErr    error
	invokePolicyProvider   = providerreg.InvokePolicy
	invokeAdvisoryProvider = providerreg.InvokeAdvisory
	// invokeAuthoritativeProvider uses the larger authoritative timeout (the
	// verdict IS the decision). Separate indirection so tests can stub it and so
	// advisory collection keeps the tight 200ms budget.
	invokeAuthoritativeProvider = providerreg.InvokePolicyAuthoritative
)

func loadProviderRegistry() *providerreg.Registry {
	reg, _ := loadProviderRegistryChecked()
	return reg
}

// loadProviderRegistryChecked returns the registry AND any load error. A load
// error means the on-disk registry (~/.sir/providers.json) is CORRUPT or
// unreadable — distinct from "no registry file" (providerreg.Load returns a nil
// error for a missing file). Callers that gate a security decision on the
// registry (the PDP authoritative path) MUST fail closed on a non-nil error: a
// corrupt control-plane file cannot tell us whether an authoritative provider
// was configured, so we must assume it was (non-negotiable #3 — corrupted state
// fails closed; only a MISSING file seeds defaults).
func loadProviderRegistryChecked() (*providerreg.Registry, error) {
	providerRegistryOnce.Do(func() {
		reg, err := providerreg.Load()
		if reg == nil {
			reg = &providerreg.Registry{}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "sir: load provider registry: %v\n", err)
		}
		providerRegistryVal = reg
		providerRegistryErr = err
	})
	return providerRegistryVal, providerRegistryErr
}

// collectPolicyVerdicts calls all active policy_providers from the registry and
// returns the merged, normalized verdict slice. Provider errors are non-fatal —
// a slow or unavailable provider never blocks evaluation.
//
// The function acts as an adapter: as long as a provider wraps its output using
// the SDK (or manually returns sir.policy_verdict.v0 JSON), SIR normalizes the
// response — filling missing fields, forcing IsAdvisory=true, using the registry
// entry name when the provider field is absent.
//
// It also returns the set of providers that failed (timeout, missing
// entrypoint, malformed output). Failures are non-fatal — evaluation falls open
// to native floors — but they are surfaced so the ledger and `sir why` can show
// that a provider's input was missing rather than silently absent (item 8).
func collectPolicyVerdicts(req policy.PolicyRequest) ([]policy.PolicyVerdict, []core.ProviderFailure) {
	return collectPolicyVerdictsFromRegistry(loadProviderRegistry(), req)
}

// collectPolicyVerdictsFromRegistry is the registry-explicit core of
// collectPolicyVerdicts. It is split out so tests can inject a registry
// (e.g. a bogus provider entrypoint) without touching on-disk state.
func collectPolicyVerdictsFromRegistry(reg *providerreg.Registry, req policy.PolicyRequest) ([]policy.PolicyVerdict, []core.ProviderFailure) {
	// Built-in NativePolicy (no-op baseline — always runs first).
	var out []policy.PolicyVerdict
	var failures []core.ProviderFailure
	if v, err := (policy.NativePolicy{}).Evaluate(context.Background(), req); err == nil {
		out = append(out, v...)
	}

	// Registry-based policy providers (OPA, Cedar, Falco, custom packs, etc.)
	for _, entry := range reg.Active(providerreg.KindPolicy) {
		// An AUTHORITATIVE provider is resolved separately in the orchestrator
		// (resolveAuthoritative) — its verdict REPLACES the native decision and
		// must NOT be folded in here as advisory (that would both double-invoke it
		// and let it merely escalate allow→ask instead of granting). Skip it.
		if entry.IsAuthoritative() {
			continue
		}
		verdicts, err := invokePolicyProvider(entry, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sir: policy provider %s: %v\n", entry.Name, err)
			failures = append(failures, providerFailure(entry.Name, err))
			continue
		}
		// Auto-normalize: fill missing Provider field with registry entry name.
		for i := range verdicts {
			if verdicts[i].Provider == "" {
				verdicts[i].Provider = entry.Name
			}
			verdicts[i].IsAdvisory = true // always advisory, never authoritative
		}
		out = append(out, verdicts...)
	}

	// Advisory providers (risk scoring, threat feeds, ML models).
	// High-risk advisory signals are translated to ask verdicts and composed
	// through the same compose_policy_verdicts() path in Rust — advisory risk
	// can raise allow→ask but never lower a deny.
	advisory, advisoryFailures := collectAdvisoryVerdicts(req, reg)
	out = append(out, advisory...)
	failures = append(failures, advisoryFailures...)

	return out, failures
}

// providerFailure builds a ProviderFailure from a provider error, marking
// TimedOut when the error string indicates a deadline was exceeded.
func providerFailure(name string, err error) core.ProviderFailure {
	reason := err.Error()
	status := "failed"
	if strings.Contains(reason, "timed out") || strings.Contains(reason, "deadline exceeded") {
		status = "timeout"
	} else if strings.Contains(reason, "executable file not found") ||
		strings.Contains(reason, "no such file") ||
		strings.Contains(reason, "not found") {
		status = "unavailable"
	} else if strings.Contains(reason, "unmarshal") ||
		strings.Contains(reason, "invalid JSON") ||
		strings.Contains(reason, "wrong schema") {
		status = "invalid_output"
	}
	return core.ProviderFailure{
		Provider: name,
		Kind:     providerreg.KindPolicy,
		Status:   status,
		Reason:   reason,
		Behavior: "ignored; native policy used",
		TimedOut: status == "timeout",
	}
}

// collectAdvisoryVerdicts invokes all active advisory_providers and translates
// their risk assessments into advisory policy verdicts for Rust composition.
// Risk translation: high/critical → ask, medium → allow (logged), low → nothing.
// It also returns any advisory provider failures (non-fatal, surfaced for audit).
func collectAdvisoryVerdicts(req policy.PolicyRequest, reg *providerreg.Registry) ([]policy.PolicyVerdict, []core.ProviderFailure) {
	var risks []*providerreg.AdvisoryRisk
	var failures []core.ProviderFailure
	for _, entry := range reg.Active(providerreg.KindAdvisory) {
		risk, err := invokeAdvisoryProvider(entry, req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sir: advisory provider %s: %v\n", entry.Name, err)
			f := providerFailure(entry.Name, err)
			f.Kind = providerreg.KindAdvisory
			failures = append(failures, f)
			continue
		}
		if risk != nil {
			risks = append(risks, risk)
		}
	}

	worst := providerreg.HighestAdvisoryRisk(risks)
	if worst == nil || worst.Level == "low" {
		return nil, failures
	}

	// Translate risk to an advisory verdict that Rust can compose.
	verdict := "ask"
	if worst.Level == "medium" {
		// Medium risk: record and nudge but don't prompt (allow stays allow).
		return nil, failures
	}

	return []policy.PolicyVerdict{{
		Provider:     worst.Provider,
		Verdict:      verdict,
		RulesMatched: []string{"advisory-" + worst.Level + "-risk"},
		Reason:       worst.Reason,
		IsAdvisory:   true,
	}}, failures
}
