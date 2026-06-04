package hooks

import (
	"strings"
	"sync"
	"testing"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	providerreg "github.com/somoore/sir/pkg/provider"
	"github.com/somoore/sir/pkg/session"
)

// Grant-axis tests for PDP authoritative override (Chunk 2b). These prove the
// invariant inversion actually works: an authoritative provider's verdict
// REPLACES the native decision, INCLUDING granting what native would gate — and
// that the override is correctly attributed in the audit record. The fail-closed
// direction is covered by authoritative_failclosed_test.go; this covers the
// success direction.

// withProviderRegistry injects a registry for the duration of a test, resetting
// the sync.Once-cached loader so the injected value is used, and restoring after.
func withProviderRegistry(t *testing.T, reg *providerreg.Registry) {
	t.Helper()
	providerRegistryOnce = sync.Once{}
	providerRegistryVal = reg
	providerRegistryOnce.Do(func() {}) // mark done so loadProviderRegistry returns reg
	t.Cleanup(func() {
		providerRegistryOnce = sync.Once{}
		providerRegistryVal = nil
	})
}

// authReg returns a registry with one active authoritative policy provider.
func authReg() *providerreg.Registry {
	return &providerreg.Registry{Providers: []providerreg.Entry{{
		Name:       "auth-opa",
		Kind:       providerreg.KindPolicy,
		Entrypoint: "/stubbed/auth-provider",
		Enabled:    true,
		Authority:  providerreg.AuthorityAuthoritative,
	}}}
}

// TestAuthoritative_Grants_OverridesNativeDeny is the core invariant-inversion
// test: when the authoritative provider returns allow, the resolved outcome is
// allow even though native would gate the action — and it is NOT fail-closed.
func TestAuthoritative_Grants_OverridesNativeDeny(t *testing.T) {
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return []policy.PolicyVerdict{{Provider: "auth-opa", Verdict: "allow", RulesMatched: []string{"allow-egress"}}}, nil
	})
	entry, ok := activeAuthoritativePolicyProvider(authReg())
	if !ok {
		t.Fatal("expected an active authoritative provider")
	}
	// net_external is a verb native would ASK/DENY; the authoritative grant must win.
	out := resolveAuthoritative(entry, policy.PolicyRequest{Action: "net_external"}, false)
	if out.FailClosed {
		t.Fatalf("a real allow verdict must not be fail-closed: %+v", out)
	}
	if out.Verdict != string(policy.VerdictAllow) {
		t.Fatalf("authoritative grant = %q, want allow", out.Verdict)
	}
	if out.Provider != "auth-opa" {
		t.Fatalf("provider attribution = %q, want auth-opa", out.Provider)
	}
}

// TestAuthoritative_Deny_IsTakenAsIs: an authoritative deny is the decision too
// (not just escalation) — it is taken as-is, not fail-closed.
func TestAuthoritative_Deny_IsTakenAsIs(t *testing.T) {
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return []policy.PolicyVerdict{{Provider: "auth-opa", Verdict: "deny", Reason: "blocked by policy"}}, nil
	})
	entry, _ := activeAuthoritativePolicyProvider(authReg())
	out := resolveAuthoritative(entry, policy.PolicyRequest{Action: "commit"}, false)
	if out.FailClosed || out.Verdict != string(policy.VerdictDeny) {
		t.Fatalf("authoritative deny = %+v, want deny, not fail-closed", out)
	}
}

// TestAuthoritative_OverrideBlock_AppliesGrantAndCoherentReason drives the REAL
// evaluatePolicy override block end-to-end: an authoritative allow on a verb
// native would gate (net_external) must yield a final allow AND a coherent
// reason — never the stale native deny reason stapled to an allow. Also asserts
// the audit fields (native base recorded, floors bypassed).
func TestAuthoritative_OverrideBlock_AppliesGrantAndCoherentReason(t *testing.T) {
	withProviderRegistry(t, authReg())
	// Provider grants allow with NO reason — the exact case that exposed the
	// stale-native-reason bug (outcome.Reason == "").
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return []policy.PolicyVerdict{{Provider: "auth-opa", Verdict: "allow"}}, nil
	})

	projectRoot := t.TempDir()
	resp, err := evaluatePolicy(
		projectRoot,
		&HookPayload{ToolName: "Bash"},
		nil,
		Intent{Verb: policy.VerbNetExternal, Target: "https://example.com"},
		lease.DefaultLease(),
		session.NewState(projectRoot),
		core.Label{Sensitivity: "public", Trust: "trusted", Provenance: "user"},
	)
	if err != nil {
		t.Fatalf("evaluatePolicy: %v", err)
	}
	if resp.Decision != policy.VerdictAllow {
		t.Fatalf("authoritative override decision = %q, want allow", resp.Decision)
	}
	// The reason must describe the AUTHORITATIVE allow, not the native deny.
	if strings.Contains(strings.ToLower(resp.Reason), "blocked") ||
		strings.Contains(strings.ToLower(resp.Reason), "denied by your security policy") {
		t.Fatalf("stale native reason leaked onto an allow: %q", resp.Reason)
	}
	if !strings.Contains(resp.Reason, "auth-opa") {
		t.Fatalf("reason should attribute the authoritative provider, got %q", resp.Reason)
	}
	// Audit: native would have gated net_external (ask/deny); record it as base.
	if resp.AuthoritativeProvider != "auth-opa" {
		t.Fatalf("AuthoritativeProvider = %q, want auth-opa", resp.AuthoritativeProvider)
	}
	if !resp.AuthoritativeFloorsBypassed || resp.AuthoritativeFailClosed {
		t.Fatalf("expected floors-bypassed grant, got bypassed=%v failClosed=%v",
			resp.AuthoritativeFloorsBypassed, resp.AuthoritativeFailClosed)
	}
	if resp.AuthoritativeNativeBase == string(policy.VerdictAllow) {
		t.Fatalf("native base should be the gated verdict (ask/deny), got %q — the override is not demonstrating a real grant",
			resp.AuthoritativeNativeBase)
	}
}

// TestAuthoritative_RegistrySkipsAuthoritativeFromAdvisory verifies the
// authoritative provider is NOT folded into the advisory verdict list (it would
// be double-invoked and merely escalate instead of granting).
func TestAuthoritative_RegistrySkipsAuthoritativeFromAdvisory(t *testing.T) {
	called := 0
	stubPolicyProviderInvocation(t, func(e providerreg.Entry, _ policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		called++
		return []policy.PolicyVerdict{{Provider: e.Name, Verdict: "allow"}}, nil
	})
	reg := authReg()
	verdicts, failures := collectPolicyVerdictsFromRegistry(reg, policy.PolicyRequest{Action: "net_external"})
	if len(failures) != 0 {
		t.Fatalf("unexpected failures: %+v", failures)
	}
	for _, v := range verdicts {
		if v.Provider == "auth-opa" {
			t.Fatalf("authoritative provider must NOT appear in advisory verdicts: %+v", v)
		}
	}
	if called != 0 {
		t.Fatalf("authoritative provider must not be invoked during advisory collection, called=%d", called)
	}
}
