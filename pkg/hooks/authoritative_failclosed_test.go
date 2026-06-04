package hooks

import (
	"errors"
	"testing"

	"github.com/somoore/sir/pkg/policy"
	providerreg "github.com/somoore/sir/pkg/provider"
)

// Adversarial fail-closed suite for authoritative PDP providers (Chunk 2).
//
// THE CONTRACT: for an authoritative provider, every way it can fail to produce
// a usable decision must resolve to a fail-closed verdict (ask or deny per
// on_failure / managed mode) — NEVER a silent grant (allow). This suite is the
// net that must be green before the grant success-path is wired into the live
// decision flow. It mirrors the differential-test discipline: prove the
// dangerous direction is impossible before enabling the capability.

func authEntry(onFailure string) providerreg.Entry {
	return providerreg.Entry{
		Name:       "auth-opa",
		Kind:       providerreg.KindPolicy,
		Entrypoint: "/stubbed/auth-provider",
		Enabled:    true,
		Authority:  providerreg.AuthorityAuthoritative,
		OnFailure:  onFailure,
	}
}

// assertFailClosed checks the outcome is a fail-closed substitute, never allow.
func assertFailClosed(t *testing.T, got authoritativeOutcome, wantVerdict string) {
	t.Helper()
	if !got.Active {
		t.Fatalf("authoritative provider must yield Active=true")
	}
	if !got.FailClosed {
		t.Fatalf("expected FailClosed=true, got %+v", got)
	}
	if got.Verdict == string(policy.VerdictAllow) {
		t.Fatalf("FAIL-OPEN BUG: authoritative failure resolved to ALLOW (%+v)", got)
	}
	if got.Verdict != wantVerdict {
		t.Fatalf("fail-closed verdict = %q, want %q (%+v)", got.Verdict, wantVerdict, got)
	}
}

// THE DEADLIEST CASE, written first: empty stdout returns (nil,nil) from
// parsePolicyVerdicts — no error. For an authoritative provider, silence must
// NOT be a grant.
func TestAuthoritative_EmptyResponse_FailsClosed(t *testing.T) {
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return nil, nil // empty stdout: no verdict, no error
	})
	got := resolveAuthoritative(authEntry(providerreg.OnFailureAsk), policy.PolicyRequest{Action: "net_external"}, false)
	assertFailClosed(t, got, providerreg.OnFailureAsk)
}

func TestAuthoritative_EmptyResponse_DenyMode_FailsClosedDeny(t *testing.T) {
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return nil, nil
	})
	got := resolveAuthoritative(authEntry(providerreg.OnFailureDeny), policy.PolicyRequest{Action: "net_external"}, false)
	assertFailClosed(t, got, providerreg.OnFailureDeny)
}

func TestAuthoritative_Unreachable_FailsClosed(t *testing.T) {
	stubPolicyProviderInvocation(t, func(e providerreg.Entry, _ policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return nil, errors.New("policy provider " + e.Name + ": executable file not found")
	})
	got := resolveAuthoritative(authEntry(providerreg.OnFailureAsk), policy.PolicyRequest{Action: "push_remote"}, false)
	assertFailClosed(t, got, providerreg.OnFailureAsk)
}

func TestAuthoritative_Timeout_FailsClosed(t *testing.T) {
	stubPolicyProviderInvocation(t, func(e providerreg.Entry, _ policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return nil, errors.New("policy provider " + e.Name + ": context deadline exceeded")
	})
	got := resolveAuthoritative(authEntry(providerreg.OnFailureAsk), policy.PolicyRequest{Action: "commit"}, false)
	assertFailClosed(t, got, providerreg.OnFailureAsk)
}

func TestAuthoritative_MalformedVerdict_FailsClosed(t *testing.T) {
	// Provider returned a verdict object but with an unrecognized verdict string.
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return []policy.PolicyVerdict{{Provider: "auth-opa", Verdict: "maybe"}}, nil
	})
	got := resolveAuthoritative(authEntry(providerreg.OnFailureAsk), policy.PolicyRequest{Action: "commit"}, false)
	assertFailClosed(t, got, providerreg.OnFailureAsk)
}

// Managed mode forces deny-on-failure regardless of the entry's on_failure=ask.
func TestAuthoritative_ManagedMode_ForcesDenyOnFailure(t *testing.T) {
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return nil, nil // empty
	})
	got := resolveAuthoritative(authEntry(providerreg.OnFailureAsk), policy.PolicyRequest{Action: "net_external"}, true /* managed */)
	assertFailClosed(t, got, providerreg.OnFailureDeny)
}

// Multiple verdicts reduce to MOST RESTRICTIVE — a provider bug emitting an
// allow alongside a deny must never grant.
func TestAuthoritative_MultipleVerdicts_MostRestrictiveWins(t *testing.T) {
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return []policy.PolicyVerdict{
			{Provider: "auth-opa", Verdict: "allow"},
			{Provider: "auth-opa", Verdict: "deny"},
			{Provider: "auth-opa", Verdict: "ask"},
		}, nil
	})
	got := resolveAuthoritative(authEntry(providerreg.OnFailureAsk), policy.PolicyRequest{Action: "commit"}, false)
	if got.FailClosed {
		t.Fatalf("a valid (if multi) response should not be fail-closed: %+v", got)
	}
	if got.Verdict != string(policy.VerdictDeny) {
		t.Fatalf("most-restrictive reduction = %q, want deny (%+v)", got.Verdict, got)
	}
}

// activeAuthoritativePolicyProvider only treats a policy_provider explicitly
// marked authoritative as such — a default/advisory entry is not authoritative,
// and the wire is_advisory flag is irrelevant (O3 enforced in code).
func TestActiveAuthoritative_OnlyExplicitOptIn(t *testing.T) {
	cases := []struct {
		name      string
		entry     providerreg.Entry
		wantFound bool
	}{
		{"advisory default", providerreg.Entry{Name: "a", Kind: providerreg.KindPolicy, Enabled: true}, false},
		{"explicit authoritative", providerreg.Entry{Name: "b", Kind: providerreg.KindPolicy, Enabled: true, Authority: providerreg.AuthorityAuthoritative}, true},
		{"authoritative but disabled", providerreg.Entry{Name: "c", Kind: providerreg.KindPolicy, Enabled: false, Authority: providerreg.AuthorityAuthoritative}, false},
		{"effect provider cannot be authoritative", providerreg.Entry{Name: "d", Kind: providerreg.KindEffect, Enabled: true, Authority: providerreg.AuthorityAuthoritative}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := &providerreg.Registry{Providers: []providerreg.Entry{tc.entry}}
			_, found := activeAuthoritativePolicyProvider(reg)
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
		})
	}
}
