package hooks

import (
	"errors"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
	providerreg "github.com/somoore/sir/pkg/provider"
)

// TestCollectPolicyVerdictsSurfacesFailure registers a policy provider whose
// entrypoint does not exist. InvokePolicy returns an error, and
// collectPolicyVerdictsFromRegistry must surface it as a ProviderFailure
// (item 8) rather than only logging to stderr — while still falling open
// (returning the native verdicts, never blocking).
func TestCollectPolicyVerdictsSurfacesFailure(t *testing.T) {
	reg := &providerreg.Registry{
		Providers: []providerreg.Entry{
			{
				Name:       "bogus-opa",
				Kind:       providerreg.KindPolicy,
				Entrypoint: "/nonexistent/sir-test-provider-does-not-exist",
				Enabled:    true,
			},
		},
	}

	verdicts, failures := collectPolicyVerdictsFromRegistry(reg, policy.PolicyRequest{Action: "push_origin"})

	// Fail-open: the bad provider produced no verdicts but evaluation continued.
	for _, v := range verdicts {
		if v.Provider == "bogus-opa" {
			t.Fatalf("failing provider must not contribute a verdict, got %+v", v)
		}
	}

	if len(failures) != 1 {
		t.Fatalf("expected exactly 1 provider failure, got %d: %+v", len(failures), failures)
	}
	f := failures[0]
	if f.Provider != "bogus-opa" {
		t.Errorf("failure provider: got %q, want %q", f.Provider, "bogus-opa")
	}
	if f.Reason == "" {
		t.Error("failure reason should be populated, not empty")
	}
	if f.Kind != providerreg.KindPolicy || f.Status != "unavailable" || f.Behavior != "ignored; native policy used" {
		t.Errorf("failure evidence fields mismatch: %+v", f)
	}
	// A missing entrypoint is a process error, not a timeout.
	if f.TimedOut {
		t.Errorf("missing-entrypoint failure should not be marked TimedOut: %+v", f)
	}
}

func TestCollectPolicyVerdictsSurfacesStderrOnlyFailure(t *testing.T) {
	stubPolicyProviderInvocation(t, func(entry providerreg.Entry, req policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return nil, errors.New("policy provider " + entry.Name + ": unavailable dependency not found")
	})
	reg := &providerreg.Registry{
		Providers: []providerreg.Entry{
			{
				Name:       "opa-bridge",
				Kind:       providerreg.KindPolicy,
				Entrypoint: "/unused/stubbed-provider",
				Enabled:    true,
			},
		},
	}

	verdicts, failures := collectPolicyVerdictsFromRegistry(reg, policy.PolicyRequest{Action: "push_origin"})
	for _, v := range verdicts {
		if v.Provider == "opa-bridge" {
			t.Fatalf("stderr-only provider must not contribute a verdict, got %+v", v)
		}
	}
	if len(failures) != 1 {
		t.Fatalf("expected exactly 1 provider failure, got %d: %+v", len(failures), failures)
	}
	f := failures[0]
	if f.Provider != "opa-bridge" || f.Kind != providerreg.KindPolicy {
		t.Fatalf("failure identity mismatch: %+v", f)
	}
	if f.Status != "unavailable" || f.TimedOut {
		t.Fatalf("failure classification mismatch: %+v", f)
	}
	if !strings.Contains(f.Reason, "unavailable dependency not found") {
		t.Fatalf("failure reason = %q, want missing-dependency classification", f.Reason)
	}
}

// TestProviderFailureTimedOut verifies the TimedOut flag is set when the
// provider error indicates a deadline was exceeded.
func TestProviderFailureTimedOut(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		timeout bool
	}{
		{"explicit timed out", errors.New("policy provider opa: timed out"), true},
		{"deadline exceeded", errors.New("context deadline exceeded"), true},
		{"plain process error", errors.New("policy provider opa: process error: exec format error"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := providerFailure("opa", tc.err)
			if f.TimedOut != tc.timeout {
				t.Errorf("TimedOut: got %v, want %v (err=%q)", f.TimedOut, tc.timeout, tc.err)
			}
			if tc.timeout && f.Status != "timeout" {
				t.Errorf("Status: got %q, want timeout", f.Status)
			}
			if !strings.Contains(f.Reason, tc.err.Error()) {
				t.Errorf("Reason should carry the error string: got %q", f.Reason)
			}
		})
	}
}

func stubPolicyProviderInvocation(t *testing.T, fn func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error)) {
	t.Helper()
	old := invokePolicyProvider
	invokePolicyProvider = fn
	t.Cleanup(func() {
		invokePolicyProvider = old
	})
}
