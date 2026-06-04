package provider

import "testing"

// Chunk 1 plumbing tests for PDP authority fields. These assert the inert
// defaults (an Entry with no authority set behaves exactly as today: advisory,
// fail-closed verdict "ask") and the explicit opt-in semantics. No behavior in
// the decision path changes until Chunk 2.

func TestEntry_IsAuthoritative(t *testing.T) {
	cases := []struct {
		name      string
		kind      string
		authority string
		want      bool
	}{
		{"default policy provider is advisory", KindPolicy, "", false},
		{"explicit advisory", KindPolicy, AuthorityAdvisory, false},
		{"authoritative policy provider", KindPolicy, AuthorityAuthoritative, true},
		{"effect provider cannot be authoritative", KindEffect, AuthorityAuthoritative, false},
		{"advisory provider cannot be authoritative", KindAdvisory, AuthorityAuthoritative, false},
		{"signal provider cannot be authoritative", KindSignal, AuthorityAuthoritative, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := Entry{Kind: tc.kind, Authority: tc.authority}
			if got := e.IsAuthoritative(); got != tc.want {
				t.Fatalf("IsAuthoritative() = %v, want %v (kind=%q authority=%q)",
					got, tc.want, tc.kind, tc.authority)
			}
		})
	}
}

func TestEntry_FailureVerdict(t *testing.T) {
	cases := []struct {
		onFailure string
		want      string
	}{
		{"", OnFailureAsk}, // default
		{OnFailureAsk, OnFailureAsk},
		{OnFailureDeny, OnFailureDeny},
		{"garbage", OnFailureAsk}, // unknown -> safe default ask
	}
	for _, tc := range cases {
		e := Entry{OnFailure: tc.onFailure}
		if got := e.FailureVerdict(); got != tc.want {
			t.Fatalf("FailureVerdict(on_failure=%q) = %q, want %q", tc.onFailure, got, tc.want)
		}
	}
}
