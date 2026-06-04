package provider

import "testing"

func policyReg(enabled bool) *Registry {
	return &Registry{Providers: []Entry{{
		Name:    "opa",
		Kind:    KindPolicy,
		Enabled: enabled,
	}}}
}

func TestSetAuthority_PromotesEnabledPolicyProvider(t *testing.T) {
	r := policyReg(true)
	if err := r.SetAuthority("opa", AuthorityAuthoritative, OnFailureDeny); err != nil {
		t.Fatalf("SetAuthority: %v", err)
	}
	e, _ := r.ByName("opa")
	if !e.IsAuthoritative() {
		t.Fatal("provider should be authoritative")
	}
	if e.OnFailure != OnFailureDeny {
		t.Fatalf("on_failure = %q, want deny", e.OnFailure)
	}
}

func TestSetAuthority_RejectsNonPolicyKind(t *testing.T) {
	r := &Registry{Providers: []Entry{{Name: "sb", Kind: KindEffect, Enabled: true}}}
	if err := r.SetAuthority("sb", AuthorityAuthoritative, OnFailureAsk); err == nil {
		t.Fatal("an effect_provider must not be allowed to become authoritative")
	}
}

func TestSetAuthority_RequiresEnabled(t *testing.T) {
	r := policyReg(false) // disabled
	if err := r.SetAuthority("opa", AuthorityAuthoritative, OnFailureAsk); err == nil {
		t.Fatal("a disabled provider must not be allowed to become authoritative")
	}
}

func TestSetAuthority_RejectsBadOnFailure(t *testing.T) {
	r := policyReg(true)
	if err := r.SetAuthority("opa", AuthorityAuthoritative, "maybe"); err == nil {
		t.Fatal("an invalid on_failure value must be rejected")
	}
}

func TestSetAuthority_DemoteClearsBothFields(t *testing.T) {
	r := policyReg(true)
	_ = r.SetAuthority("opa", AuthorityAuthoritative, OnFailureDeny)
	if err := r.SetAuthority("opa", AuthorityAdvisory, ""); err != nil {
		t.Fatalf("demote: %v", err)
	}
	e, _ := r.ByName("opa")
	if e.IsAuthoritative() || e.Authority != "" || e.OnFailure != "" {
		t.Fatalf("demote must clear authority and on_failure, got authority=%q on_failure=%q", e.Authority, e.OnFailure)
	}
}

func TestSetAuthority_UnknownProvider(t *testing.T) {
	r := policyReg(true)
	if err := r.SetAuthority("nope", AuthorityAuthoritative, OnFailureAsk); err == nil {
		t.Fatal("unknown provider must error")
	}
}

// Authority is exclusive: promoting B must clear A's authority, so the registry
// never holds two authoritative policy providers (which would make the actual
// decision-maker diverge from what `sir provider status` reports). Codex P2.
func TestSetAuthority_IsExclusive(t *testing.T) {
	r := &Registry{Providers: []Entry{
		{Name: "A", Kind: KindPolicy, Enabled: true},
		{Name: "B", Kind: KindPolicy, Enabled: true},
	}}
	if err := r.SetAuthority("A", AuthorityAuthoritative, OnFailureDeny); err != nil {
		t.Fatalf("promote A: %v", err)
	}
	if err := r.SetAuthority("B", AuthorityAuthoritative, OnFailureAsk); err != nil {
		t.Fatalf("promote B: %v", err)
	}
	// Exactly one authoritative entry, and it is B.
	var authoritative []string
	for _, e := range r.Providers {
		if e.IsAuthoritative() {
			authoritative = append(authoritative, e.Name)
		}
	}
	if len(authoritative) != 1 || authoritative[0] != "B" {
		t.Fatalf("expected exactly one authoritative provider (B), got %v", authoritative)
	}
	// A must have been fully cleared (no stale on_failure either).
	a, _ := r.ByName("A")
	if a.Authority != "" || a.OnFailure != "" {
		t.Fatalf("A should be fully demoted, got authority=%q on_failure=%q", a.Authority, a.OnFailure)
	}
}
