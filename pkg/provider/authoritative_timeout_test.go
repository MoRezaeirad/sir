package provider

import (
	"testing"
	"time"
)

// The authoritative policy budget must be LARGER than the advisory budget: an
// authoritative provider's verdict IS the decision and a timeout fails closed,
// so too tight a budget re-introduces the friction PDP exists to reduce. It must
// also stay CAPPED (bounded) so a hung provider becomes a fast fail-closed ask,
// not a hang. Regression guard for that tradeoff.
func TestAuthoritativeTimeout_LargerThanAdvisoryButCapped(t *testing.T) {
	if authoritativePolicyTimeout <= policyTimeout {
		t.Fatalf("authoritative budget (%v) must exceed advisory budget (%v) to avoid friction",
			authoritativePolicyTimeout, policyTimeout)
	}
	// Capped: a hung warm provider must fail closed fast, not hang the hook.
	if authoritativePolicyTimeout > 3*time.Second {
		t.Fatalf("authoritative budget (%v) is too large — a hung provider must fail closed fast",
			authoritativePolicyTimeout)
	}
}
