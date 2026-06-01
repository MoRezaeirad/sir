package ledger

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestProviderRecordsJSONRoundTrip verifies that policy-provider verdicts and
// fail-open failures survive a JSON marshal/unmarshal round trip on a ledger
// Entry. These fields are advisory policy metadata surfaced for the ledger and
// `sir why`; they must serialize cleanly and never carry raw secrets.
func TestProviderRecordsJSONRoundTrip(t *testing.T) {
	in := Entry{
		Decision:    "ask",
		BaseVerdict: "allow",
		Reason:      "native floor",
		ProviderVerdicts: []ProviderVerdictRecord{
			{
				Provider:     "OPA",
				Verdict:      "ask",
				RulesMatched: []string{"was-secret-push-origin", "deny-prod-egress"},
				Reason:       "session previously held secret data",
				Used:         true,
			},
			{
				Provider: "cedar",
				Verdict:  "allow",
			},
		},
		ProviderFailures: []ProviderFailureRecord{
			{Provider: "falco", Kind: "policy_provider", Status: "timeout", Reason: "policy provider falco: timed out after 200ms", Behavior: "ignored; native policy used", TimedOut: true},
			{Provider: "custom-pack", Kind: "policy_provider", Status: "unavailable", Reason: "missing entrypoint", Behavior: "ignored; native policy used"},
		},
	}

	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}

	var out Entry
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal entry: %v", err)
	}

	if out.BaseVerdict != "allow" {
		t.Errorf("BaseVerdict round-trip: got %q, want %q", out.BaseVerdict, "allow")
	}

	// BaseVerdict is advisory post-decision metadata (like ProviderVerdicts) and
	// must never enter the hash chain — otherwise replaying old entries that
	// predate the field would break verification.
	plain := &Entry{Index: 1, Decision: "ask", Reason: "x", HashVersion: currentHashVersion}
	withBase := &Entry{Index: 1, Decision: "ask", Reason: "x", HashVersion: currentHashVersion, BaseVerdict: "allow"}
	if computeHash(plain) != computeHash(withBase) {
		t.Errorf("BaseVerdict must not affect the entry hash")
	}
	if len(out.ProviderVerdicts) != 2 {
		t.Fatalf("ProviderVerdicts: got %d, want 2", len(out.ProviderVerdicts))
	}
	v0 := out.ProviderVerdicts[0]
	if v0.Provider != "OPA" || v0.Verdict != "ask" || v0.Reason != "session previously held secret data" {
		t.Errorf("verdict[0] round-trip mismatch: %+v", v0)
	}
	if !v0.Used {
		t.Errorf("verdict[0] Used round-trip mismatch: %+v", v0)
	}
	if len(v0.RulesMatched) != 2 || v0.RulesMatched[0] != "was-secret-push-origin" {
		t.Errorf("verdict[0] RulesMatched round-trip mismatch: %+v", v0.RulesMatched)
	}

	if len(out.ProviderFailures) != 2 {
		t.Fatalf("ProviderFailures: got %d, want 2", len(out.ProviderFailures))
	}
	f0 := out.ProviderFailures[0]
	if f0.Provider != "falco" || f0.Kind != "policy_provider" || f0.Status != "timeout" || f0.Behavior == "" || !f0.TimedOut {
		t.Errorf("failure[0] round-trip mismatch: %+v", f0)
	}
	if out.ProviderFailures[1].TimedOut {
		t.Errorf("failure[1] TimedOut should be false: %+v", out.ProviderFailures[1])
	}
}

// TestProviderRecordsOmittedWhenEmpty confirms the provider fields are omitted
// from serialized JSON when absent, so normal-coding entries stay compact.
func TestProviderRecordsOmittedWhenEmpty(t *testing.T) {
	data, err := json.Marshal(Entry{Decision: "allow"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)
	for _, key := range []string{"provider_verdicts", "provider_failures"} {
		if strings.Contains(s, key) {
			t.Errorf("expected %q to be omitted from empty entry JSON: %s", key, s)
		}
	}
}
