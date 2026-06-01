package kernel

import (
	"strings"
	"testing"
)

func TestBuildProviderPolicyEvidenceMarksUsedOnlyForAdvisoryEscalation(t *testing.T) {
	verdicts := []PolicyVerdict{
		{Provider: "opa-bridge", Verdict: VerdictDeny, RulesMatched: []string{"deny-clean-push"}, IsAdvisory: true},
		{Provider: "bad-provider", Verdict: VerdictDeny, RulesMatched: []string{"authoritative"}, IsAdvisory: false},
	}

	evidence := BuildProviderPolicyEvidence(verdicts, VerdictAsk, VerdictAllow)
	if len(evidence) != 2 {
		t.Fatalf("evidence length = %d, want 2", len(evidence))
	}
	if !evidence[0].Used {
		t.Fatalf("advisory deny that escalated allow->ask should be used: %+v", evidence[0])
	}
	if evidence[1].Used {
		t.Fatalf("non-advisory verdict must not be marked used: %+v", evidence[1])
	}
}

func TestExplainSeparatesNativeProviderAndFailureEvidence(t *testing.T) {
	out := Explain(LedgerEntry{
		CaseID: "provider-deny-vcs-push-clean",
		Decision: Decision{
			DecisionID:     "dec-test",
			Timestamp:      "2026-06-01T00:00:00Z",
			Mode:           ModeHookGate,
			Verdict:        VerdictAsk,
			DecisionClass:  DecisionClassBlockAndWait,
			PolicyRules:    []string{"deny-secret-to-egress", "policy:opa-bridge:deny-clean-push"},
			Effects:        []PlannedEffect{{Type: "prompt"}},
			Enforceability: ClassEnforces,
			Attribution:    ConfMedium,
			ActionType:     "vcs_push",
			Sensitivity:    "low",
			ProviderPolicyEvidence: []ProviderPolicyEvidence{
				{Provider: "opa-bridge", Verdict: VerdictDeny, RulesMatched: []string{"deny-clean-push"}, Used: true},
			},
			ProviderEvidence: []ProviderEvidence{
				{Provider: "opa-bridge", Kind: "policy_provider", Status: "timeout", Behavior: "ignored; native policy used"},
			},
		},
	})

	for _, want := range []string{
		"Native SIR policy:\n  deny-secret-to-egress",
		"Policy provider verdicts:\n  opa-bridge: deny",
		"    rule: deny-clean-push",
		"    used: yes",
		"Provider failures:\n  opa-bridge: timeout",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("Explain output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\n  policy:opa-bridge:deny-clean-push\n") {
		t.Fatalf("provider rule tag should not render as native policy:\n%s", out)
	}
}
