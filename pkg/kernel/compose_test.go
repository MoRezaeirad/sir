package kernel

import (
	"testing"

	"github.com/somoore/sir/pkg/sdk"
)

// devSignal builds a single declared_intent/pre_exec signal for composition tests.
// Mirrors the Rust sir-core dev_signal helper so the two kernels stay in parity.
func devSignal(actionType, sensitivity, actor string) []sdk.Signal {
	return []sdk.Signal{
		{
			SchemaVersion: sdk.SchemaSignalV0,
			SignalID:      "sig-compose-test",
			Source: sdk.Source{
				Kind:        "claude_hook",
				Reliability: sdk.ReliabilityDeclaredIntent,
				Timing:      sdk.TimingPreExec,
			},
			ActorClaim: &sdk.ActorClaim{Kind: actor, Name: actor},
			ActionClaim: map[string]any{
				"type":   actionType,
				"target": map[string]any{"display": actionType, "sensitivity": sensitivity},
			},
		},
	}
}

func advisoryVerdict(verdict string, rules ...string) PolicyVerdict {
	return PolicyVerdict{
		Provider:     "opa-bridge",
		Verdict:      verdict,
		RulesMatched: rules,
		IsAdvisory:   true,
	}
}

// TestCompose_CleanCommitFloorSuppressesAdvisoryDeny: the developer-workflow floor
// protects a clean human commit from an advisory deny. (item 1 + item 6)
func TestCompose_CleanCommitFloorSuppressesAdvisoryDeny(t *testing.T) {
	out := Evaluate(EvaluationInput{
		Mode:           ModeHookGate,
		Signals:        devSignal("vcs_commit", "low", "human_developer"),
		PolicyVerdicts: []PolicyVerdict{advisoryVerdict(VerdictDeny, "forbid-all-commits")},
	})
	if out.Verdict != VerdictAllow {
		t.Errorf("clean commit must stay allow despite OPA deny, got %s", out.Verdict)
	}
	if len(out.ProviderRules) != 0 {
		t.Errorf("floor returns before adding provider rule, got %v", out.ProviderRules)
	}
}

// TestCompose_AgentPushAdvisoryAskEscalates: push is not floored, so an advisory
// ask escalates allow→ask with provider attribution. (item 1 — composition proven)
func TestCompose_AgentPushAdvisoryAskEscalates(t *testing.T) {
	out := Evaluate(EvaluationInput{
		Mode:           ModeHookGate,
		Signals:        devSignal("vcs_push", "low", "ai_coding_agent"),
		PolicyVerdicts: []PolicyVerdict{advisoryVerdict(VerdictAsk, "agent-push-review")},
	})
	if out.Verdict != VerdictAsk {
		t.Errorf("push is not floored; advisory ask must escalate, got %s", out.Verdict)
	}
	want := "policy:opa-bridge:agent-push-review"
	found := false
	for _, r := range out.PolicyRules {
		if r == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected provider rule %q in %v", want, out.PolicyRules)
	}
}

// TestCompose_AdvisoryCannotWidenNativeDeny: no advisory verdict can change a
// native deny. (item 7 — non-bypassable native floors)
func TestCompose_AdvisoryCannotWidenNativeDeny(t *testing.T) {
	for _, adv := range []string{VerdictAsk, VerdictDeny, VerdictAllow} {
		out := Evaluate(EvaluationInput{
			Mode:           ModeHookGate,
			Signals:        devSignal("vcs_commit", "credential", "ai_coding_agent"),
			PolicyVerdicts: []PolicyVerdict{advisoryVerdict(adv, "x")},
		})
		if out.Verdict != VerdictDeny {
			t.Errorf("advisory %q must not change a native deny, got %s", adv, out.Verdict)
		}
	}
}

// TestCompose_NoVerdictsIsNoop: absence of verdicts reproduces the pre-provider
// baseline exactly. (item 1 — parity safety)
func TestCompose_NoVerdictsIsNoop(t *testing.T) {
	out := Evaluate(EvaluationInput{
		Mode:    ModeHookGate,
		Signals: devSignal("vcs_push", "low", "ai_coding_agent"),
	})
	if out.Verdict != VerdictAllow {
		t.Errorf("clean agent push with no verdicts = allow baseline, got %s", out.Verdict)
	}
}

// TestCompose_NonAdvisoryVerdictIgnored: is_advisory=false verdicts are ignored.
func TestCompose_NonAdvisoryVerdictIgnored(t *testing.T) {
	pv := advisoryVerdict(VerdictAsk, "x")
	pv.IsAdvisory = false
	out := Evaluate(EvaluationInput{
		Mode:           ModeHookGate,
		Signals:        devSignal("vcs_push", "low", "ai_coding_agent"),
		PolicyVerdicts: []PolicyVerdict{pv},
	})
	if out.Verdict != VerdictAllow {
		t.Errorf("non-advisory verdict must be ignored, got %s", out.Verdict)
	}
}
