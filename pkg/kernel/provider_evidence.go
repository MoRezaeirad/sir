package kernel

import "fmt"

// NativePolicyRules returns only SIR-native policy rule IDs, excluding provider
// attribution tags from EvaluationOutput.PolicyRules values.
func NativePolicyRules(rules []string) []string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		if len(rule) >= len("policy:") && rule[:len("policy:")] == "policy:" {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// BuildProviderPolicyEvidence converts advisory policy verdicts into explicit
// ledger/explanation evidence. A verdict is marked Used when provider
// composition changed a native allow into ask.
func BuildProviderPolicyEvidence(verdicts []PolicyVerdict, finalVerdict, baseVerdict string) []ProviderPolicyEvidence {
	if len(verdicts) == 0 {
		return nil
	}
	out := make([]ProviderPolicyEvidence, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, ProviderPolicyEvidence{
			Provider:     v.Provider,
			Verdict:      v.Verdict,
			RulesMatched: v.RulesMatched,
			Reason:       v.Reason,
			Used:         providerVerdictWasUsed(v, finalVerdict, baseVerdict),
		})
	}
	return out
}

func providerVerdictWasUsed(v PolicyVerdict, finalVerdict, baseVerdict string) bool {
	if !v.IsAdvisory {
		return false
	}
	if baseVerdict != VerdictAllow || finalVerdict != VerdictAsk {
		return false
	}
	return v.Verdict == VerdictAsk || v.Verdict == VerdictDeny
}

// DeveloperWorkflowFloorEvidence describes whether the clean developer workflow
// floor suppressed advisory provider escalation for this decision.
func DeveloperWorkflowFloorEvidence(priorTaint []string, actionType string, verdicts []PolicyVerdict, baseVerdict, finalVerdict string) string {
	if len(verdicts) == 0 {
		return ""
	}
	if baseVerdict == VerdictAllow && finalVerdict == VerdictAllow && isCleanDeveloperWorkflow(priorTaint, actionType) {
		return fmt.Sprintf("clean %s protected from advisory escalation", actionType)
	}
	if baseVerdict == VerdictDeny {
		return "not applicable; native SIR deny already applies"
	}
	return "not applicable"
}
