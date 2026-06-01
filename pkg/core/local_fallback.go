package core

import "github.com/somoore/sir/pkg/policy"

// localEvaluate provides a fallback when mister-core is not available.
func localEvaluate(req *Request) (*Response, error) {
	return composeLocalPolicyVerdicts(req, localEvaluateBase(req)), nil
}

func localEvaluateBase(req *Request) *Response {
	if resp := localEvaluatePreflight(req); resp != nil {
		return resp
	}

	effectiveLabels := append([]Label{}, req.Intent.Labels...)
	effectiveLabels = append(effectiveLabels, req.Intent.DerivedLabels...)

	if resp := localEvaluateNetwork(req, effectiveLabels); resp != nil {
		return resp
	}
	if resp := localEvaluateDelegation(req); resp != nil {
		return resp
	}
	if resp := localEvaluateCommandRisk(req); resp != nil {
		return resp
	}
	if deniesFlowToVerb(effectiveLabels, req.Intent.Verb) {
		return denyFlowResponse()
	}

	return &Response{
		Decision: policy.VerdictAllow,
		Reason:   "Allowed by your security policy.",
	}
}

func composeLocalPolicyVerdicts(req *Request, base *Response) *Response {
	if req == nil || base == nil || len(req.PolicyVerdicts) == 0 {
		return base
	}
	if base.Decision == policy.VerdictAllow && isLocalCleanDeveloperWorkflow(req) {
		return base
	}
	out := *base
	for _, pv := range req.PolicyVerdicts {
		if !pv.IsAdvisory {
			continue
		}
		if out.Decision != policy.VerdictAllow {
			continue
		}
		if pv.Verdict != string(policy.VerdictAsk) && pv.Verdict != string(policy.VerdictDeny) {
			continue
		}
		out.Decision = policy.VerdictAsk
		if len(pv.RulesMatched) > 0 {
			provider := pv.Provider
			if provider == "" {
				provider = "provider"
			}
			out.Reason += " [policy:" + provider + " rules:" + joinPolicyRules(pv.RulesMatched) + "]"
		}
	}
	return &out
}

func isLocalCleanDeveloperWorkflow(req *Request) bool {
	if req.Session.SecretSession || req.Session.WasSecret {
		return false
	}
	switch req.Intent.Verb {
	case policy.VerbReadRef,
		policy.VerbStageWrite,
		policy.VerbExecuteDryRun,
		policy.VerbRunTests,
		policy.VerbCommit,
		policy.VerbListFiles,
		policy.VerbSearchCode,
		policy.VerbNetLocal:
		return true
	default:
		return false
	}
}

func joinPolicyRules(rules []string) string {
	if len(rules) == 0 {
		return ""
	}
	out := rules[0]
	for _, r := range rules[1:] {
		out += "," + r
	}
	return out
}
