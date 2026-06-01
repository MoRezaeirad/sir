package core

import "github.com/somoore/sir/pkg/policy"

func nonNilLabels(in []Label) []Label {
	if in == nil {
		return []Label{}
	}
	return in
}

func nonNilPolicyVerdicts(in []policy.PolicyVerdict) []policy.PolicyVerdict {
	if in == nil {
		return []policy.PolicyVerdict{}
	}
	return in
}
