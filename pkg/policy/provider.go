package policy

import "context"

// PolicyVerdict is the structured verdict emitted by a PolicyProvider.
// Schema: sir.policy_verdict.v0
//
// The verdict is advisory input to the Rust decision composer — policy
// providers do not directly enforce. Rust sir-core composes all verdicts
// (native floors, managed policy, advisory providers) into the final decision.
type PolicyVerdict struct {
	Provider     string   `json:"provider"`
	Verdict      string   `json:"verdict"` // "allow", "ask", or "deny"
	RulesMatched []string `json:"rules_matched,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	// IsAdvisory is always true — policy providers supply evidence, not final decisions.
	// Matches the sir.policy_verdict.v0 schema. Kept explicit so providers that
	// set it to false are rejected at parse time by the Rust oracle.
	IsAdvisory bool `json:"is_advisory"`
}

// PolicyRequest is the evaluation context passed to a PolicyProvider.
// Schema: sir.policy_request.v0
type PolicyRequest struct {
	Action              string   `json:"action"`
	Target              string   `json:"target,omitempty"`
	ResolvedActor       string   `json:"resolved_actor,omitempty"`
	AttributionConf     string   `json:"attribution_confidence,omitempty"`
	Taint               []string `json:"taint,omitempty"`
	Enforceability      string   `json:"enforceability,omitempty"`
	Mode                string   `json:"mode,omitempty"`
}

// PolicyProvider evaluates policy for a given request and returns zero or more
// verdicts. A provider that encounters an error should return (nil, nil) —
// missing verdicts are never session-fatal; Rust falls back to native floors.
//
// Policy providers must not directly enforce (block/allow). They supply
// evidence. Rust sir-core is the final decision authority.
type PolicyProvider interface {
	Name() string
	Evaluate(ctx context.Context, req PolicyRequest) ([]PolicyVerdict, error)
}

// NativePolicy is the default no-op provider. It returns no verdicts, deferring
// all decisions to the built-in Rust oracle. Future policy providers (OPA,
// Cedar, Falco) register alongside NativePolicy; Rust composes all verdicts.
type NativePolicy struct{}

func (NativePolicy) Name() string { return "native" }
func (NativePolicy) Evaluate(_ context.Context, _ PolicyRequest) ([]PolicyVerdict, error) {
	return nil, nil
}
