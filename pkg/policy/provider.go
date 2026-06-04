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
// Schema: sir.policy_request.v0 (the wire schema_version string is unchanged).
//
// The session/integrity signal fields below were ADDED for PDP delegation but
// are additive and omitempty, so the wire schema string deliberately stays v0:
// a strict provider that validates schema_version == "sir.policy_request.v0"
// (the bundled packs advertise exactly that) keeps working and simply ignores
// the new optional keys. Bumping the version string would break those providers.
//
// They are the precondition for PDP delegation's "policy is the whole truth"
// model: an authoritative provider that may bypass the native integrity floors
// (the untrusted→egress / secret-session walls) can only faithfully re-implement
// them in policy if it RECEIVES the signals those walls key on. The coarse Taint
// list alone is insufficient — it collapses live-secret vs. high-water and omits
// the turn-scoped untrusted signal. See docs/research/pdp-provider-delegation.md §2b.
//
// A v1-aware provider detects the new fields by PRESENCE, not by the version
// string. All new fields are omitempty / bool-default-false, so a v0 provider
// reads them as absent/false and behaves exactly as before.
type PolicyRequest struct {
	Action          string   `json:"action"`
	Target          string   `json:"target,omitempty"`
	ResolvedActor   string   `json:"resolved_actor,omitempty"`
	AttributionConf string   `json:"attribution_confidence,omitempty"`
	Taint           []string `json:"taint,omitempty"`
	Enforceability  string   `json:"enforceability,omitempty"`
	Mode            string   `json:"mode,omitempty"`

	// --- v1 session/integrity signals (the floor-reconstruction inputs) ---

	// SessionSecret is the LIVE secret-session flag: a credential is in play this
	// turn. The confidentiality wall keys on this. Distinct from SessionWasSecret.
	SessionSecret bool `json:"session_secret,omitempty"`
	// SessionWasSecret is the monotonic high-water mark: the session has EVER been
	// secret-labeled, even after the live flag cleared on a turn boundary.
	SessionWasSecret bool `json:"session_was_secret,omitempty"`
	// SessionUntrustedRead is the strong, session-scoped integrity signal: a
	// detected untrusted/prompt-injected content read this session. The
	// untrusted→egress exfiltration wall keys on this.
	SessionUntrustedRead bool `json:"session_untrusted_read,omitempty"`
	// SessionUntrustedThisTurn is the weak, turn-scoped integrity signal: any
	// untrusted content (MCP output / fetched web content) ingested this turn.
	// Gates same-turn untrusted→egress; clears next turn. Absent from v0 Taint.
	SessionUntrustedThisTurn bool `json:"session_untrusted_this_turn,omitempty"`
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
