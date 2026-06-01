// Package sdk provides the wire types and provider interfaces for the SIR
// provider protocol (v0). All enum constants match the JSON schema definitions
// in schemas/ exactly — changing a constant here is a breaking protocol change.
package sdk

// Schema version strings.
const (
	SchemaSignalV0      = "sir.signal.v0"
	SchemaCapabilitiesV0 = "sir.capabilities.v0"
	SchemaEffectReqV0   = "sir.effect_request.v0"
	SchemaEffectResV0   = "sir.effect_result.v0"
	SchemaProviderV0    = "sir.provider.v0"
)

// Reliability values for Source.Reliability — matches sir.signal.v0 enum.
const (
	ReliabilityDeclaredIntent   = "declared_intent"
	ReliabilityMediatedAction   = "mediated_action"
	ReliabilityObservedRuntime  = "observed_runtime"
	ReliabilityEnforcedBoundary = "enforced_boundary"
	ReliabilityAdvisorySignal   = "advisory_signal"
	ReliabilityUserDecision     = "user_decision"
	ReliabilityAdminPolicy      = "admin_policy"
)

// Timing values for Source.Timing — matches sir.signal.v0 enum.
const (
	TimingPreExec    = "pre_exec"
	TimingDuringExec = "during_exec"
	TimingPostExec   = "post_exec"
	TimingUnknown    = "unknown"
)

// EffectType values — matches sir.effect_request.v0 enum.
const (
	EffectRecord           = "record"
	EffectNudge            = "nudge"
	EffectRedact           = "redact"
	EffectPrompt           = "prompt"
	EffectBlock            = "block"
	EffectContain          = "contain"
	EffectExport           = "export"
	EffectKillProcess      = "kill_process"
	EffectRequestException = "request_exception"
)

// EffectStatus values — matches sir.effect_result.v0 enum.
const (
	EffectApplied      = "applied"
	EffectUnavailable  = "unavailable"
	EffectFailed       = "failed"
	EffectNotSupported = "not_supported"
)

// ProviderKind values — matches sir.provider.v0 and sir.capabilities.v0 enums.
const (
	KindSignalProvider   = "signal_provider"
	KindEffectProvider   = "effect_provider"
	KindPolicyProvider   = "policy_provider"
	KindAdvisoryProvider = "advisory_provider"
	KindExportProvider   = "export_provider"
)

// Source describes where a signal came from and how reliable it is.
type Source struct {
	Kind            string `json:"kind"`
	Reliability     string `json:"reliability"`
	Timing          string `json:"timing"`
	Provider        string `json:"provider,omitempty"`
	ProviderVersion string `json:"provider_version,omitempty"`
}

// Session identifies the agent session context for correlation.
type Session struct {
	TraceID   string `json:"trace_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	TurnID    string `json:"turn_id,omitempty"`
	SpanID    string `json:"span_id,omitempty"`
}

// ActorClaim is the claimed identity of the actor (AI agent, user, system).
type ActorClaim struct {
	Kind        string   `json:"kind,omitempty"`
	Name        string   `json:"name,omitempty"`
	PID         int      `json:"pid,omitempty"`
	ProcessTree []string `json:"process_tree,omitempty"`
}

// Signal is sir.signal.v0 — the canonical unit emitted by a signal_provider.
type Signal struct {
	SchemaVersion string         `json:"schema_version"`
	SignalID      string         `json:"signal_id"`
	SignalTime    string         `json:"signal_time"`
	Source        Source         `json:"source"`
	Session       *Session       `json:"session,omitempty"`
	ActorClaim    *ActorClaim    `json:"actor_claim,omitempty"`
	ActionClaim   map[string]any `json:"action_claim"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// EffectRequest is sir.effect_request.v0 — SIR asks a provider to apply an effect.
type EffectRequest struct {
	SchemaVersion string         `json:"schema_version"`
	EffectID      string         `json:"effect_id"`
	Type          string         `json:"type"`
	Required      bool           `json:"required"`
	FailClosed    bool           `json:"fail_closed"`
	Target        map[string]any `json:"target,omitempty"`
}

// EffectResult is sir.effect_result.v0 — a provider's response to an effect request.
type EffectResult struct {
	SchemaVersion string         `json:"schema_version"`
	EffectID      string         `json:"effect_id"`
	Status        string         `json:"status"`
	Reason        string         `json:"reason,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
}

// CapabilitiesResponse is sir.capabilities.v0 — a provider's response to {"op":"capabilities"}.
type CapabilitiesResponse struct {
	SchemaVersion string         `json:"schema_version"`
	Provider      string         `json:"provider"`
	Kind          string         `json:"kind"`
	Capabilities  map[string]any `json:"capabilities"`
}

// ProviderManifest is sir.provider.v0 — the provider's self-declaration.
type ProviderManifest struct {
	SchemaVersion string         `json:"schema_version"`
	Name          string         `json:"name"`
	Kind          string         `json:"kind"`
	Version       string         `json:"version"`
	Protocol      string         `json:"protocol"`
	Entrypoint    string         `json:"entrypoint"`
	Platforms     []string       `json:"platforms,omitempty"`
	Capabilities  map[string]any `json:"capabilities"`
	// Enforcement is the honesty signal: "simulated" (default when absent) or
	// "real". Effect providers declaring contain/block capability should set
	// "real" only when they actually apply OS-level containment.
	Enforcement string   `json:"enforcement,omitempty"`
	Fixtures    []string `json:"fixtures,omitempty"`
}

// NewEffectResult constructs an EffectResult with the schema version set.
func NewEffectResult(effectID, status, reason string) EffectResult {
	return EffectResult{
		SchemaVersion: SchemaEffectResV0,
		EffectID:      effectID,
		Status:        status,
		Reason:        reason,
	}
}

// NewCapabilitiesResponse constructs a CapabilitiesResponse with the schema version set.
func NewCapabilitiesResponse(provider, kind string, caps map[string]any) CapabilitiesResponse {
	return CapabilitiesResponse{
		SchemaVersion: SchemaCapabilitiesV0,
		Provider:      provider,
		Kind:          kind,
		Capabilities:  caps,
	}
}
