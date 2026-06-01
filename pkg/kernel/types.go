// Package kernel implements the SIR v2 runtime decision pipeline:
// normalize → correlate → attribute → enforce → label → policy → compose → effects → evidence.
package kernel

import "github.com/somoore/sir/pkg/sdk"

// Protection mode constants.
const (
	ModeObserve    = "observe"
	ModeAdvise     = "advise"
	ModeHookGate   = "hook_gate"
	ModeOSObserved = "os_observed"
	ModeMediated   = "mediated"
	ModeContained  = "contained"
	ModeManaged    = "managed"
)

// Enforceability class constants — shared with the harness scorer.
const (
	ClassEnforces = "enforces"
	ClassDetects  = "detects"
	ClassBlind    = "blind"
)

// Verdict constants.
const (
	VerdictAllow = "allow"
	VerdictAsk   = "ask"
	VerdictDeny  = "deny"
)

// Attribution confidence constants.
const (
	ConfHigh    = "high"
	ConfMedium  = "medium"
	ConfLow     = "low"
	ConfUnknown = "unknown"
)

// EvasionFlags carries harness-level evasion context extracted from case.json.
// These are facts about the environment, not about the signals themselves.
type EvasionFlags struct {
	SpanStripped          bool
	SpanForged            bool
	DetachedChild         bool
	HookMissing           bool
	RequiredEffectUnavail bool
	FailClosed            bool
}

// EnforceabilityInput is the minimal context needed to determine enforceability.
// Used by both the harness scorer and the kernel pipeline — one implementation.
// ProviderCapabilities lists effects the active effect providers can apply
// (e.g. "block", "contain"). Mode alone does not imply enforcement.
type EnforceabilityInput struct {
	Mode                 string
	Signals              []sdk.Signal
	ProviderCapabilities []string
	// ProviderEnforcement records whether the active effect provider's
	// containment is demonstrated/real ("real") or declared-only/stubbed
	// ("simulated", or empty = unproven). A declared block/contain capability
	// only yields ClassEnforces when ProviderEnforcement == "real". This closes
	// the false-enforces soundness gap: a stub provider that merely declares
	// contain:true cannot make the kernel claim it enforces. An enforced_boundary
	// signal is inherently demonstrated and does not require this flag.
	ProviderEnforcement string
	// EnforcedActions optionally scopes a provider's real enforcement to a
	// subset of action types (item 8: action-scoped capability). Empty means the
	// provider enforces every action it is asked about — the backward-compatible
	// default that reproduces pre-item-8 behavior. When non-empty, a contained/
	// managed provider that demonstrably enforces (block/contain + real) still
	// only yields ClassEnforces for an action type in this list; an action it
	// cannot contain (e.g. a network-only sandbox asked about a file write)
	// degrades to ClassDetects — it still observes inside the jail but must not
	// claim to enforce what it cannot. Forward-looking v2 modeling: no shipping
	// provider partially-enforces yet (the devcontainer contains everything).
	EnforcedActions []string
	EvasionFlags
}

// EnforceabilityResult is the output of enforceability analysis.
type EnforceabilityResult struct {
	Class  string // ClassEnforces, ClassDetects, ClassBlind
	Reason string
}

// AttributedAction is the result of correlating and attributing signals.
type AttributedAction struct {
	ActionID       string
	Mode           string
	Signals        []sdk.Signal
	Enforceability EnforceabilityResult
	Attribution    string // ConfHigh, ConfMedium, ConfLow, ConfUnknown
	ActionType     string
	Sensitivity    string
	Labels         []string
	EvasionFlags
}

// PlannedEffect is an effect the kernel intends to apply.
type PlannedEffect struct {
	Type       string `json:"type"`
	Required   bool   `json:"required"`
	FailClosed bool   `json:"fail_closed"`
}

// DecisionClass constants — CORRELATION spec block-and-wait decision model.
// The class refines the verdict with enforcement timing semantics.
const (
	DecisionClassProceedAndReconcile = "proceed_and_reconcile" // allow + post-hoc record
	DecisionClassBlockAndWait        = "block_and_wait"        // ask — pre-exec gate, awaiting user
	DecisionClassDenyNow             = "deny_now"              // deny — immediate block
	DecisionClassRecordPostHoc       = "record_post_hoc"       // detects only, recorded after
)

// Decision is the kernel's final output for an attributed action.
type Decision struct {
	DecisionID             string                   `json:"decision_id"`
	Timestamp              string                   `json:"timestamp"`
	Mode                   string                   `json:"mode"`
	Verdict                string                   `json:"verdict"`
	DecisionClass          string                   `json:"decision_class"` // CORRELATION block-and-wait model
	PolicyRules            []string                 `json:"policy_rules,omitempty"`
	Effects                []PlannedEffect          `json:"effects,omitempty"`
	Enforceability         string                   `json:"enforceability"`
	Attribution            string                   `json:"attribution"`
	ActionType             string                   `json:"action_type"`
	Sensitivity            string                   `json:"sensitivity"`
	BaseVerdict            string                   `json:"base_verdict,omitempty"`
	DeveloperWorkflowFloor string                   `json:"developer_workflow_floor,omitempty"`
	ProviderPolicyEvidence []ProviderPolicyEvidence `json:"provider_policy_evidence,omitempty"`
	ProviderEvidence       []ProviderEvidence       `json:"provider_evidence,omitempty"`
	Explanation            string                   `json:"explanation"`
}

// LedgerEntry wraps a decision for the append-only ledger.
type LedgerEntry struct {
	EntryID  string   `json:"entry_id"`
	CaseID   string   `json:"case_id,omitempty"`
	Decision Decision `json:"decision"`
	PrevHash string   `json:"prev_hash"`
	Hash     string   `json:"hash"`
}

// EvaluationInput is the complete, explicit input to the pure Evaluate()
// function. All stateful context (prior taint, provider capabilities) is
// passed in — the kernel reads nothing from global state.
//
// This is also the wire format sent to sir-core-eval (Rust).
type EvaluationInput struct {
	CaseID               string       `json:"case_id"`
	Mode                 string       `json:"mode"`
	Signals              []sdk.Signal `json:"signals"`
	Evasion              EvasionFlags `json:"evasion_flags"`
	PriorTaint           []string     `json:"prior_taint"`           // taint from previous actions in session
	ProviderCapabilities []string     `json:"provider_capabilities"` // effects available: "block", "contain", etc.
	// ResolvedActorKind is set by the stateful orchestrator when it has resolved
	// a shell/unknown actor to an agent identity from session evidence (e.g.
	// PID+start-time matching an active agent session). Empty means: use the
	// actor_kind from the signal's actor_claim directly.
	// Pattern mirrors PriorTaint: stateful context threaded in explicitly so
	// Evaluate() stays pure and both Go and Rust produce identical results.
	ResolvedActorKind string `json:"resolved_actor_kind,omitempty"`
	// PolicyVerdicts carries advisory verdicts from registered policy providers
	// (OPA, Cedar, custom packs). The orchestrator collects them before calling
	// Evaluate(); the kernel composes them under the native floors and the
	// developer-workflow floor. Empty reproduces the no-provider baseline
	// exactly — both Go and Rust must agree on the composed result.
	PolicyVerdicts []PolicyVerdict `json:"policy_verdicts,omitempty"`
	// ProviderEnforcement is "real" when the active effect provider demonstrably
	// enforces containment, or "simulated"/"" when it only declares the capability
	// (a stub). Gates whether a declared block/contain capability counts toward
	// ClassEnforces — see EnforceabilityInput.ProviderEnforcement.
	ProviderEnforcement string `json:"provider_enforcement,omitempty"`
	// ProviderEnforcedActions optionally scopes the active provider's real
	// enforcement to a subset of action types (item 8). Empty = enforces every
	// action (backward-compatible default). See EnforceabilityInput.EnforcedActions.
	ProviderEnforcedActions []string `json:"provider_enforced_actions,omitempty"`
}

// PolicyVerdict is the kernel-local form of an advisory policy provider verdict.
// It mirrors the sir.policy_verdict.v0 wire shape and policy.PolicyVerdict so the
// kernel stays self-contained and pure (no import of pkg/policy or pkg/provider).
type PolicyVerdict struct {
	Provider     string   `json:"provider"`
	Verdict      string   `json:"verdict"` // allow | ask | deny
	RulesMatched []string `json:"rules_matched,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	IsAdvisory   bool     `json:"is_advisory"`
}

// ProviderPolicyEvidence is the ledger/explanation form of an advisory policy
// verdict. It is intentionally separate from Decision.PolicyRules so native SIR
// floors remain distinguishable from provider recommendations.
type ProviderPolicyEvidence struct {
	Provider     string   `json:"provider"`
	Verdict      string   `json:"verdict"`
	RulesMatched []string `json:"rules_matched,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Used         bool     `json:"used"`
}

// ProviderEvidence records a provider invocation that did not produce usable
// policy evidence. Fail-open provider failures are still visible in the ledger.
type ProviderEvidence struct {
	Provider string `json:"provider"`
	Kind     string `json:"kind"`
	Status   string `json:"status"` // unavailable | timeout | invalid_output | disabled | failed
	Reason   string `json:"reason,omitempty"`
	Behavior string `json:"behavior,omitempty"`
}

// SpoofingRisk constants — mirrors sir.attribution.v0.spoofing_risk enum.
const (
	SpoofingRiskNone   = "none"   // enforced boundary verified (hardware/OS enforced)
	SpoofingRiskLow    = "low"    // span present but unverified (hook fired, span not authenticated)
	SpoofingRiskMedium = "medium" // span absent but runtime fallback present
	SpoofingRiskHigh   = "high"   // span forged or span absent with no fallback (blind)
)

// EvaluationOutput is the pure, deterministic output of Evaluate().
// These fields are what both Go and Rust must agree on (parity fields).
// decision_id and timestamp are NOT here — Go stamps those after evaluation.
type EvaluationOutput struct {
	Verdict        string `json:"verdict"`
	DecisionClass  string `json:"decision_class"`
	Enforceability string `json:"enforceability"`
	Attribution    string `json:"attribution"`
	// SpoofingRisk is derived from evasion flags and signal set.
	// Matches sir.attribution.v0 spoofing_risk enum: none/low/medium/high.
	SpoofingRisk string          `json:"spoofing_risk"`
	PolicyRules  []string        `json:"policy_rules"`
	Effects      []PlannedEffect `json:"effects"`
	ActionType   string          `json:"action_type"`
	Sensitivity  string          `json:"sensitivity"`
	NewTaint     []string        `json:"new_taint"` // taint this action adds to session
	// ProviderRules lists the advisory provider verdicts that contributed to the
	// final decision, kept SEPARATE from native PolicyRules so `sir why` and the
	// ledger can attribute a composed ask to the provider that triggered it
	// without collapsing it into native floor rules. Empty when no provider
	// verdict changed the outcome. NOT a parity field — Go and Rust need not agree
	// on it (it is explanation metadata layered over the parity decision).
	ProviderRules []string `json:"provider_rules,omitempty"`
}
