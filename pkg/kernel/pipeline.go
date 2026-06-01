package kernel

import (
	"strings"

	"github.com/somoore/sir/pkg/sdk"
)

// AnalyzeEnforceability is the canonical enforceability function shared by
// the harness scorer (cmd/sir/harness.go) and the kernel pipeline. One
// implementation guarantees they cannot diverge.
func AnalyzeEnforceability(in EnforceabilityInput) EnforceabilityResult {
	if in.RequiredEffectUnavail {
		if in.FailClosed {
			return EnforceabilityResult{ClassEnforces, "required effect unavailable: fail_closed=true denies"}
		}
		return EnforceabilityResult{ClassDetects, "required effect unavailable: recorded but not blocked"}
	}

	switch in.Mode {
	case ModeContained, ModeManaged:
		// Mode alone does not imply enforcement. An enforced_boundary signal is
		// inherent proof (hardware/OS), so it always yields enforces.
		if hasSignal(in.Signals, sdk.ReliabilityEnforcedBoundary, "") {
			return EnforceabilityResult{ClassEnforces, "enforced-boundary signal proves containment"}
		}
		// A declared block/contain capability only yields enforces when the
		// provider's enforcement is DEMONSTRATED (real), not merely declared. A
		// stub provider (simulated/unproven) classifies at most detects — closing
		// the false-enforces soundness gap.
		if providerCan(in.ProviderCapabilities, "block") || providerCan(in.ProviderCapabilities, "contain") {
			if in.ProviderEnforcement == "real" {
				// Action-scoped capability (item 8): a provider may demonstrably
				// enforce only some action types. If it scopes its enforcement
				// and the current action is not covered, it cannot claim to
				// enforce THIS action — degrade to detects (it still observes
				// inside the jail). Empty EnforcedActions = enforces everything
				// (backward-compatible default). Deliberately NOT applied to the
				// enforced_boundary branch above: that signal is per-action proof
				// the action hit a real boundary, not a capability declaration.
				if !actionEnforced(in.EnforcedActions, PrimaryActionType(in.Signals)) {
					return EnforceabilityResult{ClassDetects, "provider enforces a different action set — this action type is observed, not contained"}
				}
				return EnforceabilityResult{ClassEnforces, "provider-backed mode with demonstrated (real) enforcement"}
			}
			return EnforceabilityResult{ClassDetects, "provider declares block/contain but enforcement is simulated/unproven — detects only"}
		}
		return EnforceabilityResult{ClassDetects, "contained/managed mode but no capable provider available"}

	case ModeMediated:
		if in.SpanStripped || in.DetachedChild {
			if hasSignal(in.Signals, sdk.ReliabilityObservedRuntime, "") {
				return EnforceabilityResult{ClassDetects, "mediated span severed; runtime signal caught residue"}
			}
			return EnforceabilityResult{ClassBlind, "mediated span severed; no fallback"}
		}
		if hasSignal(in.Signals, "", sdk.TimingPreExec) {
			// Demonstrated-mediation gate (item 9), parallel to the contained
			// real-enforcement gate: a pre-exec signal alone is a DECLARED
			// control point, not proof SIR actually launches/proxies the
			// process. Mediated mode claims enforces only when the mediation is
			// demonstrated — provider_enforcement=="real" (an active runner like
			// the macOS sandbox-exec provider that genuinely wraps execution,
			// backed by capture proof) or an enforced_boundary signal (inherent
			// proof the mediation boundary held). A declared-only pre-exec signal
			// degrades to detects — it records but cannot prove it prevented.
			// Closes the same false-enforces gap that was closed for contained.
			if in.ProviderEnforcement == "real" || hasSignal(in.Signals, sdk.ReliabilityEnforcedBoundary, "") {
				return EnforceabilityResult{ClassEnforces, "mediated pre-exec control with demonstrated mediation"}
			}
			return EnforceabilityResult{ClassDetects, "mediated pre-exec signal declared but mediation unproven — detects only"}
		}
		return EnforceabilityResult{ClassDetects, "no pre-exec signal"}

	case ModeHookGate:
		if in.HookMissing || in.SpanStripped || in.SpanForged || in.DetachedChild {
			if hasSignal(in.Signals, sdk.ReliabilityObservedRuntime, "") {
				return EnforceabilityResult{ClassDetects, "hook/span unreliable; fallback observed"}
			}
			return EnforceabilityResult{ClassBlind, "hook/span unreliable; no fallback"}
		}
		if hasSignal(in.Signals, sdk.ReliabilityDeclaredIntent, sdk.TimingPreExec) {
			return EnforceabilityResult{ClassEnforces, "cooperative pre-exec hook can gate"}
		}
		return EnforceabilityResult{ClassDetects, "no cooperative pre-exec hook"}

	case ModeOSObserved:
		if hasSignal(in.Signals, sdk.ReliabilityObservedRuntime, "") {
			return EnforceabilityResult{ClassDetects, "post-hoc or partial runtime observation"}
		}
		return EnforceabilityResult{ClassBlind, "no runtime signal"}

	case ModeObserve, ModeAdvise:
		if len(in.Signals) > 0 {
			return EnforceabilityResult{ClassDetects, in.Mode + " mode records/explains but does not enforce"}
		}
		return EnforceabilityResult{ClassBlind, "no signals"}
	}

	return EnforceabilityResult{ClassBlind, "unknown mode"}
}

// providerCan returns true if the capability list includes the given effect.
func providerCan(caps []string, effect string) bool {
	for _, c := range caps {
		if c == effect {
			return true
		}
	}
	return false
}

// actionEnforced reports whether a provider that scopes its enforcement to
// enforcedActions covers actionType. Empty enforcedActions means "enforces
// everything" (the backward-compatible default). An "unknown" action type is
// never in a non-empty list, so it correctly degrades to detects.
func actionEnforced(enforcedActions []string, actionType string) bool {
	if len(enforcedActions) == 0 {
		return true
	}
	for _, a := range enforcedActions {
		if a == actionType {
			return true
		}
	}
	return false
}

// AttributionConfidence returns the highest attribution confidence across signals.
func AttributionConfidence(signals []sdk.Signal) string {
	best := ConfUnknown
	for _, s := range signals {
		switch s.Source.Reliability {
		case sdk.ReliabilityEnforcedBoundary:
			return ConfHigh
		case sdk.ReliabilityMediatedAction, sdk.ReliabilityDeclaredIntent:
			if best == ConfUnknown || best == ConfLow {
				best = ConfMedium
			}
		case sdk.ReliabilityObservedRuntime:
			if best == ConfUnknown {
				best = ConfLow
			}
		}
	}
	return best
}

// NormalizeSignals drops signals with missing required fields or wrong schema version.
func NormalizeSignals(signals []sdk.Signal) []sdk.Signal {
	var out []sdk.Signal
	for _, s := range signals {
		if s.SchemaVersion != sdk.SchemaSignalV0 {
			continue
		}
		if s.SignalID == "" || s.Source.Kind == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// PrimaryActionType extracts the action type from the first signal with one.
func PrimaryActionType(signals []sdk.Signal) string {
	for _, s := range signals {
		if t, ok := s.ActionClaim["type"].(string); ok && t != "" {
			return t
		}
	}
	return "unknown"
}

// PrimarySensitivity extracts the highest sensitivity across signal targets.
// Never stores actual secret values — only the sensitivity label.
func PrimarySensitivity(signals []sdk.Signal) string {
	order := map[string]int{"credential": 3, "external_network": 2, "high": 2, "medium": 1, "low": 0}
	best := ""
	bestRank := -1
	for _, s := range signals {
		target, _ := s.ActionClaim["target"].(map[string]any)
		if target == nil {
			continue
		}
		sens, _ := target["sensitivity"].(string)
		if rank, ok := order[sens]; ok && rank > bestRank {
			best = sens
			bestRank = rank
		}
	}
	if best == "" {
		return "low"
	}
	return best
}

// ComputeSpoofingRisk derives the spoofing risk from evasion flags and signal
// reliability. Mirrors sir.attribution.v0 spoofing_risk enum:
//
//	none   — enforced boundary verified (hardware/OS guarantee)
//	low    — span present but unverified (hook fired, span not authenticated)
//	medium — span absent but runtime fallback present (some correlation evidence)
//	high   — span forged or span absent with no fallback (blind to what actually ran)
func ComputeSpoofingRisk(flags EvasionFlags, signals []sdk.Signal) string {
	// Forged span: attacker injected a fake span_id — identity is untrustworthy.
	if flags.SpanForged {
		return SpoofingRiskHigh
	}
	// Enforced boundary: sandbox or OS hardware guarantee — zero spoofing risk.
	if hasSignal(signals, sdk.ReliabilityEnforcedBoundary, "") {
		return SpoofingRiskNone
	}
	// Span stripped or detached child: span was deliberately removed or the
	// action escaped the hook surface. If there's a runtime fallback, risk is
	// medium (we have partial evidence); without fallback it's high.
	if flags.SpanStripped || flags.DetachedChild || flags.HookMissing {
		if hasSignal(signals, sdk.ReliabilityObservedRuntime, "") {
			return SpoofingRiskMedium
		}
		return SpoofingRiskHigh
	}
	// Normal hook signal present, no known evasion: span present but not
	// cryptographically authenticated — low spoofing risk.
	if hasSignal(signals, sdk.ReliabilityDeclaredIntent, "") ||
		hasSignal(signals, sdk.ReliabilityMediatedAction, "") {
		return SpoofingRiskLow
	}
	// Only advisory or no signals — treat as high (no identity evidence).
	return SpoofingRiskHigh
}

// hasSignal returns true if any signal matches the given reliability and timing filters.
func hasSignal(signals []sdk.Signal, reliability, timing string) bool {
	for _, s := range signals {
		if reliability != "" && s.Source.Reliability != reliability {
			continue
		}
		if timing != "" && s.Source.Timing != timing {
			continue
		}
		return true
	}
	return false
}

// DisplayTarget returns a redacted display path from a signal's action_claim target.
// Only paths/display labels are ledgered — never raw values or secrets.
func DisplayTarget(signals []sdk.Signal) string {
	for _, s := range signals {
		target, _ := s.ActionClaim["target"].(map[string]any)
		if target == nil {
			continue
		}
		if d, ok := target["display"].(string); ok && d != "" {
			return d
		}
	}
	return ""
}

// Labelize assigns human-readable labels to an action for policy and explanation.
func Labelize(actionType, sensitivity string, signals []sdk.Signal) []string {
	var labels []string
	if sensitivity == "credential" {
		labels = append(labels, "credential_access")
	}
	if sensitivity == "external_network" {
		labels = append(labels, "external_egress")
	}
	if strings.Contains(actionType, "shell_exec") {
		labels = append(labels, "shell_execution")
	}
	if strings.Contains(actionType, "file_write") {
		labels = append(labels, "file_mutation")
	}
	for _, s := range signals {
		if s.ActorClaim != nil && s.ActorClaim.Kind == "ai_coding_agent" {
			labels = appendUnique(labels, "ai_agent_actor")
			break
		}
	}
	return labels
}

func appendUnique(ss []string, s string) []string {
	for _, existing := range ss {
		if existing == s {
			return ss
		}
	}
	return append(ss, s)
}
