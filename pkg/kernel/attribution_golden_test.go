package kernel

import (
	"testing"

	"github.com/somoore/sir/pkg/sdk"
)

// TestEnforceabilitySoundnessGap_DemonstratedCapability is the sentinel for the
// false-enforces soundness gap: a provider that merely DECLARES "block"/"contain"
// used to make the kernel claim "enforces" without any proof the provider actually
// enforces. The fix: a declared-only (simulated/stub) capability classifies at most
// "detects"; only DEMONSTRATED enforcement (provider_enforcement="real", or an
// enforced_boundary signal) yields "enforces".
//
// See docs/providers.md "enforcement honesty" and recommendation item 3.
func TestEnforceabilitySoundnessGap_DemonstratedCapability(t *testing.T) {
	signal := sdk.Signal{
		SchemaVersion: sdk.SchemaSignalV0, SignalID: "sig-soundness",
		Source:     sdk.Source{Kind: "os_sensor", Reliability: sdk.ReliabilityDeclaredIntent, Timing: sdk.TimingPreExec},
		ActorClaim: &sdk.ActorClaim{Kind: "ai_coding_agent"},
		ActionClaim: map[string]any{
			"type":   "network_connect",
			"target": map[string]any{"display": "https://unknown.example", "sensitivity": "external_network"},
		},
	}

	// Declared-only (stub) provider: declares contain but enforcement is simulated.
	// Must NOT yield enforces.
	simulated := Evaluate(EvaluationInput{
		CaseID:               "soundness-simulated",
		Mode:                 ModeContained,
		Signals:              []sdk.Signal{signal},
		ProviderCapabilities: []string{"contain", "record"},
		ProviderEnforcement:  "simulated",
	})
	if simulated.Enforceability != ClassDetects {
		t.Errorf("simulated provider: want detects (declared-only capability), got %s", simulated.Enforceability)
	}

	// Same with no enforcement flag at all (unproven) — also detects.
	unproven := Evaluate(EvaluationInput{
		CaseID:               "soundness-unproven",
		Mode:                 ModeContained,
		Signals:              []sdk.Signal{signal},
		ProviderCapabilities: []string{"contain", "record"},
	})
	if unproven.Enforceability != ClassDetects {
		t.Errorf("unproven provider: want detects (no enforcement proof), got %s", unproven.Enforceability)
	}

	// Demonstrated (real) provider: declared contain AND proven enforcement → enforces.
	real := Evaluate(EvaluationInput{
		CaseID:               "soundness-real",
		Mode:                 ModeContained,
		Signals:              []sdk.Signal{signal},
		ProviderCapabilities: []string{"contain", "record"},
		ProviderEnforcement:  "real",
	})
	if real.Enforceability != ClassEnforces {
		t.Errorf("real provider: want enforces (demonstrated capability), got %s", real.Enforceability)
	}

	// An enforced_boundary signal is inherent proof — enforces even without the flag.
	boundary := Evaluate(EvaluationInput{
		CaseID: "soundness-boundary",
		Mode:   ModeContained,
		Signals: []sdk.Signal{{
			SchemaVersion: sdk.SchemaSignalV0, SignalID: "sig-boundary",
			Source:      sdk.Source{Kind: "sandbox", Reliability: sdk.ReliabilityEnforcedBoundary, Timing: sdk.TimingPreExec},
			ActorClaim:  &sdk.ActorClaim{Kind: "ai_coding_agent"},
			ActionClaim: map[string]any{"type": "network_connect", "target": map[string]any{"display": "x", "sensitivity": "external_network"}},
		}},
	})
	if boundary.Enforceability != ClassEnforces {
		t.Errorf("enforced_boundary signal: want enforces, got %s", boundary.Enforceability)
	}
}

// Attribution golden tests (Item 5). These tests pin the mapping:
//   signal_set → expected {confidence, spoofing_risk}
//
// Changing a correlation weight or attribution rule must break a golden here,
// not silently degrade a downstream policy test.

// goldenAttributionTest asserts attribution confidence and spoofing risk.
func goldenAttributionTest(t *testing.T, name string, in EvaluationInput, wantConf, wantSpoofing string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		out := Evaluate(in)
		if out.Attribution != wantConf {
			t.Errorf("attribution: want %q, got %q", wantConf, out.Attribution)
		}
		if out.SpoofingRisk != wantSpoofing {
			t.Errorf("spoofing_risk: want %q, got %q", wantSpoofing, out.SpoofingRisk)
		}
	})
}

// TestAttributionGoldens_ConfidenceByReliability pins confidence derivation
// from signal reliability. These match the sir.attribution.v0 spec.
func TestAttributionGoldens_ConfidenceByReliability(t *testing.T) {
	// enforced_boundary → high confidence, no spoofing risk.
	goldenAttributionTest(t, "enforced_boundary→high/none",
		EvaluationInput{
			CaseID: "golden-enf-boundary", Mode: ModeContained,
			Signals: []sdk.Signal{{
				SchemaVersion: sdk.SchemaSignalV0, SignalID: "sig-enf",
				Source:      sdk.Source{Kind: "sandbox", Reliability: sdk.ReliabilityEnforcedBoundary, Timing: sdk.TimingPreExec},
				ActionClaim: map[string]any{"type": "shell_exec", "target": map[string]any{"display": "cmd", "sensitivity": "low"}},
			}},
		},
		ConfHigh, SpoofingRiskNone,
	)

	// declared_intent only, no evasion → medium confidence, low spoofing risk.
	goldenAttributionTest(t, "declared_intent_only→medium/low",
		EvaluationInput{
			CaseID: "golden-decl-intent", Mode: ModeHookGate,
			Signals: []sdk.Signal{{
				SchemaVersion: sdk.SchemaSignalV0, SignalID: "sig-decl",
				Source:      sdk.Source{Kind: "claude_hook", Reliability: sdk.ReliabilityDeclaredIntent, Timing: sdk.TimingPreExec},
				ActionClaim: map[string]any{"type": "shell_exec", "target": map[string]any{"display": "ls", "sensitivity": "low"}},
			}},
		},
		ConfMedium, SpoofingRiskLow,
	)

	// observed_runtime only → low confidence, high spoofing risk (no hook evidence).
	goldenAttributionTest(t, "observed_runtime_only→low/high",
		EvaluationInput{
			CaseID: "golden-obs-runtime", Mode: ModeOSObserved,
			Signals: []sdk.Signal{{
				SchemaVersion: sdk.SchemaSignalV0, SignalID: "sig-obs",
				Source:      sdk.Source{Kind: "os_sensor", Reliability: sdk.ReliabilityObservedRuntime, Timing: sdk.TimingPostExec},
				ActionClaim: map[string]any{"type": "file_read", "target": map[string]any{"display": "file.txt", "sensitivity": "low"}},
			}},
		},
		ConfLow, SpoofingRiskHigh,
	)

	// No signals → unknown confidence, high spoofing risk.
	goldenAttributionTest(t, "no_signals→unknown/high",
		EvaluationInput{
			CaseID: "golden-no-signals", Mode: ModeHookGate,
			Signals: nil,
		},
		ConfUnknown, SpoofingRiskHigh,
	)
}

// TestAttributionGoldens_SpanEvasion pins spoofing risk derivation from evasion flags.
func TestAttributionGoldens_SpanEvasion(t *testing.T) {
	declaredIntentSignal := sdk.Signal{
		SchemaVersion: sdk.SchemaSignalV0, SignalID: "sig-hook",
		Source:      sdk.Source{Kind: "claude_hook", Reliability: sdk.ReliabilityDeclaredIntent, Timing: sdk.TimingPreExec},
		ActionClaim: map[string]any{"type": "shell_exec", "target": map[string]any{"display": "cmd", "sensitivity": "low"}},
	}

	// span_stripped + no OS fallback → medium confidence (hook fired), HIGH spoofing risk.
	// The hook fired (medium confidence) but span was stripped (high spoofing risk — blind post-exec).
	goldenAttributionTest(t, "span_stripped_no_fallback→medium/high",
		EvaluationInput{
			CaseID: "golden-span-strip", Mode: ModeHookGate,
			Signals: []sdk.Signal{declaredIntentSignal},
			Evasion: EvasionFlags{SpanStripped: true},
		},
		ConfMedium, SpoofingRiskHigh,
	)

	// span_forged → medium confidence (hook fired), HIGH spoofing risk.
	// The forged span_id means the actor identity is untrustworthy regardless of
	// what the hook signal says. Spoofing risk is always high for forged spans.
	goldenAttributionTest(t, "span_forged→medium/high",
		EvaluationInput{
			CaseID: "golden-span-forge", Mode: ModeHookGate,
			Signals: []sdk.Signal{declaredIntentSignal},
			Evasion: EvasionFlags{SpanForged: true},
		},
		ConfMedium, SpoofingRiskHigh,
	)

	// declared_intent + observed_runtime, span_stripped, matching pid/window →
	// medium confidence (hook fired), MEDIUM spoofing risk (span absent but runtime fallback).
	goldenAttributionTest(t, "span_stripped_with_os_fallback→medium/medium",
		EvaluationInput{
			CaseID: "golden-span-strip-fallback", Mode: ModeHookGate,
			Signals: []sdk.Signal{
				declaredIntentSignal,
				{
					SchemaVersion: sdk.SchemaSignalV0, SignalID: "sig-os",
					Source:      sdk.Source{Kind: "os_sensor", Reliability: sdk.ReliabilityObservedRuntime, Timing: sdk.TimingPostExec},
					ActionClaim: map[string]any{"type": "file_read", "target": map[string]any{"display": "f.txt", "sensitivity": "low"}},
				},
			},
			Evasion: EvasionFlags{SpanStripped: true},
		},
		ConfMedium, SpoofingRiskMedium,
	)

	// hook_missing + no signals → unknown confidence, HIGH spoofing risk (blind).
	goldenAttributionTest(t, "hook_missing_no_signals→unknown/high",
		EvaluationInput{
			CaseID: "golden-hook-missing", Mode: ModeHookGate,
			Signals: nil,
			Evasion: EvasionFlags{HookMissing: true},
		},
		ConfUnknown, SpoofingRiskHigh,
	)

	// hook_missing + OS fallback → low confidence (OS only), MEDIUM spoofing risk
	// (no span but partial evidence from OS sensor).
	goldenAttributionTest(t, "hook_missing_with_os_fallback→low/medium",
		EvaluationInput{
			CaseID: "golden-hook-missing-os", Mode: ModeOSObserved,
			Signals: []sdk.Signal{{
				SchemaVersion: sdk.SchemaSignalV0, SignalID: "sig-os",
				Source:      sdk.Source{Kind: "os_sensor", Reliability: sdk.ReliabilityObservedRuntime, Timing: sdk.TimingPostExec},
				ActionClaim: map[string]any{"type": "file_read", "target": map[string]any{"display": "f.txt", "sensitivity": "low"}},
			}},
			Evasion: EvasionFlags{HookMissing: true},
		},
		ConfLow, SpoofingRiskMedium,
	)
}
