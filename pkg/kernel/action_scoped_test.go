package kernel

import (
	"testing"

	"github.com/somoore/sir/pkg/sdk"
)

// Item 8: action-scoped capability. A provider scoping real enforcement to a
// subset of action types only enforces a covered action; an uncovered or unknown
// action degrades to detects (it still observes inside the jail but must not
// over-claim). Must match the Rust sir-core mirror exactly.

func actionSignal(actionType string) sdk.Signal {
	return sdk.Signal{
		Source:      sdk.Source{Reliability: sdk.ReliabilityDeclaredIntent, Timing: sdk.TimingPreExec},
		ActionClaim: map[string]any{"type": actionType},
	}
}

func netjailInput(actionType string) EnforceabilityInput {
	in := EnforceabilityInput{
		Mode:                 ModeContained,
		ProviderCapabilities: []string{"block", "record"},
		ProviderEnforcement:  "real",
		EnforcedActions:      []string{"network_connect"},
	}
	if actionType != "" {
		in.Signals = []sdk.Signal{actionSignal(actionType)}
	}
	return in
}

func TestActionScoped(t *testing.T) {
	cases := []struct {
		name      string
		in        EnforceabilityInput
		wantClass string
	}{
		{"covered enforces", netjailInput("network_connect"), ClassEnforces},
		{"uncovered detects", netjailInput("file_write"), ClassDetects},
		{"unknown action detects", netjailInput(""), ClassDetects},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AnalyzeEnforceability(tc.in).Class; got != tc.wantClass {
				t.Errorf("class = %q, want %q", got, tc.wantClass)
			}
		})
	}

	// Backward compat: empty EnforcedActions = enforces every action.
	in := netjailInput("file_write")
	in.EnforcedActions = nil
	if got := AnalyzeEnforceability(in).Class; got != ClassEnforces {
		t.Errorf("empty EnforcedActions must enforce all (backward compat), got %q", got)
	}
}

// TestMediatedDemonstratedMediationGate pins item 9: mediated mode enforces only
// with demonstrated mediation (provider_enforcement real or an enforced_boundary
// signal); a declared-only pre-exec signal degrades to detects. Mirrors the Rust
// sir-core gate exactly.
func TestMediatedDemonstratedMediationGate(t *testing.T) {
	preExec := []sdk.Signal{{Source: sdk.Source{Reliability: sdk.ReliabilityMediatedAction, Timing: sdk.TimingPreExec}}}
	boundary := []sdk.Signal{{Source: sdk.Source{Reliability: sdk.ReliabilityEnforcedBoundary, Timing: sdk.TimingPreExec}}}

	cases := []struct {
		name      string
		in        EnforceabilityInput
		wantClass string
	}{
		{"real enforcement enforces", EnforceabilityInput{Mode: ModeMediated, Signals: preExec, ProviderEnforcement: "real"}, ClassEnforces},
		{"enforced-boundary signal enforces", EnforceabilityInput{Mode: ModeMediated, Signals: boundary}, ClassEnforces},
		{"declared-only detects", EnforceabilityInput{Mode: ModeMediated, Signals: preExec}, ClassDetects},
		{"no pre-exec detects", EnforceabilityInput{Mode: ModeMediated, Signals: nil}, ClassDetects},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AnalyzeEnforceability(tc.in).Class; got != tc.wantClass {
				t.Errorf("class = %q, want %q", got, tc.wantClass)
			}
		})
	}
}

// TestActionEnforced pins the helper directly.
func TestActionEnforced(t *testing.T) {
	if !actionEnforced(nil, "anything") {
		t.Error("empty list must cover everything")
	}
	if !actionEnforced([]string{"a", "b"}, "b") {
		t.Error("listed action must be covered")
	}
	if actionEnforced([]string{"a"}, "unknown") {
		t.Error("unknown must not be covered by a non-empty list")
	}
}
