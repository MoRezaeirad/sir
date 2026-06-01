package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

func TestDispatchEffects_EmptyRegistry(t *testing.T) {
	// With no providers registered, DispatchEffects must not panic and must
	// return an empty summary with no errors.
	intent := Intent{
		Verb:   policy.VerbPushOrigin,
		Target: "origin",
	}
	summary := DispatchEffects(policy.VerdictAllow, intent, nil, t.TempDir())
	if len(summary.Errors) != 0 {
		t.Errorf("expected no errors with empty registry, got: %v", summary.Errors)
	}
	if summary.BlockApplied {
		t.Error("BlockApplied should be false with no effect providers")
	}
}

func TestDispatchEffects_DenyWithNoProviders(t *testing.T) {
	// A deny verdict with no registered effect providers returns gracefully —
	// the hook wire format itself (deny response to Claude) is the enforcement.
	intent := Intent{
		Verb:   policy.VerbNetExternal,
		Target: "https://evil.example.com",
	}
	summary := DispatchEffects(policy.VerdictDeny, intent, nil, t.TempDir())
	if summary.BlockApplied {
		t.Error("no block provider registered, BlockApplied should be false")
	}
}

func TestNewEffectID_Unique(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := newEffectID()
		if ids[id] {
			t.Fatalf("duplicate effect ID generated: %s", id)
		}
		ids[id] = true
		if len(id) < 10 {
			t.Errorf("effect ID too short: %s", id)
		}
	}
}
