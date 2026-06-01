package kernel

import (
	"sync"
	"time"
)

// FrictionState tracks prompt counts per scope to enforce the CORRELATION
// friction bound: "Repeated low-confidence prompts must escalate, aggregate,
// or fail closed. Do not nag forever."
type FrictionState struct {
	mu      sync.Mutex
	prompts map[string][]time.Time // scope → prompt timestamps
}

var globalFriction = &FrictionState{
	prompts: map[string][]time.Time{},
}

// FrictionPolicy controls escalation behavior.
type FrictionPolicy struct {
	MaxPromptsPerWindow int           // max ask verdicts before escalation
	Window              time.Duration // rolling window
	EscalationVerdict   string        // what to do after max prompts
}

var defaultFrictionPolicy = FrictionPolicy{
	MaxPromptsPerWindow: 3,
	Window:              10 * time.Minute,
	EscalationVerdict:   VerdictDeny,
}

// CheckFriction tests whether the scope has exceeded the prompt threshold.
// Returns the escalated verdict if the threshold is exceeded, "" otherwise.
// Implements PRD Phase 9: no broad low-confidence grants, bounded prompts.
func CheckFriction(scope, currentVerdict string, policy *FrictionPolicy) string {
	if currentVerdict != VerdictAsk {
		return currentVerdict
	}
	if policy == nil {
		policy = &defaultFrictionPolicy
	}

	globalFriction.mu.Lock()
	defer globalFriction.mu.Unlock()

	now := time.Now()
	window := now.Add(-policy.Window)
	var recent []time.Time
	for _, t := range globalFriction.prompts[scope] {
		if t.After(window) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= policy.MaxPromptsPerWindow {
		return policy.EscalationVerdict
	}

	recent = append(recent, now)
	globalFriction.prompts[scope] = recent
	return currentVerdict
}

// DegradedModeVerdict returns what to do when a required provider is unavailable.
// "Developers can proceed safely when provider is unavailable, with explicit
// degraded-mode evidence." (PRD Phase 9 exit criteria)
func DegradedModeVerdict(mode, verdict string, providerAvailable bool) (string, string) {
	if providerAvailable {
		return verdict, ""
	}
	// In contained/managed mode, required-provider absence fails closed.
	if mode == ModeContained || mode == ModeManaged {
		return VerdictDeny, "required provider unavailable in " + mode + " mode (fail closed)"
	}
	// In hook_gate/observe/advise, degrade gracefully to detect+record.
	return verdict, "degraded: provider unavailable; detection-only mode"
}
