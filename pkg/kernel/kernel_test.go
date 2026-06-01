package kernel

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/sdk"
)

// lowConfidenceSignals returns signals with only observed_runtime reliability
// (post-hoc OS sensor only), producing ConfLow attribution.
func lowConfidenceSignals(actionType, sensitivity string) []sdk.Signal {
	return []sdk.Signal{
		{
			SchemaVersion: sdk.SchemaSignalV0,
			SignalID:      "sig-test-low",
			Source: sdk.Source{
				Kind:        "os_file_sensor",
				Reliability: sdk.ReliabilityObservedRuntime,
				Timing:      sdk.TimingPostExec,
			},
			ActorClaim: &sdk.ActorClaim{Kind: "ai_coding_agent", Name: "claude-code"},
			ActionClaim: map[string]any{
				"type":   actionType,
				"target": map[string]any{"display": "test-target", "sensitivity": sensitivity},
			},
		},
	}
}

// mediumConfidenceSignals returns signals with declared_intent reliability,
// producing ConfMedium attribution.
func mediumConfidenceSignals(actionType, sensitivity string) []sdk.Signal {
	return []sdk.Signal{
		{
			SchemaVersion: sdk.SchemaSignalV0,
			SignalID:      "sig-test-med",
			Source: sdk.Source{
				Kind:        "claude_hook",
				Reliability: sdk.ReliabilityDeclaredIntent,
				Timing:      sdk.TimingPreExec,
			},
			ActorClaim: &sdk.ActorClaim{Kind: "ai_coding_agent", Name: "claude-code"},
			ActionClaim: map[string]any{
				"type":   actionType,
				"target": map[string]any{"display": "test-target", "sensitivity": sensitivity},
			},
		},
	}
}

// --- Rule 1: Policy matches on attribution confidence ---

// TestLowConfidenceEscalation_AllowBecomesAsk verifies rule 1:
// credential sensitivity + low confidence promotes allow → ask.
// The low-confidence-escalation rule fires when the initial verdict would be
// allow but attribution is too weak to trust the action is safe.
func TestLowConfidenceEscalation_AllowBecomesAsk(t *testing.T) {
	// Credential read, no agent actor (bypasses deny-agent-credential-read),
	// OS sensor only → low attribution → should escalate allow to ask.
	signals := []sdk.Signal{
		{
			SchemaVersion: sdk.SchemaSignalV0,
			SignalID:      "sig-low-cred",
			Source: sdk.Source{
				Kind:        "os_file_sensor",
				Reliability: sdk.ReliabilityObservedRuntime,
				Timing:      sdk.TimingPostExec,
			},
			ActionClaim: map[string]any{
				"type":   "file_read",
				"target": map[string]any{"display": ".env", "sensitivity": "credential"},
			},
		},
	}
	out := Evaluate(EvaluationInput{
		CaseID:  "rule1-test",
		Mode:    ModeHookGate,
		Signals: signals,
	})
	if out.Attribution != ConfLow {
		t.Errorf("rule 1 precondition: want low attribution, got %s", out.Attribution)
	}
	if out.Verdict != VerdictAsk {
		t.Errorf("rule 1: low confidence + credential (no agent actor) → want ask, got %s", out.Verdict)
	}
	found := false
	for _, r := range out.PolicyRules {
		if r == "low-confidence-escalation" {
			found = true
		}
	}
	if !found {
		t.Errorf("rule 1: expected 'low-confidence-escalation' in policy_rules, got %v", out.PolicyRules)
	}
}


// TestMediumConfidence_NoEscalation verifies that medium confidence does NOT
// trigger the low-confidence escalation rule.
func TestMediumConfidence_NoEscalation(t *testing.T) {
	signals := mediumConfidenceSignals("network_connect", "external_network")
	out := Evaluate(EvaluationInput{
		CaseID:  "no-escalation-test",
		Mode:    ModeHookGate,
		Signals: signals,
	})
	for _, r := range out.PolicyRules {
		if r == "low-confidence-escalation" {
			t.Errorf("rule 1: medium confidence should not trigger low-confidence-escalation, got rules %v", out.PolicyRules)
		}
	}
}

// --- Rule 2: High-sensitivity + low confidence fails stricter; deny does not relax ---

// TestLowConfidenceDenyDoesNotRelax verifies rule 2:
// when policy produces deny, low confidence must not downgrade it to ask.
func TestLowConfidenceDenyDoesNotRelax(t *testing.T) {
	// AI agent reads credentials (os sensor only) — deny-agent-credential-read fires.
	signals := lowConfidenceSignals("file_read", "credential")
	out := Evaluate(EvaluationInput{
		CaseID:  "rule2-deny-test",
		Mode:    ModeHookGate,
		Signals: signals,
	})
	if out.Attribution != ConfLow {
		t.Errorf("rule 2 precondition: want low attribution, got %s", out.Attribution)
	}
	if out.Verdict != VerdictDeny {
		t.Errorf("rule 2: low confidence must not relax deny → want deny, got %s", out.Verdict)
	}
	// low-confidence-escalation must NOT appear (deny is already stricter than ask).
	for _, r := range out.PolicyRules {
		if r == "low-confidence-escalation" {
			t.Errorf("rule 2: low-confidence-escalation must not appear when verdict is already deny, got rules %v", out.PolicyRules)
		}
	}
}

// TestLowConfidenceDeny_PolicyRulePresent verifies the deny rule is correctly attributed.
func TestLowConfidenceDeny_PolicyRulePresent(t *testing.T) {
	signals := lowConfidenceSignals("file_read", "credential")
	out := Evaluate(EvaluationInput{
		CaseID:  "rule2-rule-test",
		Mode:    ModeHookGate,
		Signals: signals,
	})
	found := false
	for _, r := range out.PolicyRules {
		if r == "deny-agent-credential-read" {
			found = true
		}
	}
	if !found {
		t.Errorf("rule 2: expected deny-agent-credential-read in policy_rules, got %v", out.PolicyRules)
	}
}

// --- Rule 3: Repeated low-confidence asks are bounded ---

// TestFrictionBound_RepeatedAskEscalates verifies rule 3:
// repeated asks escalate to deny after MaxPromptsPerWindow.
func TestFrictionBound_RepeatedAskEscalates(t *testing.T) {
	scope := "friction-test-scope-" + t.Name()
	policy := &FrictionPolicy{
		MaxPromptsPerWindow: 2,
		Window:              10 * time.Minute,
		EscalationVerdict:   VerdictDeny,
	}

	// First two asks pass through.
	for i := 0; i < 2; i++ {
		result := CheckFriction(scope, VerdictAsk, policy)
		if result != VerdictAsk {
			t.Fatalf("rule 3: ask %d should pass friction, got %s", i+1, result)
		}
	}
	// Third ask exceeds the bound → escalate to deny.
	result := CheckFriction(scope, VerdictAsk, policy)
	if result != VerdictDeny {
		t.Errorf("rule 3: third ask should escalate to deny, got %s", result)
	}
}

// TestFrictionBound_NonAskUnaffected verifies friction does not affect allow/deny.
func TestFrictionBound_NonAskUnaffected(t *testing.T) {
	scope := "friction-nonask-" + t.Name()
	policy := &FrictionPolicy{MaxPromptsPerWindow: 1, Window: 10 * time.Minute, EscalationVerdict: VerdictDeny}
	for _, v := range []string{VerdictAllow, VerdictDeny} {
		result := CheckFriction(scope, v, policy)
		if result != v {
			t.Errorf("rule 3: friction must not affect %s verdict, got %s", v, result)
		}
	}
}

// TestFrictionBound_DefaultPolicyBounds verifies the default friction policy
// (3 asks per 10 minutes) escalates after the threshold.
func TestFrictionBound_DefaultPolicyBounds(t *testing.T) {
	scope := "friction-default-" + t.Name()
	for i := 0; i < 3; i++ {
		result := CheckFriction(scope, VerdictAsk, nil)
		if result != VerdictAsk {
			t.Fatalf("rule 3: default policy ask %d should pass, got %s", i+1, result)
		}
	}
	result := CheckFriction(scope, VerdictAsk, nil)
	if result != VerdictDeny {
		t.Errorf("rule 3: default policy should escalate to deny after 3 asks, got %s", result)
	}
}

// --- Rule 4: Grants and taint-clears inherit the confidence context ---

// TestTaintInheritsConfidence verifies rule 4:
// taint entries record the attribution confidence at creation time.
func TestTaintInheritsConfidence(t *testing.T) {
	scope := "taint-confidence-" + t.Name()
	taintKind := "credential_access_test_r4"

	Taint(scope, "session", taintKind, ConfLow)

	globalTaint.mu.Lock()
	var found *TaintEntry
	for i := range globalTaint.entries {
		e := &globalTaint.entries[i]
		if e.Scope == scope && e.TaintKind == taintKind {
			found = e
			break
		}
	}
	globalTaint.mu.Unlock()

	if found == nil {
		t.Fatal("rule 4: taint entry not found after Taint()")
	}
	if found.Confidence != ConfLow {
		t.Errorf("rule 4: taint confidence want %s, got %s", ConfLow, found.Confidence)
	}
}

// TestTaintPersist_SkipsLowConfidence verifies rule 4 (persistence):
// PersistTaint must not write low-confidence entries to disk.
// Low-confidence taints are runtime state; persistence grants them unintended longevity.
func TestTaintPersist_SkipsLowConfidence(t *testing.T) {
	path := t.TempDir() + "/taint.json"
	scope := "taint-persist-low-" + t.Name()
	Taint(scope, "session", "credential_access_persist_low", ConfLow)

	if err := PersistTaint(path); err != nil {
		t.Fatalf("PersistTaint: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read taint file: %v", err)
	}
	if strings.Contains(string(data), scope) {
		t.Errorf("rule 4: low-confidence taint scope %q must not be persisted to disk, found in:\n%s", scope, data)
	}
}

// TestTaintPersist_KeepsHighConfidence verifies rule 4 (persistence):
// PersistTaint must write high-confidence entries.
func TestTaintPersist_KeepsHighConfidence(t *testing.T) {
	path := t.TempDir() + "/taint-high.json"
	scope := "taint-persist-high-" + t.Name()
	Taint(scope, "session", "credential_access_persist_high", ConfHigh)

	if err := PersistTaint(path); err != nil {
		t.Fatalf("PersistTaint: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read taint file: %v", err)
	}
	if !strings.Contains(string(data), scope) {
		t.Errorf("rule 4: high-confidence taint scope %q must be persisted, not found in:\n%s", scope, data)
	}
}

// --- Item 4: Decision-time downgrade surface ---

// TestRequiredEffectDowngrade_SurfacedInExplanation verifies that when a policy
// requires a block effect but the active mode cannot deliver it, the DOWNGRADE
// notice appears in the decision explanation (surfaced by 'sir why', not only
// buried in the ledger).
func TestRequiredEffectDowngrade_SurfacedInExplanation(t *testing.T) {
	// advise mode cannot block — ModeCanBlock("advise") is false.
	// An ai_agent_actor credential read triggers deny-agent-credential-read
	// which plans a required block effect.
	signals := lowConfidenceSignals("file_read", "credential")
	dec := Process("downgrade-test", ModeAdvise, signals, EvasionFlags{})

	if !strings.Contains(dec.Explanation, "DOWNGRADE") {
		t.Errorf("expected DOWNGRADE notice in explanation when block effect unavailable in advise mode, got:\n%s", dec.Explanation)
	}
	if !strings.Contains(dec.Explanation, "block") {
		t.Errorf("expected 'block' in downgrade explanation, got:\n%s", dec.Explanation)
	}
}

// TestRequiredEffectDowngrade_NotPresentWhenModeCanBlock verifies no false
// downgrade when the active mode CAN deliver block effects.
func TestRequiredEffectDowngrade_NotPresentWhenModeCanBlock(t *testing.T) {
	signals := lowConfidenceSignals("file_read", "credential")
	dec := Process("nodegrade-test", ModeHookGate, signals, EvasionFlags{})

	if strings.Contains(dec.Explanation, "DOWNGRADE") {
		t.Errorf("unexpected DOWNGRADE notice in explanation for hook_gate mode:\n%s", dec.Explanation)
	}
}

// TestUnavailableRequiredEffects_Unit verifies the availability check function.
func TestUnavailableRequiredEffects_Unit(t *testing.T) {
	effects := []PlannedEffect{
		{Type: "block", Required: true, FailClosed: true},
		{Type: "record", Required: true, FailClosed: false},
	}

	unavail := UnavailableRequiredEffects(ModeAdvise, effects)
	if len(unavail) == 0 {
		t.Error("expected block to be unavailable in advise mode, got empty list")
	}
	found := false
	for _, u := range unavail {
		if strings.Contains(u, "block") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'block' in unavailable list, got %v", unavail)
	}

	unavail = UnavailableRequiredEffects(ModeHookGate, effects)
	if len(unavail) > 0 {
		t.Errorf("expected no unavailable effects in hook_gate mode, got %v", unavail)
	}
}

// TestApplyLowConfidenceEscalation_Unit tests the escalation function directly.
// Only credential/high/critical sensitivity triggers escalation; external_network
// already has its own ask rule so escalation is not added there.
func TestApplyLowConfidenceEscalation_Unit(t *testing.T) {
	tests := []struct {
		verdict     string
		attribution string
		sensitivity string
		wantVerdict string
		wantRule    bool
	}{
		{VerdictAllow, ConfLow, "credential", VerdictAsk, true},
		{VerdictAllow, ConfLow, "high", VerdictAsk, true},
		{VerdictAllow, ConfUnknown, "credential", VerdictAsk, true},
		{VerdictAllow, ConfLow, "external_network", VerdictAllow, false}, // external_network not in escalation list
		{VerdictDeny, ConfLow, "credential", VerdictDeny, false},         // deny must not relax
		{VerdictAsk, ConfLow, "credential", VerdictAsk, false},           // ask stays ask
		{VerdictAllow, ConfMedium, "credential", VerdictAllow, false},
		{VerdictAllow, ConfHigh, "credential", VerdictAllow, false},
		{VerdictAllow, ConfLow, "low", VerdictAllow, false},
		{VerdictAllow, ConfLow, "medium", VerdictAllow, false},
	}

	for _, tc := range tests {
		rules := []string{}
		got, gotRules := applyLowConfidenceEscalation(tc.verdict, rules, tc.attribution, tc.sensitivity)
		if got != tc.wantVerdict {
			t.Errorf("applyLowConfidenceEscalation(%s, %s, %s): verdict want %s, got %s",
				tc.verdict, tc.attribution, tc.sensitivity, tc.wantVerdict, got)
		}
		hasRule := false
		for _, r := range gotRules {
			if r == "low-confidence-escalation" {
				hasRule = true
			}
		}
		if tc.wantRule && !hasRule {
			t.Errorf("applyLowConfidenceEscalation(%s, %s, %s): want escalation rule, got rules %v",
				tc.verdict, tc.attribution, tc.sensitivity, gotRules)
		}
		if !tc.wantRule && len(gotRules) > 0 {
			t.Errorf("applyLowConfidenceEscalation(%s, %s, %s): want no rules, got %v",
				tc.verdict, tc.attribution, tc.sensitivity, gotRules)
		}
	}
}

// --- Item 3: Actor attribution resolution ---

// TestResolvedActorKind_DenyFiresWhenAgentResolved proves that deny-agent-credential-read
// fires when the orchestrator resolves a shell signal to ai_coding_agent via session
// evidence. The shell provider is honest (kind="shell"); the resolution is in the kernel.
func TestResolvedActorKind_DenyFiresWhenAgentResolved(t *testing.T) {
	signals := []sdk.Signal{
		{
			SchemaVersion: sdk.SchemaSignalV0,
			SignalID:      "sig-shell-cred",
			Source: sdk.Source{
				Kind:        "shell_wrapper",
				Reliability: sdk.ReliabilityDeclaredIntent,
				Timing:      sdk.TimingPreExec,
			},
			// Shell provider is honest: actor_claim.kind="shell", not ai_coding_agent.
			ActorClaim: &sdk.ActorClaim{Kind: "shell", PID: 9001},
			ActionClaim: map[string]any{
				"type":   "shell_exec",
				"target": map[string]any{"display": "cat ~/.aws/credentials", "sensitivity": "credential"},
			},
		},
	}

	// With orchestrator resolution: deny-agent-credential-read MUST fire.
	out := Evaluate(EvaluationInput{
		CaseID:            "item3-resolved-test",
		Mode:              ModeHookGate,
		Signals:           signals,
		ResolvedActorKind: "ai_coding_agent",
	})
	if out.Verdict != VerdictDeny {
		t.Errorf("item 3: resolved ai_coding_agent + credential → want deny, got %s", out.Verdict)
	}
	found := false
	for _, r := range out.PolicyRules {
		if r == "deny-agent-credential-read" {
			found = true
		}
	}
	if !found {
		t.Errorf("item 3: deny-agent-credential-read must fire for resolved agent, got rules %v", out.PolicyRules)
	}
}

// TestResolvedActorKind_RuleDoesNotFireWithoutResolution proves that when no
// agent-session evidence exists, the shell signal does NOT trigger deny-agent-credential-read.
// A developer's own shell credential access must not be silently denied.
func TestResolvedActorKind_RuleDoesNotFireWithoutResolution(t *testing.T) {
	signals := []sdk.Signal{
		{
			SchemaVersion: sdk.SchemaSignalV0,
			SignalID:      "sig-shell-cred-no-resolve",
			Source: sdk.Source{
				Kind:        "shell_wrapper",
				Reliability: sdk.ReliabilityDeclaredIntent,
				Timing:      sdk.TimingPreExec,
			},
			// Shell provider is honest: no ai_coding_agent claim.
			ActorClaim: &sdk.ActorClaim{Kind: "shell", PID: 9001},
			ActionClaim: map[string]any{
				"type":   "shell_exec",
				"target": map[string]any{"display": "cat ~/.aws/credentials", "sensitivity": "credential"},
			},
		},
	}

	// Without orchestrator resolution (ResolvedActorKind empty): deny-agent rule must NOT fire.
	out := Evaluate(EvaluationInput{
		CaseID:  "item3-unresolved-test",
		Mode:    ModeHookGate,
		Signals: signals,
		// ResolvedActorKind is empty — no agent-session evidence.
	})
	for _, r := range out.PolicyRules {
		if r == "deny-agent-credential-read" {
			t.Errorf("item 3: deny-agent-credential-read must NOT fire without resolution, got rules %v", out.PolicyRules)
		}
	}
	// Shell-only credential access: medium attribution, allow (not deny).
	if out.Verdict == VerdictDeny {
		t.Errorf("item 3: shell credential access without agent resolution must not deny, got %s", out.Verdict)
	}
	if out.Attribution != ConfMedium {
		t.Errorf("item 3: declared_intent → medium attribution, got %s", out.Attribution)
	}
}
