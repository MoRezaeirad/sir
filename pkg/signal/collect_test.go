package signal

import (
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/kernel"
	"github.com/somoore/sir/pkg/sdk"
)

func samplePayload(toolName string, input map[string]any) *agent.HookPayload {
	return &agent.HookPayload{
		SessionID:     "test-session",
		ToolUseID:     "use-123",
		ToolName:      toolName,
		ToolInput:     input,
		AgentID:       agent.Claude,
		HookEventName: "PreToolUse",
	}
}

// ── FromHookPayload ──────────────────────────────────────────────────────────

func TestFromHookPayload_BashCommand(t *testing.T) {
	payload := samplePayload("Bash", map[string]any{"command": "git push origin main"})
	sig := FromHookPayload(payload)

	if sig.SchemaVersion != sdk.SchemaSignalV0 {
		t.Errorf("SchemaVersion = %q, want %q", sig.SchemaVersion, sdk.SchemaSignalV0)
	}
	if sig.Source.Reliability != sdk.ReliabilityDeclaredIntent {
		t.Errorf("Reliability = %q, want declared_intent", sig.Source.Reliability)
	}
	if sig.Source.Timing != sdk.TimingPreExec {
		t.Errorf("Timing = %q, want pre_exec", sig.Source.Timing)
	}
	if sig.ActorClaim == nil || sig.ActorClaim.Kind != "ai_coding_agent" {
		t.Errorf("ActorClaim.Kind should be ai_coding_agent for Claude hook")
	}
	if sig.Session == nil || sig.Session.SessionID != "test-session" {
		t.Error("Session.SessionID not propagated")
	}
	if sig.Session.SpanID != "use-123" {
		t.Error("Session.SpanID (ToolUseID) not propagated")
	}
	actionType, _ := sig.ActionClaim["type"].(string)
	if actionType != "shell_exec" {
		t.Errorf("action type = %q, want shell_exec", actionType)
	}
}

func TestFromHookPayload_FileRead(t *testing.T) {
	payload := samplePayload("Read", map[string]any{"file_path": "src/main.go"})
	sig := FromHookPayload(payload)
	if at, _ := sig.ActionClaim["type"].(string); at != "file_read" {
		t.Errorf("action type = %q, want file_read", at)
	}
}

func TestFromHookPayload_FileWrite(t *testing.T) {
	payload := samplePayload("Write", map[string]any{"file_path": "output.go"})
	sig := FromHookPayload(payload)
	if at, _ := sig.ActionClaim["type"].(string); at != "file_write" {
		t.Errorf("action type = %q, want file_write", at)
	}
}

func TestFromHookPayload_SensitiveFile(t *testing.T) {
	payload := samplePayload("Read", map[string]any{"file_path": ".env"})
	sig := FromHookPayload(payload)
	target, _ := sig.ActionClaim["target"].(map[string]any)
	if target == nil {
		t.Fatal("target is nil")
	}
	if target["sensitivity"] != "credential" {
		t.Errorf("sensitivity = %q, want credential for .env", target["sensitivity"])
	}
}

func TestFromHookPayload_NetworkFetch(t *testing.T) {
	payload := samplePayload("WebFetch", map[string]any{"url": "https://api.example.com"})
	sig := FromHookPayload(payload)
	if at, _ := sig.ActionClaim["type"].(string); at != "network_fetch" {
		t.Errorf("action type = %q, want network_fetch", at)
	}
	target, _ := sig.ActionClaim["target"].(map[string]any)
	if target["sensitivity"] != "external_network" {
		t.Errorf("sensitivity = %q, want external_network", target["sensitivity"])
	}
}

func TestFromHookPayload_MCPTool(t *testing.T) {
	payload := samplePayload("mcp__github__create_issue", map[string]any{})
	sig := FromHookPayload(payload)
	if at, _ := sig.ActionClaim["type"].(string); at != "mcp_call" {
		t.Errorf("action type = %q, want mcp_call", at)
	}
}

func TestFromHookPayload_NilPayload(t *testing.T) {
	sig := FromHookPayload(nil)
	if sig.SignalID != "" {
		t.Error("nil payload should produce empty signal")
	}
}

func TestFromHookPayload_NoAgentID(t *testing.T) {
	payload := &agent.HookPayload{
		ToolName: "Bash",
		ToolInput: map[string]any{"command": "ls"},
	}
	sig := FromHookPayload(payload)
	if sig.ActorClaim == nil || sig.ActorClaim.Kind != "human_developer" {
		t.Errorf("ActorClaim.Kind = %q, want human_developer for empty AgentID", sig.ActorClaim.Kind)
	}
}

// ── ActorKindFromSignals ─────────────────────────────────────────────────────

func TestActorKindFromSignals_AgentHook(t *testing.T) {
	payload := samplePayload("Bash", map[string]any{"command": "ls"})
	signals := []sdk.Signal{FromHookPayload(payload)}
	if got := ActorKindFromSignals(signals); got != "ai_coding_agent" {
		t.Errorf("ActorKindFromSignals = %q, want ai_coding_agent", got)
	}
}

func TestActorKindFromSignals_NoSignals(t *testing.T) {
	if got := ActorKindFromSignals(nil); got != "unknown" {
		t.Errorf("ActorKindFromSignals(nil) = %q, want unknown", got)
	}
}

// ── EnforceabilityForSignals ─────────────────────────────────────────────────

func TestEnforceabilityForSignals_HookSignal(t *testing.T) {
	payload := samplePayload("Bash", map[string]any{"command": "git push"})
	signals := []sdk.Signal{FromHookPayload(payload)}
	class := EnforceabilityForSignals(signals)
	if class != kernel.ClassEnforces {
		t.Errorf("enforceability = %q, want %q for hook signal", class, kernel.ClassEnforces)
	}
}

func TestEnforceabilityForSignals_NoSignals(t *testing.T) {
	// hook_gate mode with no signals and no evasion flags → detects
	// (the hook path exists but fired nothing; runtime observation is absent).
	class := EnforceabilityForSignals(nil)
	if class != kernel.ClassDetects {
		t.Errorf("enforceability = %q, want %q for no signals in hook_gate mode", class, kernel.ClassDetects)
	}
}

func TestEnforceabilityForSignals_RuntimeSignal(t *testing.T) {
	// An observed_runtime signal (from eBPF or process monitor) gives ClassDetects.
	sig := sdk.Signal{
		SchemaVersion: sdk.SchemaSignalV0,
		SignalID:      "runtime-001",
		Source: sdk.Source{
			Kind:        "ebpf",
			Reliability: sdk.ReliabilityObservedRuntime,
			Timing:      sdk.TimingPostExec,
		},
		ActionClaim: map[string]any{"type": "shell_exec"},
	}
	class := EnforceabilityForSignals([]sdk.Signal{sig})
	if class != kernel.ClassDetects {
		t.Errorf("enforceability = %q, want %q for runtime signal", class, kernel.ClassDetects)
	}
}

// ── CollectSignals ───────────────────────────────────────────────────────────

func TestCollectSignals_HookOnlyAlwaysReturnsOne(t *testing.T) {
	// When no signal providers are registered, exactly one signal is returned
	// (the hook signal). The registry path doesn't exist in the test temp dir.
	t.Setenv("HOME", t.TempDir())
	payload := samplePayload("Bash", map[string]any{"command": "ls"})
	signals := CollectSignals(payload, t.TempDir())
	if len(signals) == 0 {
		t.Error("CollectSignals should return at least the hook signal")
	}
	if signals[0].Source.Reliability != sdk.ReliabilityDeclaredIntent {
		t.Error("first signal should be the hook (declared_intent)")
	}
}

func TestCollectSignals_NilPayload(t *testing.T) {
	// Nil payload (no hook fired) is valid: only provider signals are collected.
	t.Setenv("HOME", t.TempDir())
	signals := CollectSignals(nil, t.TempDir())
	// No providers registered → empty is correct (not an error).
	_ = signals
}
