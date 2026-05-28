package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// envReadPayload builds a PreToolUse payload reading a seeded .env (a sensitive
// path), which the default policy gates with an interactive ask.
func envReadPayload(t *testing.T, projectRoot string) *HookPayload {
	t.Helper()
	if err := os.WriteFile(filepath.Join(projectRoot, ".env"), []byte("API_KEY=shh\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	return &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": filepath.Join(projectRoot, ".env")},
		CWD:       projectRoot,
	}
}

func writeThinkingSettings(t *testing.T, dir string) {
	t.Helper()
	claudeDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"alwaysThinkingEnabled": true}`), 0o644); err != nil {
		t.Fatalf("write settings: %v", err)
	}
}

// isolateHome points os.UserHomeDir at a clean temp dir so a real
// ~/.claude/settings.json on the test machine can't leak a thinking signal in.
func isolateHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

func TestThinkingGuard_DegradesAskToDenyWhenSettingEnabled(t *testing.T) {
	isolateHome(t)
	projectRoot := t.TempDir()
	writeThinkingSettings(t, projectRoot)
	state := newTestSession(t, projectRoot)
	payload := envReadPayload(t, projectRoot)

	resp, err := evaluatePayload(payload, lease.DefaultLease(), state, projectRoot, agent.NewClaudeAgent())
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("expected ask to degrade to deny under thinking, got %s", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "thinking") {
		t.Errorf("deny reason should explain the thinking guard, got: %s", resp.Reason)
	}
	// The ledger must record the degraded deny, not the policy's ask, so
	// `sir explain`/`sir why` match what the agent actually saw.
	if e := lastDecision(t, projectRoot); e.Decision != "deny" {
		t.Errorf("ledger decision = %q, want deny", e.Decision)
	}
}

func TestThinkingGuard_KeepsAskWhenThinkingDisabled(t *testing.T) {
	isolateHome(t)
	projectRoot := t.TempDir()
	state := newTestSession(t, projectRoot)
	payload := envReadPayload(t, projectRoot)

	resp, err := evaluatePayload(payload, lease.DefaultLease(), state, projectRoot, agent.NewClaudeAgent())
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("expected ask to be preserved when thinking is off, got %s", resp.Decision)
	}
}

func TestThinkingGuard_DetectsThinkingViaTranscript(t *testing.T) {
	isolateHome(t)
	projectRoot := t.TempDir()
	transcript := filepath.Join(projectRoot, "transcript.jsonl")
	line := `{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"..."},{"type":"tool_use","name":"Read"}]}}` + "\n"
	if err := os.WriteFile(transcript, []byte(line), 0o644); err != nil {
		t.Fatalf("write transcript: %v", err)
	}
	state := newTestSession(t, projectRoot)
	payload := envReadPayload(t, projectRoot)
	payload.TranscriptPath = transcript

	resp, err := evaluatePayload(payload, lease.DefaultLease(), state, projectRoot, agent.NewClaudeAgent())
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("expected transcript thinking blocks to degrade ask to deny, got %s", resp.Decision)
	}
}

func TestThinkingGuard_OnlyAppliesToClaude(t *testing.T) {
	isolateHome(t)
	projectRoot := t.TempDir()
	writeThinkingSettings(t, projectRoot)
	state := newTestSession(t, projectRoot)
	payload := envReadPayload(t, projectRoot)

	// No agent passed: the guard requires the Claude adapter, so the ask stands.
	resp, err := evaluatePayload(payload, lease.DefaultLease(), state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("guard must not fire without the Claude adapter, got %s", resp.Decision)
	}
}

// subagentAskState seeds a session whose posture forces SubagentStart to ask
// (tainted MCP + critical posture), with a clean posture-integrity baseline so
// the ask path — not deny-all — is the one exercised.
func subagentAskState(t *testing.T, projectRoot string) {
	t.Helper()
	state := newTestSession(t, projectRoot)
	state.PostureHashes = HashSentinelFiles(projectRoot, lease.DefaultLease().PostureFiles)
	state.AddTaintedMCPServer("jira")
	state.RaisePosture(policy.PostureStateCritical)
	if err := state.Save(); err != nil {
		t.Fatalf("save session: %v", err)
	}
}

func subagentWireDecision(t *testing.T, out []byte) string {
	t.Helper()
	var resp struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal subagent response %q: %v", out, err)
	}
	return resp.HookSpecificOutput.PermissionDecision
}

func TestThinkingGuard_DegradesSubagentAsk(t *testing.T) {
	isolateHome(t)
	projectRoot := t.TempDir()
	subagentAskState(t, projectRoot)
	transcript := filepath.Join(projectRoot, "t.jsonl")
	if err := os.WriteFile(transcript, []byte(`{"type":"assistant","message":{"content":[{"type":"thinking"}]}}`+"\n"), 0o644); err != nil {
		t.Fatalf("write transcript: %v", err)
	}

	out, err := runSubagentStartForTest(t, projectRoot, SubagentPayload{
		HookEventName:  "SubagentStart",
		AgentName:      "general-purpose",
		Tools:          []string{"Read"},
		CWD:            projectRoot,
		TranscriptPath: transcript,
	})
	if err != nil {
		t.Fatalf("EvaluateSubagentStart: %v", err)
	}
	if d := subagentWireDecision(t, out); d != "deny" {
		t.Errorf("subagent wire decision = %q, want deny", d)
	}
	if e := lastDecision(t, projectRoot); e.Decision != "deny" {
		t.Errorf("subagent ledger decision = %q, want deny", e.Decision)
	}
}

func TestThinkingGuard_SubagentAskPreservedWithoutThinking(t *testing.T) {
	isolateHome(t)
	projectRoot := t.TempDir()
	subagentAskState(t, projectRoot)

	out, err := runSubagentStartForTest(t, projectRoot, SubagentPayload{
		HookEventName: "SubagentStart",
		AgentName:     "general-purpose",
		Tools:         []string{"Read"},
		CWD:           projectRoot,
	})
	if err != nil {
		t.Fatalf("EvaluateSubagentStart: %v", err)
	}
	if d := subagentWireDecision(t, out); d != "ask" {
		t.Errorf("subagent wire decision = %q, want ask", d)
	}
	if e := lastDecision(t, projectRoot); e.Decision != "ask" {
		t.Errorf("subagent ledger decision = %q, want ask", e.Decision)
	}
}

func TestThinkingGuard_ObserveModeStillWins(t *testing.T) {
	isolateHome(t)
	projectRoot := t.TempDir()
	writeThinkingSettings(t, projectRoot)
	l := lease.DefaultLease()
	l.ObserveOnly = true
	state := newTestSession(t, projectRoot)
	payload := envReadPayload(t, projectRoot)

	resp, err := evaluatePayload(payload, l, state, projectRoot, agent.NewClaudeAgent())
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("observe mode must downgrade the guarded deny to allow, got %s", resp.Decision)
	}
	// Ledger reflects the degraded deny in its observe form.
	if e := lastDecision(t, projectRoot); e.Decision != "would_deny" {
		t.Errorf("observe ledger decision = %q, want would_deny", e.Decision)
	}
}
