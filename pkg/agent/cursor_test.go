package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func loadCursorFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cursor", name))
	if err != nil {
		t.Fatalf("read cursor fixture %s: %v", name, err)
	}
	return raw
}

func TestCursorAgent_ParseBeforeShellExecution(t *testing.T) {
	c := NewCursorAgent()
	p, err := c.ParsePreToolUse(loadCursorFixture(t, "before-shell-execution.json"))
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.AgentID != Cursor {
		t.Fatalf("AgentID = %q, want %q", p.AgentID, Cursor)
	}
	if p.SessionID != "conv_cursor_123" {
		t.Fatalf("SessionID = %q", p.SessionID)
	}
	if p.HookEventName != "PreToolUse" || p.ToolName != "Bash" {
		t.Fatalf("normalized event/tool = %q/%q", p.HookEventName, p.ToolName)
	}
	if got, _ := p.ToolInput["command"].(string); got != "go test ./pkg/agent" {
		t.Fatalf("command = %q", got)
	}
}

func TestCursorAgent_ParseMCPExecution(t *testing.T) {
	c := NewCursorAgent()
	p, err := c.ParsePreToolUse(loadCursorFixture(t, "before-mcp-execution.json"))
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.ToolName != "mcp__github__search_issues" {
		t.Fatalf("ToolName = %q", p.ToolName)
	}
	if _, ok := p.ToolInput["args"].(map[string]interface{}); !ok {
		t.Fatalf("args not preserved as map: %#v", p.ToolInput["args"])
	}
}

func TestCursorAgent_ParsePostOutput(t *testing.T) {
	c := NewCursorAgent()
	p, err := c.ParsePostToolUse(loadCursorFixture(t, "after-shell-execution.json"))
	if err != nil {
		t.Fatalf("ParsePostToolUse: %v", err)
	}
	if p.HookEventName != "PostToolUse" || p.ToolName != "Bash" {
		t.Fatalf("normalized event/tool = %q/%q", p.HookEventName, p.ToolName)
	}
	if p.ToolOutput != "hello\n" {
		t.Fatalf("ToolOutput = %q", p.ToolOutput)
	}
}

func TestCursorAgent_ParsePostFailureOutput(t *testing.T) {
	c := NewCursorAgent()
	p, err := c.ParsePostToolUse(loadCursorFixture(t, "post-tool-use-failure.json"))
	if err != nil {
		t.Fatalf("ParsePostToolUse: %v", err)
	}
	if p.HookEventName != "PostToolUse" || p.ToolName != "Bash" {
		t.Fatalf("normalized event/tool = %q/%q", p.HookEventName, p.ToolName)
	}
	if p.ToolOutput != "exit status 1\n" {
		t.Fatalf("ToolOutput = %q", p.ToolOutput)
	}
}

func TestCursorAgent_FormatPreToolUseResponse(t *testing.T) {
	c := NewCursorAgent()
	allow, err := c.FormatPreToolUseResponse("allow", "ok")
	if err != nil {
		t.Fatalf("allow format: %v", err)
	}
	if string(allow) != "{}" {
		t.Fatalf("allow response = %q", allow)
	}

	ask, err := c.FormatPreToolUseResponse("ask", "network approval needed")
	if err != nil {
		t.Fatalf("ask format: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(ask, &resp); err != nil {
		t.Fatalf("unmarshal ask response: %v", err)
	}
	if resp["permission"] != "deny" {
		t.Fatalf("permission = %v, want deny", resp["permission"])
	}
	reason, _ := resp["user_message"].(string)
	if !strings.Contains(reason, "network approval needed") || !strings.Contains(reason, "sir allow-host") {
		t.Fatalf("ask remediation missing: %q", reason)
	}
}

func TestCursorAgent_GenerateHooksConfigShape(t *testing.T) {
	c := NewCursorAgent()
	raw, err := c.GenerateHooksConfig("/usr/local/bin/sir", "guard")
	if err != nil {
		t.Fatalf("GenerateHooksConfig: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["version"].(float64) != 1 {
		t.Fatalf("version = %v", doc["version"])
	}
	hooks := doc["hooks"].(map[string]interface{})
	for _, event := range []string{"beforeShellExecution", "afterShellExecution", "beforeMCPExecution", "afterMCPExecution", "beforeReadFile", "afterFileEdit", "postToolUseFailure", "sessionStart"} {
		arr, ok := hooks[event].([]interface{})
		if !ok || len(arr) == 0 {
			t.Fatalf("hooks[%s] missing", event)
		}
		entry := arr[0].(map[string]interface{})
		cmd, _ := entry["command"].(string)
		if !strings.Contains(cmd, "/usr/local/bin/sir guard ") || !strings.Contains(cmd, "--agent cursor") {
			t.Fatalf("bad command for %s: %q", event, cmd)
		}
		if entry["failClosed"] != true {
			t.Fatalf("failClosed missing for %s: %#v", event, entry)
		}
	}
}

func TestCursorAgent_DetectInstallation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("PATH", filepath.Join(tmp, "bin"))
	c := NewCursorAgent()
	if c.DetectInstallation() {
		t.Skip("cursor binary is visible despite test PATH; host-specific smoke not useful")
	}
	if err := os.MkdirAll(filepath.Join(tmp, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !c.DetectInstallation() {
		t.Fatal("DetectInstallation() = false after creating ~/.cursor")
	}
	if _, err := exec.LookPath("cursor-agent"); err == nil {
		t.Log("cursor-agent exists on host PATH outside test env")
	}
}

func TestForID_Cursor(t *testing.T) {
	a := ForID(Cursor)
	if a == nil {
		t.Fatal("ForID(Cursor) = nil")
	}
	if _, ok := a.(*CursorAgent); !ok {
		t.Fatalf("ForID(Cursor) returned %T", a)
	}
}
