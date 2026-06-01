package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

func TestSelectAgentsForInstall_DefaultUsesClaudeOnly(t *testing.T) {
	home := installDetectionHome(t)
	mustMkdirAll(t, filepath.Join(home, ".claude"))
	mustMkdirAll(t, filepath.Join(home, ".gemini"))
	mustMkdirAll(t, filepath.Join(home, ".codex"))

	agents, err := selectAgentsForInstall("", false)
	if err != nil {
		t.Fatalf("selectAgentsForInstall: %v", err)
	}
	if got, want := installAgentIDs(agents), []agent.AgentID{agent.Claude}; !equalAgentIDs(got, want) {
		t.Fatalf("agent selection mismatch\nwant: %v\ngot:  %v", want, got)
	}
}

func TestSelectAgentsForInstall_DefaultRequiresEnabledTarget(t *testing.T) {
	home := installDetectionHome(t)
	mustMkdirAll(t, filepath.Join(home, ".gemini"))
	mustMkdirAll(t, filepath.Join(home, ".codex"))

	_, err := selectAgentsForInstall("", false)
	if err == nil {
		t.Fatal("expected error when only disabled agents are detected")
	}
	if got := err.Error(); got == "" || !containsAll(got, "none are enabled", "Currently enabled: Claude Code") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectAgentsForInstall_DefaultErrorsWhenNothingDetected(t *testing.T) {
	installDetectionHome(t)

	_, err := selectAgentsForInstall("", false)
	if err == nil {
		t.Fatal("expected error when no AI coding agent is detected")
	}
	if got := err.Error(); got == "" || !containsAll(got, "no AI coding agent detected on this machine", "Currently enabled: Claude Code") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectAgentsForInstall_ExplicitAgentRequiresDetection(t *testing.T) {
	installDetectionHome(t)

	_, err := selectAgentsForInstall("claude", false)
	if err == nil {
		t.Fatal("expected error when explicit agent is not detected")
	}
	if got := err.Error(); got == "" || !containsAll(got, "--agent claude requested", "Claude Code is not installed on this machine") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectAgentsForInstall_ExplicitAgentUsesDetectedSurface(t *testing.T) {
	home := installDetectionHome(t)
	mustMkdirAll(t, filepath.Join(home, ".claude"))

	agents, err := selectAgentsForInstall("claude", false)
	if err != nil {
		t.Fatalf("selectAgentsForInstall: %v", err)
	}
	if got, want := installAgentIDs(agents), []agent.AgentID{agent.Claude}; !equalAgentIDs(got, want) {
		t.Fatalf("agent selection mismatch\nwant: %v\ngot:  %v", want, got)
	}
}

func TestSelectAgentsForInstall_ExplicitUnknownAgent(t *testing.T) {
	installDetectionHome(t)

	_, err := selectAgentsForInstall("factory", false)
	if err == nil {
		t.Fatal("expected unknown agent error")
	}
	if got := err.Error(); got == "" || !containsAll(got, "unknown agent: factory", "enabled install targets:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSelectAgentsForInstall_ExplicitKnownDisabledAgent(t *testing.T) {
	home := installDetectionHome(t)
	mustMkdirAll(t, filepath.Join(home, ".gemini"))

	_, err := selectAgentsForInstall("gemini", false)
	if err == nil {
		t.Fatal("expected disabled-agent error")
	}
	if got := err.Error(); got == "" || !containsAll(got, "--agent gemini", "not enabled", "enabled install targets: claude") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func installDetectionHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	pathDir := filepath.Join(home, "bin")
	mustMkdirAll(t, pathDir)
	t.Setenv("HOME", home)
	t.Setenv("PATH", pathDir)
	return home
}

func installAgentIDs(agents []agent.Agent) []agent.AgentID {
	ids := make([]agent.AgentID, 0, len(agents))
	for _, ag := range agents {
		ids = append(ids, ag.ID())
	}
	return ids
}

func equalAgentIDs(got, want []agent.AgentID) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func containsAll(body string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(body, needle) {
			return false
		}
	}
	return true
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}
