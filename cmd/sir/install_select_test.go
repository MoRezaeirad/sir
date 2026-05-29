package main

import (
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

// agentsFromIDs builds a detected-agents slice from the real registry so the
// resolver sees genuine agent.Agent values (ID/Name/ConfigPath) without
// touching the host machine.
func agentsFromIDs(t *testing.T, ids ...agent.AgentID) []agent.Agent {
	t.Helper()
	var out []agent.Agent
	for _, id := range ids {
		ag := agent.ForID(id)
		if ag == nil {
			t.Fatalf("registry has no agent for %q", id)
		}
		out = append(out, ag)
	}
	return out
}

func idsOf(agents []agent.Agent) []agent.AgentID {
	out := make([]agent.AgentID, 0, len(agents))
	for _, a := range agents {
		out = append(out, a.ID())
	}
	return out
}

func equalIDs(got []agent.Agent, want []agent.AgentID) bool {
	g := idsOf(got)
	if len(g) != len(want) {
		return false
	}
	for i := range g {
		if g[i] != want[i] {
			return false
		}
	}
	return true
}

// TestResolveAgentSelection_RememberedPreferenceWins verifies a remembered
// config preference narrows the install set to the remembered-and-detected
// intersection, in registry order, without prompting.
func TestResolveAgentSelection_RememberedPreferenceWins(t *testing.T) {
	detected := agentsFromIDs(t, agent.Claude, agent.Codex, agent.Gemini)
	res, err := resolveAgentSelection(agentSelectionInputs{
		remembered:  []string{"gemini", "claude"},
		detected:    detected,
		interactive: true, // selector must NOT run when a remembered pref hits
		selector: func([]agent.Agent) ([]agent.Agent, bool, bool) {
			t.Fatal("selector should not run when a remembered preference resolves")
			return nil, false, false
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Registry order is claude, codex, gemini → remembered {gemini,claude}
	// filters to [claude, gemini].
	if !equalIDs(res.agents, []agent.AgentID{agent.Claude, agent.Gemini}) {
		t.Errorf("got %v, want [claude gemini]", idsOf(res.agents))
	}
	if res.rememberChoice {
		t.Error("rememberChoice must be false when reusing an existing preference")
	}
}

// TestResolveAgentSelection_RememberedDropsUninstalled verifies that a
// remembered ID no longer detected on the machine is silently dropped, and the
// surviving remembered agents are still honored.
func TestResolveAgentSelection_RememberedDropsUninstalled(t *testing.T) {
	detected := agentsFromIDs(t, agent.Claude) // only claude present now
	res, err := resolveAgentSelection(agentSelectionInputs{
		remembered: []string{"gemini", "claude"}, // gemini no longer installed
		detected:   detected,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalIDs(res.agents, []agent.AgentID{agent.Claude}) {
		t.Errorf("got %v, want [claude]", idsOf(res.agents))
	}
}

// TestResolveAgentSelection_RememberedAllGoneFallsToAuto verifies that when no
// remembered ID is still detected, resolution falls through (here, to
// auto-detect-all because interactive is false).
func TestResolveAgentSelection_RememberedAllGoneFallsToAuto(t *testing.T) {
	detected := agentsFromIDs(t, agent.Codex)
	res, err := resolveAgentSelection(agentSelectionInputs{
		remembered:  []string{"gemini"}, // not detected
		detected:    detected,
		interactive: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalIDs(res.agents, []agent.AgentID{agent.Codex}) {
		t.Errorf("got %v, want [codex] (auto-detect-all fallback)", idsOf(res.agents))
	}
}

// TestResolveAgentSelection_NonInteractiveAutoDetectsAll pins the CI / --yes /
// piped fallback: no prompt, install for every detected agent. This is the
// behavior that must not regress.
func TestResolveAgentSelection_NonInteractiveAutoDetectsAll(t *testing.T) {
	detected := agentsFromIDs(t, agent.Claude, agent.Codex, agent.Gemini)
	res, err := resolveAgentSelection(agentSelectionInputs{
		detected:    detected,
		interactive: false,
		selector: func([]agent.Agent) ([]agent.Agent, bool, bool) {
			t.Fatal("selector must not run when non-interactive")
			return nil, false, false
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalIDs(res.agents, []agent.AgentID{agent.Claude, agent.Codex, agent.Gemini}) {
		t.Errorf("got %v, want all detected", idsOf(res.agents))
	}
}

// TestResolveAgentSelection_InteractivePickSubsetAndRemember verifies that an
// interactive selection narrows the set and propagates the remember flag.
func TestResolveAgentSelection_InteractivePickSubsetAndRemember(t *testing.T) {
	detected := agentsFromIDs(t, agent.Claude, agent.Codex, agent.Gemini)
	res, err := resolveAgentSelection(agentSelectionInputs{
		detected:    detected,
		interactive: true,
		selector: func(d []agent.Agent) ([]agent.Agent, bool, bool) {
			// Pick claude + gemini, ask to remember.
			return []agent.Agent{d[0], d[2]}, true, true
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalIDs(res.agents, []agent.AgentID{agent.Claude, agent.Gemini}) {
		t.Errorf("got %v, want [claude gemini]", idsOf(res.agents))
	}
	if !res.rememberChoice {
		t.Error("rememberChoice must propagate from the selector")
	}
}

// TestResolveAgentSelection_InteractiveCancelFallsToAuto verifies that
// cancelling the selector (confirmed=false) does not abort — it falls back to
// the safe auto-detect-all default.
func TestResolveAgentSelection_InteractiveCancelFallsToAuto(t *testing.T) {
	detected := agentsFromIDs(t, agent.Claude, agent.Codex)
	res, err := resolveAgentSelection(agentSelectionInputs{
		detected:    detected,
		interactive: true,
		selector: func([]agent.Agent) ([]agent.Agent, bool, bool) {
			return nil, false, false // cancelled
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !equalIDs(res.agents, []agent.AgentID{agent.Claude, agent.Codex}) {
		t.Errorf("cancel should fall back to auto-detect-all, got %v", idsOf(res.agents))
	}
}

// TestResolveAgentSelection_InteractiveEmptyConfirmIsError verifies that
// confirming with zero agents selected is a user-fixable error, not a silent
// no-op install.
func TestResolveAgentSelection_InteractiveEmptyConfirmIsError(t *testing.T) {
	detected := agentsFromIDs(t, agent.Claude)
	_, err := resolveAgentSelection(agentSelectionInputs{
		detected:    detected,
		interactive: true,
		selector: func([]agent.Agent) ([]agent.Agent, bool, bool) {
			return nil, false, true // confirmed but nothing selected
		},
	})
	if err == nil {
		t.Fatal("expected an error when confirming with no agents selected")
	}
}

// TestResolveAgentSelection_NoDetectedAgentsErrors pins the operator-facing
// error when nothing is installed.
func TestResolveAgentSelection_NoDetectedAgentsErrors(t *testing.T) {
	_, err := resolveAgentSelection(agentSelectionInputs{detected: nil})
	if err == nil {
		t.Fatal("expected an error when no agents are detected")
	}
}

// TestResolveAgentSelection_UnknownExplicitErrors verifies the explicit-flag
// fail-closed path for an unknown agent ID (does not touch the host).
func TestResolveAgentSelection_UnknownExplicitErrors(t *testing.T) {
	_, err := resolveAgentSelection(agentSelectionInputs{
		explicit: "not-a-real-agent",
		detected: agentsFromIDs(t, agent.Claude),
	})
	if err == nil {
		t.Fatal("expected an error for an unknown --agent value")
	}
}

// TestWizardMCPScope_IncludesProjectLocalAndOnlyChosenGlobals is the gate for
// the P1 fix: a wizard install over a chosen agent set must discover the
// project-local `.mcp.json` (so project MCP servers get wrapped/approved like
// a bare `sir install`) while NOT touching an unchosen agent's global MCP
// surface.
func TestWizardMCPScope_IncludesProjectLocalAndOnlyChosenGlobals(t *testing.T) {
	// Claude chosen, Gemini NOT chosen.
	s := wizardMCPScope(agentsFromIDs(t, agent.Claude))

	// Property 1: project-local IS in scope.
	if !s[mcpConfigProjectLocal] {
		t.Error("wizard scope must include project-local .mcp.json")
	}
	// The chosen agent's global IS in scope.
	if !s[mcpConfigClaudeGlobal] {
		t.Error("wizard scope must include the chosen agent's global (claude)")
	}
	// Property 2: an unchosen agent's global is NOT in scope.
	if s[mcpConfigGeminiGlobal] {
		t.Error("wizard scope must NOT include an unchosen agent's global (gemini)")
	}

	// Both chosen → both globals present, project-local present.
	both := wizardMCPScope(agentsFromIDs(t, agent.Claude, agent.Gemini))
	if !both[mcpConfigClaudeGlobal] || !both[mcpConfigGeminiGlobal] || !both[mcpConfigProjectLocal] {
		t.Errorf("both-chosen scope incomplete: %v", both)
	}
}

// TestWizardMCPScope_CodexOnlyNeverCollapsesToNil pins the nil-collapse guard:
// Codex contributes no scopes today, but the scope must still be a non-nil
// {ProjectLocal} — never nil, which scopeAllowed treats as "all scopes
// allowed" and would silently widen rewriting to unchosen agents' globals.
func TestWizardMCPScope_CodexOnlyNeverCollapsesToNil(t *testing.T) {
	s := wizardMCPScope(agentsFromIDs(t, agent.Codex))
	if s == nil {
		t.Fatal("wizard scope must never be nil (nil = all scopes allowed)")
	}
	if !s[mcpConfigProjectLocal] {
		t.Error("codex-only wizard scope must still include project-local")
	}
	// No global surfaces for a codex-only selection.
	if s[mcpConfigClaudeGlobal] || s[mcpConfigGeminiGlobal] {
		t.Errorf("codex-only scope must not include any agent globals, got %v", s)
	}
	if len(s) != 1 {
		t.Errorf("codex-only scope should be exactly {ProjectLocal}, got %v", s)
	}
}

func TestFilterDetectedByIDs_PreservesRegistryOrder(t *testing.T) {
	detected := agentsFromIDs(t, agent.Claude, agent.Codex, agent.Gemini)
	// IDs given out of order; result must follow detected (registry) order.
	got := filterDetectedByIDs(detected, []string{"gemini", "codex"})
	if !equalIDs(got, []agent.AgentID{agent.Codex, agent.Gemini}) {
		t.Errorf("got %v, want [codex gemini]", idsOf(got))
	}
	if filterDetectedByIDs(detected, nil) != nil {
		t.Error("empty ids must return nil")
	}
	if got := filterDetectedByIDs(detected, []string{"bogus"}); got != nil {
		t.Errorf("unknown id must filter to nil, got %v", idsOf(got))
	}
}
