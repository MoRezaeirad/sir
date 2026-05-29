package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/somoore/sir/pkg/agent"
)

func supportedAgentIDs() string {
	ids := make([]string, 0, len(agent.Registry()))
	for _, reg := range agent.Registry() {
		ids = append(ids, string(reg.ID))
	}
	return strings.Join(ids, ", ")
}

func mustHomeDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fatal("get home dir: %v", err)
	}
	return homeDir
}

// parseInstallAgentFlag scans install/uninstall args for --agent <id> or
// --agent=<id>. Unlike parseAgentFlag (cmd/sir/main.go) which defaults to
// "claude" for guard dispatch, this variant returns "" when the flag is
// absent so the install path can auto-detect all available agents.
func parseInstallAgentFlag(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--agent" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "--agent=") {
			return strings.TrimPrefix(a, "--agent=")
		}
	}
	return ""
}

type installOptions struct {
	explicitAgent string
	skipPreview   bool
	noRebaseline  bool
	global        bool
	forget        bool
}

func parseInstallOptions(args []string) installOptions {
	opts := installOptions{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes":
			opts.skipPreview = true
		case a == "--no-rebaseline":
			opts.noRebaseline = true
		case a == "--global":
			opts.global = true
		case a == "--forget":
			opts.forget = true
		case a == "--agent" && i+1 < len(args):
			opts.explicitAgent = args[i+1]
			i++
		case strings.HasPrefix(a, "--agent="):
			opts.explicitAgent = strings.TrimPrefix(a, "--agent=")
		}
	}
	return opts
}

func mcpScopesForAgent(explicitAgent string) map[mcpConfigScope]bool {
	if explicitAgent == "" {
		return nil
	}
	switch agent.AgentID(explicitAgent) {
	case agent.Claude:
		return map[mcpConfigScope]bool{mcpConfigClaudeGlobal: true}
	case agent.Gemini:
		return map[mcpConfigScope]bool{mcpConfigGeminiGlobal: true}
	default:
		return map[mcpConfigScope]bool{}
	}
}

// wizardMCPScope returns the MCP discovery scope for a wizard install over a
// chosen set of agents: the union of each agent's scope PLUS the project-local
// `.mcp.json`. The project-local seed is mandatory and load-bearing — the
// wizard always installs *in* a project, and per-agent scoping
// (mcpScopesForAgent) deliberately omits project-local, so without this seed a
// wizard install would wrap the agents' global MCP servers but leave project
// servers raw/undiscovered.
//
// Crucially this never returns nil. A nil scope means scopeAllowed() permits
// EVERY scope — including unchosen agents' globals — which would silently
// widen which surfaces get rewritten. The explicit {ProjectLocal} seed
// guarantees a non-nil map even for a Codex-only selection (Codex contributes
// no scopes today), so an unchosen agent's global config is never touched.
func wizardMCPScope(agents []agent.Agent) map[mcpConfigScope]bool {
	scopes := map[mcpConfigScope]bool{mcpConfigProjectLocal: true}
	for _, ag := range agents {
		for s := range mcpScopesForAgent(string(ag.ID())) {
			scopes[s] = true
		}
	}
	return scopes
}

func detectInstalledAgents() []agent.Agent {
	var agents []agent.Agent
	for _, reg := range agent.Registry() {
		ag := reg.New()
		if ag.DetectInstallation() {
			agents = append(agents, ag)
		}
	}
	return agents
}

// agentSelectionInputs carries the resolution policy's inputs so it can be
// unit-tested without a TTY or the config file. The thin wrapper
// selectAgentsForInstall populates it from the real environment. (The
// resolver is pure over these inputs for every path except the explicit
// --agent branch, which must validate the requested ID against the real
// registry and host installation — see resolveAgentSelection.)
type agentSelectionInputs struct {
	// explicit is the value of --agent (empty when absent).
	explicit string
	// remembered is the persisted InstallAgents preference (config), nil/empty
	// when there is no remembered choice.
	remembered []string
	// detected is the set of agents found installed on this machine, in
	// deterministic registry order.
	detected []agent.Agent
	// interactive reports whether an interactive selector is available
	// (TTY present and the caller has not suppressed prompting via --yes).
	interactive bool
	// selector, when non-nil, is invoked to run the interactive multi-select.
	// It receives the detected agents and returns the chosen subset plus
	// whether the user asked to remember the choice. A nil selector with
	// interactive=true is treated as "no selection made" (fall through to
	// auto-detect-all) so tests can exercise the resolver without a terminal.
	selector func(detected []agent.Agent) (chosen []agent.Agent, remember bool, confirmed bool)
}

// agentSelectionResult is the resolved outcome.
type agentSelectionResult struct {
	agents []agent.Agent
	// rememberChoice is true when the user asked to persist the selection.
	rememberChoice bool
}

// resolveAgentSelection is the pure resolution policy. Order of precedence:
//
//  1. Explicit --agent: use exactly that one adapter. Fail-closed if unknown
//     or not detected — never silently fall back to a different agent. An
//     explicit flag always wins over any remembered preference.
//  2. Remembered preference (config InstallAgents): use those of the
//     remembered IDs that are still detected on this machine. Unknown or
//     no-longer-installed remembered IDs are dropped with the rest still
//     honored; if none survive, fall through to selection.
//  3. Interactive selector (TTY only): let the user pick a subset and
//     optionally remember it.
//  4. Auto-detect-all: install for every detected agent (today's default,
//     and the non-interactive / CI fallback).
//
// Returns an operator-facing error when nothing can be resolved (no agents
// detected, or an explicit/remembered selection resolves to the empty set in
// a way the user must fix).
func resolveAgentSelection(in agentSelectionInputs) (agentSelectionResult, error) {
	if in.explicit != "" {
		ag := agent.ForID(agent.AgentID(in.explicit))
		if ag == nil {
			return agentSelectionResult{}, fmt.Errorf("unknown agent: %s (supported: %s)", in.explicit, supportedAgentIDs())
		}
		if !ag.DetectInstallation() {
			return agentSelectionResult{}, fmt.Errorf("--agent %s requested but %s is not installed on this machine.\n  Install %s first, then re-run sir install.", in.explicit, ag.Name(), ag.Name())
		}
		return agentSelectionResult{agents: []agent.Agent{ag}}, nil
	}

	if len(in.detected) == 0 {
		return agentSelectionResult{}, fmt.Errorf("no supported agents detected on this machine.\n  Install Claude Code, Gemini CLI, or Codex, then re-run sir install.\n  To pin one surface explicitly later, use --agent <%s> once that agent is present.", supportedAgentIDs())
	}

	if remembered := filterDetectedByIDs(in.detected, in.remembered); len(remembered) > 0 {
		return agentSelectionResult{agents: remembered}, nil
	}

	if in.interactive && in.selector != nil {
		chosen, remember, confirmed := in.selector(in.detected)
		if confirmed {
			if len(chosen) == 0 {
				return agentSelectionResult{}, fmt.Errorf("no agents selected. Re-run `sir install` and select at least one with Space, or pass --agent <id>.")
			}
			return agentSelectionResult{agents: chosen, rememberChoice: remember}, nil
		}
		// User cancelled the selector: fall through to auto-detect-all so the
		// safe default still applies rather than aborting the install.
	}

	return agentSelectionResult{agents: in.detected}, nil
}

// filterDetectedByIDs returns the detected agents whose IDs appear in ids,
// preserving detected (registry) order. Unknown or no-longer-detected IDs in
// ids are silently dropped — the remembered preference is advisory, not a
// trust anchor.
func filterDetectedByIDs(detected []agent.Agent, ids []string) []agent.Agent {
	if len(ids) == 0 {
		return nil
	}
	want := make(map[agent.AgentID]struct{}, len(ids))
	for _, id := range ids {
		want[agent.AgentID(id)] = struct{}{}
	}
	var out []agent.Agent
	for _, ag := range detected {
		if _, ok := want[ag.ID()]; ok {
			out = append(out, ag)
		}
	}
	return out
}
