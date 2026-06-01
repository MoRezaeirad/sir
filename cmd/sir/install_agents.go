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

func supportedInstallAgentIDs() string {
	return string(agent.Claude)
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
// absent so the install path can resolve the configured/default agent set.
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
	withProviders []string // --with-provider <manifest.yaml> (repeatable)
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
		case a == "--with-provider" && i+1 < len(args):
			opts.withProviders = append(opts.withProviders, args[i+1])
			i++
		case strings.HasPrefix(a, "--with-provider="):
			opts.withProviders = append(opts.withProviders, strings.TrimPrefix(a, "--with-provider="))
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
	case agent.Cursor:
		return map[mcpConfigScope]bool{mcpConfigCursorProject: true, mcpConfigCursorGlobal: true}
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
	// interactive=true is treated as "no selection made" (fall through to the
	// non-interactive default) so tests can exercise the resolver without a
	// terminal.
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
//     remembered IDs that are still detected and installable on this machine.
//     Unknown, no-longer-installed, or non-installable remembered IDs are
//     dropped; if none survive, fall through to selection.
//  3. Interactive selector (TTY only): let the user pick from the currently
//     enabled protection targets and optionally remember it.
//  4. Default install: protect Claude Code when it is detected. Other
//     adapters are still detected and supported for payload parsing/status, but
//     hook installation is not enabled for them in this build.
//
// Returns an operator-facing error when nothing can be resolved (no agents
// detected, or an explicit/remembered selection resolves to the empty set in
// a way the user must fix).
func resolveAgentSelection(in agentSelectionInputs) (agentSelectionResult, error) {
	if in.explicit != "" {
		if agent.AgentID(in.explicit) != agent.Claude {
			if agent.ForID(agent.AgentID(in.explicit)) == nil {
				return agentSelectionResult{}, fmt.Errorf("unknown agent: %s (enabled install targets: %s; known adapters: %s)", in.explicit, supportedInstallAgentIDs(), supportedAgentIDs())
			}
			return agentSelectionResult{}, fmt.Errorf("--agent %s is detected/supported, but hook protection is not enabled for it in this build (enabled install targets: %s)", in.explicit, supportedInstallAgentIDs())
		}
		ag := agent.ForID(agent.AgentID(in.explicit))
		if ag == nil {
			return agentSelectionResult{}, fmt.Errorf("unknown agent: %s (enabled install targets: %s)", in.explicit, supportedInstallAgentIDs())
		}
		if !ag.DetectInstallation() {
			return agentSelectionResult{}, fmt.Errorf("--agent %s requested but %s is not installed on this machine.\n  Install %s first, then re-run sir install.", in.explicit, ag.Name(), ag.Name())
		}
		return agentSelectionResult{agents: []agent.Agent{ag}}, nil
	}

	detected := filterInstallableAgents(in.detected)
	if len(detected) == 0 {
		if len(in.detected) == 0 {
			return agentSelectionResult{}, fmt.Errorf("no AI coding agent detected on this machine.\n  Install an enabled agent target, then re-run sir install. Currently enabled: Claude Code.")
		}
		return agentSelectionResult{}, fmt.Errorf("AI coding agents were detected, but none are enabled for hook protection in this build.\n  Currently enabled: Claude Code. Install Claude Code, then re-run sir install.")
	}

	if remembered := filterDetectedByIDs(detected, in.remembered); len(remembered) > 0 {
		return agentSelectionResult{agents: remembered}, nil
	}

	if in.interactive && in.selector != nil {
		chosen, remember, confirmed := in.selector(detected)
		if confirmed {
			if len(chosen) == 0 {
				return agentSelectionResult{}, fmt.Errorf("no agents selected. Re-run `sir install` and select Claude Code with Space, or pass --agent claude.")
			}
			return agentSelectionResult{agents: chosen, rememberChoice: remember}, nil
		}
		// User cancelled the selector: fall through to the deterministic
		// default so the safe default still applies rather than aborting the
		// install.
	}

	if defaults := defaultInstallAgents(detected); len(defaults) > 0 {
		return agentSelectionResult{agents: defaults}, nil
	}

	return agentSelectionResult{}, fmt.Errorf("no enabled protection target detected.\n  Currently enabled: Claude Code.")
}

func defaultInstallAgents(detected []agent.Agent) []agent.Agent {
	for _, ag := range detected {
		if ag.ID() == agent.Claude {
			return []agent.Agent{ag}
		}
	}
	return nil
}

func isInstallableAgent(ag agent.Agent) bool {
	return ag != nil && ag.ID() == agent.Claude
}

func filterInstallableAgents(detected []agent.Agent) []agent.Agent {
	out := make([]agent.Agent, 0, len(detected))
	for _, ag := range detected {
		if isInstallableAgent(ag) {
			out = append(out, ag)
		}
	}
	return out
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
