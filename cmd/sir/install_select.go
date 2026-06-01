package main

import (
	"fmt"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/config"
)

// install_select.go is the thin I/O layer between the pure resolver
// (resolveAgentSelection in install_agents.go) and the real environment: the
// global config (remembered preference), TTY detection, and the interactive
// checklist (tui_checklist.go). Keeping the side effects here lets the
// resolution policy stay a pure, table-testable function.

// selectAgentsForInstall resolves the set of agents to install for, consulting
// (in precedence order) the explicit --agent flag, the remembered config
// preference, an interactive selector on a TTY, and finally the default enabled
// install target. The resolver filters detected agents to the currently enabled
// install set. For this testing build, that set is Claude Code. When
// suppressPrompt is true (e.g. --yes / CI), the interactive selector is skipped.
//
// It also persists the user's "remember this choice" selection to the global
// config when requested. This write is user-initiated and out-of-band of any
// agent session, so it does not route through the posture-file gate (see the
// PostureFiles note in cmdInstall).
func selectAgentsForInstall(explicit string, suppressPrompt bool) ([]agent.Agent, error) {
	remembered := loadRememberedInstallAgents()

	in := agentSelectionInputs{
		explicit:    explicit,
		remembered:  remembered,
		interactive: !suppressPrompt && isInteractiveTerminal(),
	}
	in.detected = detectInstalledAgents()
	in.selector = func(enabled []agent.Agent) ([]agent.Agent, bool, bool) {
		printDisabledInstallTargets(in.detected, enabled)
		return runAgentChecklist(enabled)
	}

	res, err := resolveAgentSelection(in)
	if err != nil {
		return nil, err
	}

	if res.rememberChoice {
		persistRememberedInstallAgents(res.agents)
	}

	return res.agents, nil
}

// loadRememberedInstallAgents returns the persisted InstallAgents preference,
// or nil when absent or unreadable. A read failure is non-fatal here: the
// preference is advisory, and resolution falls through to interactive/default
// selection.
func loadRememberedInstallAgents() []string {
	cfg, _, err := config.Load()
	if err != nil {
		// Config parse errors are surfaced elsewhere (install's posture
		// resolution calls config.Load and fatals). Don't double-report;
		// just decline to use a remembered preference.
		return nil
	}
	return cfg.InstallAgents
}

// persistRememberedInstallAgents writes the chosen installable agent IDs to the
// global config so a future bare `sir install` reuses them. Best-effort: a
// write failure prints a warning but does not abort the install in progress.
func persistRememberedInstallAgents(agents []agent.Agent) {
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Printf("  warning: could not load config to remember agent choice: %v\n", err)
		return
	}
	ids := make([]string, 0, len(agents))
	for _, ag := range agents {
		ids = append(ids, string(ag.ID()))
	}
	cfg.InstallAgents = ids
	if err := cfg.Save(); err != nil {
		fmt.Printf("  warning: could not persist remembered agent choice: %v\n", err)
		return
	}
	fmt.Printf("  Remembered: future `sir install` will target %v (clear with `sir install --forget`).\n", ids)
}

// forgetRememberedInstallAgents clears the persisted InstallAgents preference
// so a future bare `sir install` re-prompts (TTY) or falls back to the default
// Claude-only install.
func forgetRememberedInstallAgents() {
	cfg, _, err := config.Load()
	if err != nil {
		fatal("load config: %v", err)
	}
	if len(cfg.InstallAgents) == 0 {
		fmt.Println("No remembered agent preference to clear.")
		return
	}
	prev := cfg.InstallAgents
	cfg.InstallAgents = nil
	if err := cfg.Save(); err != nil {
		fatal("clear remembered agent choice: %v", err)
	}
	fmt.Printf("Cleared remembered agent preference (was %v).\n", prev)
}

func printDisabledInstallTargets(detected, enabled []agent.Agent) {
	names := disabledInstallTargetNames(detected, enabled)
	if len(names) == 0 {
		return
	}
	fmt.Printf("Detected but disabled for hook install in this build: %s\n\n", strings.Join(names, ", "))
}

func disabledInstallTargetNames(detected, enabled []agent.Agent) []string {
	enabledIDs := make(map[agent.AgentID]struct{}, len(enabled))
	for _, ag := range enabled {
		if ag == nil {
			continue
		}
		enabledIDs[ag.ID()] = struct{}{}
	}
	var names []string
	for _, ag := range detected {
		if ag == nil {
			continue
		}
		if _, ok := enabledIDs[ag.ID()]; ok {
			continue
		}
		names = append(names, ag.Name())
	}
	return names
}

// runAgentChecklist drives the interactive checklist over the installable
// detected agents and maps the result back to the resolver's selector contract.
// The last row is a synthetic "Remember this choice" toggle, not an agent.
func runAgentChecklist(detected []agent.Agent) (chosen []agent.Agent, remember bool, confirmed bool) {
	items := make([]checklistItem, 0, len(detected)+1)
	for _, ag := range detected {
		items = append(items, checklistItem{
			Label:   ag.Name(),
			Detail:  ag.ConfigPath(),
			Checked: ag.ID() == agent.Claude,
		})
	}
	rememberIdx := len(items)
	items = append(items, checklistItem{
		Label:   "Remember this choice for future installs",
		Checked: false,
	})

	picked, ok := runChecklist("Which AI coding agents should sir protect?", items)
	if !ok {
		return nil, false, false
	}

	for _, i := range picked {
		if i == rememberIdx {
			remember = true
			continue
		}
		chosen = append(chosen, detected[i])
	}
	return chosen, remember, true
}
