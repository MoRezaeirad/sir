package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/provider"
)

// configure.go — `sir config` / `sir configure` guided setup flow.
//
// Design goals: frictionless, honest, minimal.
//   1. Discover all known AI coding agents on this machine.
//   2. Offer a checklist for currently enabled protection targets. For this
//      testing phase that is Claude Code. Other adapters are still detected and
//      shown, but disabled for hook installation in this build.
//   3. Install global hooks for selected enabled agents, show a receipt.
//   4. Show registered provider status; skip cleanly when none registered.
//
// Unlike `sir wizard`, there is no repo-scope picker: hooks are global
// (they fire in every repo once installed). Frictionless means no extra
// questions that don't change the outcome.

// agentProbe describes an AI coding agent sir knows about for discovery
// purposes. supported=true means a full adapter exists in agent.Registry().
// That does not imply `sir install` can write that adapter's hook config in the
// current build; installability is checked separately by isInstallableAgent.
// supported=false means we can detect presence but hooks are not yet
// implemented.
type agentProbe struct {
	id          string   // matches agent.AgentID when supported
	name        string   // human-readable product name
	binaryNames []string // binary names to probe on $PATH
	configDirs  []string // paths relative to $HOME to probe for existence
	supported   bool     // true ⟺ full adapter in agent.Registry()
}

// knownAgents is the full catalog of AI coding agents sir knows about.
// Supported agents appear first; unsupported (coming soon) follow.
var knownAgents = []agentProbe{
	{
		id:          "claude",
		name:        "Claude Code",
		binaryNames: []string{"claude"},
		configDirs:  []string{".claude"},
		supported:   true,
	},
	{
		id:          "codex",
		name:        "Codex",
		binaryNames: []string{"codex"},
		configDirs:  []string{".codex"},
		supported:   true,
	},
	{
		id:          "gemini",
		name:        "Gemini CLI",
		binaryNames: []string{"gemini"},
		configDirs:  []string{".gemini", ".config/gemini-cli"},
		supported:   true,
	},
	{
		id:          "cursor",
		name:        "Cursor",
		binaryNames: []string{"cursor-agent", "cursor"},
		configDirs:  []string{".cursor"},
		supported:   true,
	},
	{
		id:          "factory",
		name:        "Factory",
		binaryNames: []string{"factory", "droid"},
		configDirs:  []string{".factory", ".config/factory"},
		supported:   false,
	},
	{
		id:          "grok",
		name:        "Grok (xAI)",
		binaryNames: []string{"grok"},
		configDirs:  []string{".grok", ".config/grok"},
		supported:   false,
	},
	{
		id:          "opencode",
		name:        "OpenCode",
		binaryNames: []string{"opencode"},
		configDirs:  []string{".config/opencode"},
		supported:   false,
	},
}

// agentDiscovery is the result of probing one known agent on this machine.
type agentDiscovery struct {
	probe      agentProbe
	detected   bool
	configPath string      // representative path shown to the user (binary or config dir)
	ag         agent.Agent // non-nil when supported && detected
}

// discoverAgents probes every entry in knownAgents and returns the results.
func discoverAgents() []agentDiscovery {
	homeDir := mustHomeDir()
	results := make([]agentDiscovery, 0, len(knownAgents))
	for _, probe := range knownAgents {
		d := agentDiscovery{probe: probe}
		if probe.supported {
			ag := agent.ForID(agent.AgentID(probe.id))
			if ag != nil && ag.DetectInstallation() {
				d.detected = true
				d.configPath = ag.ConfigPath()
				d.ag = ag
			}
		} else {
			d.detected, d.configPath = probeAgentPresence(probe, homeDir)
		}
		results = append(results, d)
	}
	return results
}

// probeAgentPresence checks binary names on $PATH and config dirs under home.
// Returns (detected, representativePath).
func probeAgentPresence(probe agentProbe, homeDir string) (bool, string) {
	for _, bin := range probe.binaryNames {
		if p, err := exec.LookPath(bin); err == nil {
			return true, p
		}
	}
	for _, dir := range probe.configDirs {
		full := filepath.Join(homeDir, dir)
		if _, err := os.Stat(full); err == nil {
			return true, full
		}
	}
	return false, ""
}

// splitDiscovery partitions results into detected-supported and
// detected-unsupported (coming soon) slices.
func splitDiscovery(results []agentDiscovery) (supported, comingSoon []agentDiscovery) {
	for _, d := range results {
		if !d.detected {
			continue
		}
		if d.probe.supported {
			supported = append(supported, d)
		} else {
			comingSoon = append(comingSoon, d)
		}
	}
	return
}

// cmdConfigure implements `sir config` / `sir configure`.
func cmdConfigure(projectRoot string) {
	fmt.Println()
	fmt.Printf("  %s\n", ansiBold("sir config"))
	fmt.Printf("  %s\n", ansiDim("quiet on normal coding  ·  loud on dangerous transitions"))
	fmt.Println()

	if !isInteractiveTerminal() {
		fmt.Println("  Non-interactive terminal — guided setup requires an interactive shell.")
		fmt.Println()
		fmt.Println("  To install hooks:  sir install --agent claude")
		fmt.Println("  To view policy:    sir policy show")
		fmt.Println()
		return
	}

	// ── Step 1: Discover ─────────────────────────────────────────────────

	printConfigStep("1", "Discover")
	fmt.Println()
	discovered := discoverAgents()
	printDiscoveryTable(discovered)
	fmt.Println()

	detectedSupported, detectedComingSoon := splitDiscovery(discovered)
	totalDetected := len(detectedSupported) + len(detectedComingSoon)

	if totalDetected == 0 {
		fmt.Println("  No AI coding agents found on this machine.")
		fmt.Println("  Install an enabled protection target, then re-run `sir config`. Currently enabled: Claude Code.")
		fmt.Println()
		return
	}

	// ── Step 2: Select ────────────────────────────────────────────────────

	printConfigStep("2", "Select")
	fmt.Println()

	if len(detectedSupported) == 0 {
		// Only coming-soon agents were detected — nothing to hook yet.
		names := make([]string, 0, len(detectedComingSoon))
		for _, d := range detectedComingSoon {
			names = append(names, d.probe.name)
		}
		fmt.Printf("  %s detected but hook support is not yet available.\n",
			strings.Join(names, ", "))
		fmt.Printf("  No enabled protection target found. Currently enabled: Claude Code.\n")
		fmt.Println()
		printConfigFooter()
		return
	}

	agentsToOffer := make([]agent.Agent, 0, len(detectedSupported))
	nonInstallableDetected := make([]string, 0, len(detectedSupported))
	for _, d := range detectedSupported {
		if isInstallableAgent(d.ag) {
			agentsToOffer = append(agentsToOffer, d.ag)
		} else {
			nonInstallableDetected = append(nonInstallableDetected, d.probe.name)
		}
	}
	if len(agentsToOffer) == 0 {
		fmt.Println("  No enabled protection target was detected.")
		if len(nonInstallableDetected) > 0 {
			fmt.Printf("  %s detected, but hook protection is not enabled for them in this build.\n",
				strings.Join(nonInstallableDetected, ", "))
		}
		fmt.Println("  Currently enabled: Claude Code.")
		fmt.Println()
		printConfigFooter()
		return
	}

	// Mention coming-soon agents above the checklist so they're not invisible.
	if len(nonInstallableDetected) > 0 {
		fmt.Printf("  %s %s — detected, but disabled for hook install in this build.\n",
			ansiDim("Also detected:"), ansiDim(strings.Join(nonInstallableDetected, ", ")))
		fmt.Println()
	}
	if len(detectedComingSoon) > 0 {
		names := make([]string, 0, len(detectedComingSoon))
		for _, d := range detectedComingSoon {
			names = append(names, d.probe.name)
		}
		fmt.Printf("  %s %s — hook support coming soon.\n",
			ansiDim("Also detected:"), ansiDim(strings.Join(names, ", ")))
		fmt.Println()
	}

	chosen, remember, confirmed := runAgentChecklist(agentsToOffer)
	if !confirmed {
		fmt.Println()
		fmt.Println("  Configuration cancelled. Nothing changed.")
		return
	}
	if len(chosen) == 0 {
		fmt.Println()
		fatal("no agents selected — re-run `sir config` and select Claude Code with Space.")
	}
	fmt.Println()

	// ── Step 3: Install ───────────────────────────────────────────────────

	printConfigStep("3", "Install")
	fmt.Println()
	runInstall(projectRoot, "guard", installOptions{skipPreview: true}, chosen, wizardMCPScope(chosen))
	if remember {
		persistRememberedInstallAgents(chosen)
	}
	fmt.Println()

	// ── Step 4: Receipt ────────────────────────────────────────────────────

	printConfigStep("4", "Receipt")
	fmt.Println()
	printAgentReceipt(chosen, detectedComingSoon)
	fmt.Println()

	// ── Step 5: Providers ─────────────────────────────────────────────────

	printConfigStep("5", "Providers")
	fmt.Println()
	printProviderSection()
	fmt.Println()

	// ── Done ───────────────────────────────────────────────────────────────

	printConfigFooter()
}

// printConfigStep renders a numbered step header.
func printConfigStep(num, title string) {
	fmt.Printf("  %s  %s\n",
		ansiDim("Step "+num),
		ansiBold(title))
}

// printDiscoveryTable renders the discovery results in a compact table.
func printDiscoveryTable(results []agentDiscovery) {
	for _, d := range results {
		name := fmt.Sprintf("%-20s", d.probe.name)
		if d.detected {
			var status string
			if d.probe.supported {
				status = ansiGreen("found")
			} else {
				status = ansiDim("found") + ansiDim("  (hooks coming soon)")
			}
			detail := ""
			if d.configPath != "" {
				detail = "  " + ansiDim(d.configPath)
			}
			fmt.Printf("  %s  %s%s\n", name, status, detail)
		} else {
			fmt.Printf("  %s  %s\n", name, ansiDim("not found"))
		}
	}
}

// printAgentReceipt shows a per-agent installation outcome.
func printAgentReceipt(chosen []agent.Agent, comingSoon []agentDiscovery) {
	for _, ag := range chosen {
		fmt.Printf("  %s  %-20s  hooks installed\n",
			ansiGreen("[ok]"), ag.Name())
	}
	for _, d := range comingSoon {
		fmt.Printf("  %s  %-20s  %s\n",
			ansiDim("[--]"), d.probe.name,
			ansiDim("detected — hook support coming soon"))
	}
}

// printProviderSection shows registered providers or skips cleanly.
func printProviderSection() {
	reg, err := provider.Load()
	if err != nil || len(reg.Providers) == 0 {
		fmt.Printf("  %s\n", ansiDim("No providers configured."))
		fmt.Printf("  %s\n", ansiDim("To add one: sir provider install <manifest.yaml>"))
		return
	}

	for _, e := range reg.Providers {
		status := ansiDim("inactive")
		if e.Enabled {
			status = ansiGreen("active")
		}
		healthy, _ := provider.HealthCheck(e)
		health := ansiGreen("healthy")
		if !healthy {
			health = ac(auditYellow, "unhealthy")
		}
		fmt.Printf("  %-26s  %-18s  %-8s  %s\n",
			e.Name, e.Kind, status, health)
	}
	fmt.Println()
	fmt.Printf("  %s\n", ansiDim("To configure: sir provider configure <name> --set key=value"))
	fmt.Printf("  %s\n", ansiDim("To inspect:   sir provider status [<name>]"))
}

// printConfigFooter shows post-setup hints.
func printConfigFooter() {
	fmt.Printf("  %s\n", ansiBold("Setup complete."))
	fmt.Println()
	fmt.Printf("  %-24s  %s\n", ansiBold("sir status"), ansiDim("check what sir sees"))
	fmt.Printf("  %-24s  %s\n", ansiBold("sir posture"), ansiDim("full posture view"))
	fmt.Printf("  %-24s  %s\n", ansiBold("sir why"), ansiDim("explain the last decision"))
	fmt.Println()
}
