package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/agent"
)

func printDoctorAgentChecks(statuses []agentStatus) (bool, bool) {
	sawAnyInstalled := false
	schemaFixed := false

	for _, status := range statuses {
		if !status.Installed {
			continue
		}
		sawAnyInstalled = true
		if status.ReadErr != nil {
			fmt.Printf("  WARNING: %s: could not read hook configuration: %v\n", status.Agent.Name(), status.ReadErr)
			continue
		}

		supportPreview := agent.SupportManifestForAgent(status.Agent).StatusSuffix()
		if len(status.Missing) > 0 {
			fmt.Printf("  WARNING: %s: %d/%d hook events registered. Missing:\n", status.Agent.Name(), status.Found, status.Total)
			for _, event := range status.Missing {
				fmt.Printf("    - %s\n", event)
			}
			fmt.Println("  Run 'sir install' to register all hooks.")
		} else {
			fmt.Printf("  [ok] %s: all %d hook events registered%s\n", status.Agent.Name(), status.Total, supportPreview)
		}

		if spec := status.Agent.GetSpec(); spec != nil && spec.MinVersion != "" {
			for _, bin := range spec.BinaryNames {
				if installed := agent.DetectInstalledVersion(bin); installed != "" {
					if agent.SemverLessThan(installed, spec.MinVersion) {
						fmt.Printf("  warn  %s %s detected; sir requires %s+\n", status.Agent.Name(), installed, spec.MinVersion)
					}
					break
				}
			}
		}

		if len(status.SchemaInval) > 0 {
			fmt.Printf("  [!!] CRITICAL: %s: %d hook event(s) use invalid schema:\n", status.Agent.Name(), len(status.SchemaInval))
			for _, event := range status.SchemaInval {
				fmt.Printf("    - %s (missing 'hooks' array wrapper)\n", event)
			}
			fmt.Println("  Run 'sir install' to fix. This is the #1 cause of sir being completely inert.")
			schemaFixed = true
		} else {
			fmt.Printf("  [ok] %s: hook schema valid\n", status.Agent.Name())
		}

		if spec := status.Agent.GetSpec(); spec != nil && spec.RequiredFeatureFlag != "" {
			configPath, featureStatus, supported := featureFlagStatusForAgent(status.Agent)
			if !supported {
				fmt.Printf("  [!!] WARNING: %s: feature flag validation for %s is not implemented yet\n", status.Agent.Name(), spec.RequiredFeatureFlag)
				continue
			}
			switch featureStatus {
			case codexFlagAlreadyEnabled:
				fmt.Printf("  [ok] %s: %s feature flag enabled in %s\n", status.Agent.Name(), spec.RequiredFeatureFlag, configPath)
			case codexFlagMissingFile:
				fmt.Printf("  [!!] WARNING: %s: %s does not exist yet\n", status.Agent.Name(), configPath)
				fmt.Printf("        Run '%s' (or create the file with [features]\\n%s = true).\n", spec.FeatureFlagEnableCommand, spec.RequiredFeatureFlag)
			case codexFlagNeedsEnable:
				fmt.Printf("  [!!] WARNING: %s: %s=true is NOT set under [features] in %s\n", status.Agent.Name(), spec.RequiredFeatureFlag, configPath)
				fmt.Printf("        Hooks are written but %s will NOT fire them until the feature flag is enabled.\n", status.Agent.Name())
				fmt.Printf("        Fix: %s\n", spec.FeatureFlagEnableCommand)
			case codexFlagUnreadable:
				fmt.Printf("  [!!] WARNING: %s: could not read %s - unable to verify %s flag\n", status.Agent.Name(), configPath, spec.RequiredFeatureFlag)
			}

			// Hook-trust diagnostic (Codex 0.135/0.136): even with the feature
			// flag on, hooks only fire interactively after the user trusts them
			// at the "Hooks need review" prompt. exec never fires them.
			if status.Agent.ID() == agent.Codex && featureStatus != codexFlagMissingFile {
				printCodexHookTrust(status.Agent, configPath)
			}
		}
	}

	if !sawAnyInstalled {
		fmt.Println("  WARNING: no supported agent detected. Run 'sir install' after installing Claude Code, Codex, or Gemini CLI.")
	}
	printDoctorSupportWarnings(statuses)
	return sawAnyInstalled, schemaFixed
}

// printCodexHookTrust reports whether Codex has recorded trust for sir's
// hooks. On 0.135/0.136 hooks only fire interactively after the user accepts
// the "Hooks need review" prompt, and never under `codex exec`. This surfaces
// the trust state so a user whose hooks are silently untrusted gets a clear
// signal instead of assuming sir is active.
func printCodexHookTrust(ag agent.Agent, configPath string) {
	homeDir, _ := os.UserHomeDir()
	spec := ag.GetSpec()
	hooksJSONPath := filepath.Join(homeDir, spec.ConfigFile)

	trust, err := readCodexHookTrust(configPath, hooksJSONPath)
	if err != nil || !trust.configReadable {
		fmt.Printf("  [!!] WARNING: %s: could not read hook-trust state from %s\n", ag.Name(), configPath)
		return
	}

	// Which of sir's registered events lack a trust entry?
	var untrusted []string
	for _, ev := range spec.SupportedWireEvents {
		token, ok := codexEventTrustToken[ev]
		if !ok {
			continue
		}
		if !trust.trustedEvents[token] {
			untrusted = append(untrusted, ev)
		}
	}

	if !trust.hasFeaturesGate {
		fmt.Printf("  [!!] WARNING: %s: no hook-trust entries found in %s\n", ag.Name(), configPath)
		fmt.Printf("        Codex has not trusted sir's hooks yet. They will NOT fire until you\n")
		fmt.Printf("        start an interactive `codex` session and choose \"Trust all\" at the\n")
		fmt.Printf("        \"Hooks need review\" prompt. NOTE: `codex exec` never fires hooks (0.135/0.136).\n")
		return
	}
	if len(untrusted) > 0 {
		fmt.Printf("  [!!] WARNING: %s: %d hook event(s) have no Codex trust entry: %v\n", ag.Name(), len(untrusted), untrusted)
		fmt.Printf("        Trust them in an interactive `codex` session at the \"Hooks need review\"\n")
		fmt.Printf("        prompt. (`codex exec` never fires hooks on 0.135/0.136.)\n")
		return
	}
	// Every event has a trust entry with a recorded hash. sir cannot recompute
	// Codex's hash, so it cannot confirm the entry matches the current
	// hooks.json — Codex re-verifies at session start and re-prompts if the hook
	// changed. Report the entry's presence, not certified trust.
	fmt.Printf("  [ok] %s: all hook events have a Codex trust entry. Codex re-verifies the hash\n", ag.Name())
	fmt.Printf("        at session start; if hooks.json changed it will re-prompt. (`codex exec` never fires hooks.)\n")
}
