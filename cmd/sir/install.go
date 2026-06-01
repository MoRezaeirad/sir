package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/config"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/provider"
	"github.com/somoore/sir/pkg/session"
)

func cmdInstall(projectRoot, mode string) {
	if mode != "guard" && mode != "observe" {
		fatal("mode must be 'guard' or 'observe'")
	}

	opts := parseInstallOptions(os.Args[2:])

	// --forget clears the remembered agent preference and returns. It is a
	// standalone maintenance action, not part of a real install run.
	if opts.forget {
		forgetRememberedInstallAgents()
		return
	}

	// CLI path: no caller-supplied agent set or MCP scope, so install resolves
	// them from flags/detection exactly as before.
	runInstall(projectRoot, mode, opts, nil, nil)
}

// runInstall is the install body shared by the CLI (cmdInstall) and the
// wizard. agentsOverride, when non-nil, pins the exact set of agents to
// install for (bypassing flag/detection resolution); scopeOverride, when
// non-nil, pins MCP discovery scope. The wizard uses both so it can install a
// chosen *set* of agents in one pass while still discovering project-local
// `.mcp.json` — which the per-`--agent` scoping deliberately excludes (see
// mcpScopesForAgent) and which a per-agent install loop would therefore skip.
func runInstall(projectRoot, mode string, opts installOptions, agentsOverride []agent.Agent, scopeOverride map[mcpConfigScope]bool) {
	policy, err := loadManagedPolicyForCLI()
	if err != nil {
		fatal("load managed policy: %v", err)
	}

	stateDir := session.StateDir(projectRoot)
	leasePath := filepath.Join(stateDir, "lease.json")
	existingLease, existingLeaseErr := lease.Load(leasePath)

	l := lease.DefaultLease()
	if policy != nil {
		if cloned, cloneErr := policy.CloneLease(); cloneErr != nil {
			fatal("clone managed lease: %v", cloneErr)
		} else {
			l = cloned
		}
		if mode != l.Mode {
			fmt.Printf("  Managed mode ignores local install mode %q and applies lease mode %q from policy %s.\n",
				mode, l.Mode, policy.PolicyVersion)
		}
	} else {
		if existingLeaseErr == nil {
			l = existingLease
		} else if existingLeaseErr != nil && !os.IsNotExist(existingLeaseErr) {
			fatal("load existing lease: %v", existingLeaseErr)
		} else {
			// Fresh install, no prior lease: seed the personal-profile default so
			// the README quickstart (`sir install`) gets the advertised behavior
			// without a separate `sir policy init`. Raw secret reads are denied and
			// the agent gets the redacted `sir secret view` inline, so credential
			// values never enter model context. `sir policy init --profile <p>`
			// re-profiles; an existing operator lease is preserved untouched.
			l.DenyRawSecretReads = true
		}
		l.ObserveOnly = mode == "observe"
	}

	// Populate ApprovedMCPServers from typed MCP inventory so install, status,
	// doctor, and rewrite all operate on the same source-aware view. In managed
	// mode the manifest lease is the trust anchor, so local discovery must not
	// widen approved_mcp_servers.
	mcpScopes := mcpScopesForAgent(opts.explicitAgent)
	if scopeOverride != nil {
		mcpScopes = scopeOverride
	}
	mcpReport := discoverMCPInventoryForScopes(projectRoot, mcpScopes)
	if len(mcpReport.Errors) > 0 {
		for _, invErr := range mcpReport.Errors {
			fmt.Fprintf(os.Stderr, "warning: could not parse %s: %v\n", invErr.Path, invErr.Err)
		}
	}
	mcpServers := approvedMCPServerNames(mcpReport.Servers)
	posture := resolveMCPTrustPostureForInstall()
	if policy == nil && l.Mode == "strict" {
		posture = config.PostureStrict
	}
	// Preserve existing approvals across re-runs of `sir install`. In strict
	// posture, previously-approved servers that are still present in
	// discovery keep their approval and are NOT moved into
	// DiscoveredMCPServers; only newly-surfaced servers sit in the
	// discovered-pending-approval bucket. Managed mode bypasses this (the
	// policy lease is the trust anchor).
	carryApproved, carryApprovals := map[string]struct{}{}, map[string]lease.MCPApproval{}
	if existingLeaseErr == nil && policy == nil && posture == config.PostureStrict {
		for _, s := range existingLease.ApprovedMCPServers {
			carryApproved[s] = struct{}{}
		}
		for k, v := range existingLease.MCPApprovals {
			carryApprovals[k] = v
		}
	}

	if policy != nil && len(mcpServers) > 0 {
		fmt.Printf("  Managed mode keeps approved_mcp_servers pinned to policy %s; locally discovered MCP servers remain unapproved until the manifest lease is updated.\n",
			policy.PolicyVersion)
	} else if len(mcpServers) > 0 {
		switch posture {
		case config.PostureStrict:
			var carriedApprovedNames []string
			var newlyDiscovered []lease.MCPDiscoveredServer
			seen := make(map[string]struct{}, len(mcpReport.Servers))
			for _, s := range mcpReport.Servers {
				if _, dup := seen[s.Name]; dup {
					continue
				}
				seen[s.Name] = struct{}{}
				if _, ok := carryApproved[s.Name]; ok {
					carriedApprovedNames = append(carriedApprovedNames, s.Name)
					continue
				}
				newlyDiscovered = append(newlyDiscovered, lease.MCPDiscoveredServer{
					Name:       s.Name,
					SourcePath: s.SourcePath,
					Command:    s.Command,
				})
			}
			l.ApprovedMCPServers = carriedApprovedNames
			if len(carryApprovals) > 0 {
				l.MCPApprovals = make(map[string]lease.MCPApproval, len(carriedApprovedNames))
				for _, name := range carriedApprovedNames {
					if rec, ok := carryApprovals[name]; ok {
						l.MCPApprovals[name] = rec
					}
				}
			}
			l.DiscoveredMCPServers = newlyDiscovered
			switch {
			case len(newlyDiscovered) == 0 && len(carriedApprovedNames) > 0:
				fmt.Printf("  Kept %d previously-approved MCP server(s) (strict posture): %v\n", len(carriedApprovedNames), carriedApprovedNames)
			case len(newlyDiscovered) > 0 && len(carriedApprovedNames) > 0:
				fmt.Printf("  Kept %d approved, discovered %d new MCP server(s) awaiting `sir mcp approve` (strict): approved=%v discovered=%v\n",
					len(carriedApprovedNames), len(newlyDiscovered), carriedApprovedNames, mcpDiscoveredNames(newlyDiscovered))
			default:
				fmt.Printf("  Discovered %d MCP server(s) (strict posture: use `sir mcp approve <name>` to trust): %v\n", len(newlyDiscovered), mcpDiscoveredNames(newlyDiscovered))
			}
		default:
			l.ApprovedMCPServers = mcpServers
			fmt.Printf("  Discovered %d MCP server(s) to auto-approve via approved_mcp_servers: %v\n", len(mcpServers), mcpServers)
		}
	}
	mcpRewrites := planMCPProxyRewrites(mcpReport.Servers)

	homeDir := mustHomeDir()

	// The global config file (~/.sir/config.json) carries the user's MCP
	// trust posture and deep-gating preferences. Agent-initiated writes to
	// it are security-relevant — a compromised agent should not be able to
	// silently flip the posture from strict to permissive or disable the
	// onboarding gate. Route it through the existing posture-file gate by
	// appending its absolute path to PostureFiles. Manual edits in a
	// terminal outside the agent are still possible; they are outside sir's
	// threat model the same way a shell-level `rm -rf` is.
	if configAbsPath := filepath.Join(homeDir, ".sir", "config.json"); configAbsPath != "" {
		already := false
		for _, p := range l.PostureFiles {
			if p == configAbsPath {
				already = true
				break
			}
		}
		if !already {
			l.PostureFiles = append(l.PostureFiles, configAbsPath)
		}
	}

	// Resolve the set of agents to install for. This build only enables hook
	// installation for Claude Code; other adapters may still be
	// parsed/statused, but this install path must not create or update their
	// hook configuration.
	agents := agentsOverride
	if agents == nil {
		agents, err = selectAgentsForInstall(opts.explicitAgent, opts.skipPreview)
		if err != nil {
			fatal("%v", err)
		}
	}
	for _, ag := range agents {
		if !isInstallableAgent(ag) {
			fatal("%s is detected/supported, but hook protection is not enabled for it in this build", ag.Name())
		}
	}

	// Detection summary before any prompt.
	fmt.Println("sir install detected:")
	for _, ag := range agents {
		if policy != nil {
			if _, ok := policy.HookSubtree(string(ag.ID())); !ok {
				fatal("managed policy %s does not define hooks for %s; re-run with --agent claude or update %s",
					policy.PolicyVersion, ag.Name(), policy.ManagedPolicySourcePath())
			}
		}
		fmt.Printf("  ok  %s  (%s)\n", ag.Name(), ag.ConfigPath())
	}
	fmt.Println()
	if policy != nil {
		fmt.Printf("  %s\n\n", managedPolicyNotice(policy))
	}

	for _, ag := range agents {
		hooksConfig, err := generatedHooksConfigForAgent(ag, l.Mode)
		if err != nil {
			fatal("preflight %s install: %v", ag.Name(), err)
		}
		if err := validateGeneratedHooksPolicy(ag, hooksConfig, policy); err != nil {
			fatal("preflight %s install: %v", ag.Name(), err)
		}
	}

	// Preview changes before applying them.
	if !opts.skipPreview {
		fmt.Println("sir install will:")
		for _, ag := range agents {
			fmt.Printf("  Update  %s  (%s hooks)\n", ag.ConfigPath(), ag.Name())
		}
		for _, rewrite := range mcpRewrites {
			fmt.Printf("  Rewrite %s  (wrap MCP server %q with sir mcp-proxy)\n", rewrite.SourcePath, rewrite.Name)
		}
		fmt.Printf("  Create  %s  (project state)\n", stateDir)
		fmt.Printf("  Write   %s  (project lease)\n", leasePath)
		fmt.Println()
		fmt.Print("Proceed? [Y/n] ")

		var confirm string
		fmt.Scanln(&confirm)
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm == "n" || confirm == "no" {
			fmt.Println("Install cancelled.")
			return
		}
	}

	// Ensure ~/.sir/ exists for canonical copies (per-agent).
	sirRootDir := filepath.Join(homeDir, ".sir")
	if err := os.MkdirAll(sirRootDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create ~/.sir dir: %v\n", err)
	}

	// Wrap raw MCP servers first. installForAgent re-reads live config files,
	// so the subsequent hook merge preserves the rewritten mcpServers entries.
	if results, err := rewriteDiscoveredMCPServers(mcpReport.Servers, sirBinaryPath); err != nil {
		fatal("rewrite MCP servers through sir mcp-proxy: %v", err)
	} else {
		for _, result := range results {
			fmt.Printf("  Rewrote %s  (wrapped %s)\n", result.Path, strings.Join(result.Servers, ", "))
		}
	}

	// Install per agent.
	for _, ag := range agents {
		if err := installForAgent(ag, l.Mode, homeDir, opts.skipPreview, policy); err != nil {
			fatal("install %s hooks: %v", ag.Name(), err)
		}
	}

	// Create sir state directory
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		fatal("create state dir: %v", err)
	}

	// Write default lease
	if err := l.Save(leasePath); err != nil {
		fatal("save lease: %v", err)
	}

	// Initialize session and hash posture files (once — session state is
	// project-scoped, not agent-scoped).
	if _, err := hooks.SessionStart(projectRoot, l); err != nil {
		fatal("session start: %v", err)
	}

	// Refresh posture baselines across every sir project state directory.
	// Install rewrote the host-agent hook files, so any existing session
	// carries a stale baseline and would trip the tamper detector on its
	// next Bash call. RebaselineAllProjects walks ~/.sir/projects/* and
	// rehashes against current on-disk state — this also re-covers the
	// project we just initialized above (harmless: we just wrote those
	// hashes) and any other projects on this machine. `sir install` is
	// user-initiated from a terminal and out-of-band of any agent session,
	// so the hook changes are legitimate by definition. Callers that want
	// the old behavior (leave other sessions wedged, force a per-project
	// `sir doctor`) can pass --no-rebaseline.
	if !opts.noRebaseline {
		summary, err := hooks.RebaselineAllProjects()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cross-project rebaseline failed: %v\n", err)
			fmt.Fprintln(os.Stderr, "  Run `sir doctor` in each active agent session to recover manually.")
		} else if summary.Refreshed > 0 || summary.DenyAllCleared > 0 || len(summary.Skipped) > 0 {
			printRebaselineSummary(os.Stdout, os.Stderr, summary)
		}
	} else {
		fmt.Println("  --no-rebaseline set: existing project sessions keep their old posture baselines.")
		fmt.Println("  Run `sir doctor` inside any active agent session to clear deny-all manually.")
	}

	fmt.Printf("sir installed successfully — %s profile, %s\n", describeProfile(l), describeEnforcement(l))
	if policy != nil {
		fmt.Printf("  Managed policy: %s (%s)\n", policy.PolicyVersion, policy.ManagedPolicySourcePath())
	}
	fmt.Println()
	for _, ag := range agents {
		fmt.Printf("  Hooks:   %s  (%s)\n", ag.ConfigPath(), ag.Name())
	}
	fmt.Printf("  State:   %s\n", stateDir)
	fmt.Printf("  Lease:   %s\n", leasePath)
	fmt.Println()
	fmt.Println("What sir watches:")
	if l.DenyRawSecretReads {
		fmt.Println("  * .env, *.pem, .aws/, .ssh/ — raw reads denied; redacted key view returned (sir secret view)")
	} else {
		fmt.Println("  * .env, *.pem, .aws/, .ssh/ — asks before reading")
	}
	fmt.Println("  * External network + git push — blocked if secrets in session")
	fmt.Println("  * postinstall scripts — hashed before/after npm/pip/cargo install")
	fmt.Println("  * Hook config changes — auto-restored and session halted")
	fmt.Println()
	fmt.Println("What sir doesn't catch (honest):")
	fmt.Println("  * python myscript.py (script-file exfil — content invisible to sir)")
	fmt.Println("  * Shell syntax that defeats lexical classification or hides behavior in child scripts")
	fmt.Println("  * Secrets paraphrased in model output — semantic laundering")
	fmt.Println()
	if len(agents) > 1 {
		fmt.Println("Run any installed agent in any project. sir is invisible until something dangerous happens.")
	} else {
		switch agents[0].ID() {
		case agent.Codex:
			fmt.Println("Run 'codex' in any project. sir is invisible until something dangerous happens.")
		case agent.Gemini:
			fmt.Println("Run 'gemini' in any project. sir is invisible until something dangerous happens.")
		default:
			fmt.Println("Run 'claude' in any project. sir is invisible until something dangerous happens.")
		}
	}
	hasClaude := false
	for _, a := range agents {
		if a.ID() == agent.Claude {
			hasClaude = true
		}
	}
	if hasClaude {
		fmt.Println()
		fmt.Println("Note (Claude Code + extended thinking): an approval prompt mid-turn corrupts the")
		fmt.Println("  thinking stream, so when an action would prompt, sir denies instead. Approve from")
		fmt.Println("  YOUR terminal — sir approve --last — or turn thinking off (/config) for inline prompts.")
	}

	fmt.Println()
	fmt.Println("See it work now:  sir demo        (60-second tour of what sir catches)")
	fmt.Println("Check anytime:    sir status      ·  if blocked: sir why  (full chain: sir explain)")

	// Register any providers passed via --with-provider.
	if len(opts.withProviders) > 0 {
		fmt.Println()
		for _, manifestPath := range opts.withProviders {
			registerProviderFromInstall(manifestPath)
		}
	}
}

const rebaselineSkipDetailLimit = 5

func printRebaselineSummary(stdout, stderr io.Writer, summary hooks.RebaselineSummary) {
	fmt.Fprintf(stdout, "  Refreshed baselines across %d project session(s); cleared deny-all on %d.\n",
		summary.Refreshed, summary.DenyAllCleared)
	if len(summary.Skipped) == 0 {
		return
	}
	fmt.Fprintf(stderr, "  Skipped %d stale/bad project session(s) during rebaseline.\n", len(summary.Skipped))
	limit := len(summary.Skipped)
	if limit > rebaselineSkipDetailLimit {
		limit = rebaselineSkipDetailLimit
	}
	for _, s := range summary.Skipped[:limit] {
		fmt.Fprintf(stderr, "    - %s: %s\n", s.Project, s.Reason)
	}
	if remaining := len(summary.Skipped) - limit; remaining > 0 {
		fmt.Fprintf(stderr, "    ... %d more skipped; run `sir doctor` in an affected project to inspect.\n", remaining)
	}
}

// registerProviderFromInstall validates and registers a provider manifest
// specified via --with-provider during sir install.
func registerProviderFromInstall(manifestPath string) {
	absPath, err := filepath.Abs(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: --with-provider %s: resolve path: %v\n", manifestPath, err)
		return
	}
	m, issues := loadAndValidateManifest(absPath)
	if len(issues) > 0 {
		fmt.Fprintf(os.Stderr, "  warning: --with-provider %s: validation failed:\n", manifestPath)
		for _, iss := range issues {
			fmt.Fprintf(os.Stderr, "    %s\n", iss)
		}
		return
	}
	reg, err := provider.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: load provider registry: %v\n", err)
		return
	}
	dir := filepath.Dir(absPath)
	entrypoint, err := filepath.Abs(filepath.Join(dir, m.Entrypoint))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: resolve entrypoint: %v\n", err)
		return
	}
	e := provider.Entry{
		Name:         m.Name,
		Kind:         m.Kind,
		Version:      m.Version,
		ManifestPath: absPath,
		Entrypoint:   entrypoint,
		Platforms:    m.Platforms,
		Capabilities: m.Capabilities,
		Enabled:      true,
		InstalledBy:  "sir install --with-provider",
	}
	if existing, ok := reg.ByName(m.Name); ok {
		// Already registered — update entrypoint and version.
		existing.Version = m.Version
		existing.ManifestPath = absPath
		existing.Entrypoint = entrypoint
	} else {
		if err := reg.Add(e); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: register provider: %v\n", err)
			return
		}
	}
	healthy, reason := provider.HealthCheck(e)
	healthStatus := provider.HealthHealthy
	if !healthy {
		healthStatus = provider.HealthUnhealthy
		fmt.Fprintf(os.Stderr, "  warning: provider %s health check: %s\n", m.Name, reason)
	}
	reg.UpdateHealth(m.Name, healthStatus, reason)
	if err := reg.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: save registry: %v\n", err)
		return
	}
	fmt.Printf("  Provider: %s (%s) — %s\n", m.Name, m.Kind, healthStatus)
}

// describeProfile returns a human label for the lease's profile axis
// (personal -> team -> strict -> managed), which is orthogonal to the
// guard/observe enforcement axis. Mode carries the profile for team/strict/
// managed; a plain "guard" lease is the low-friction personal default.
func describeProfile(l *lease.Lease) string {
	switch l.Mode {
	case "managed", "strict", "team":
		return l.Mode
	default:
		return "personal"
	}
}

// describeEnforcement reports the guard/observe axis in plain language.
func describeEnforcement(l *lease.Lease) string {
	if l.ObserveOnly {
		return "observe (records would_allow/ask/deny, blocks nothing)"
	}
	return "guard (enforcing)"
}

// resolveMCPTrustPostureForInstall returns the posture to use for this
// install. Missing config file on a first install (no binary manifest yet)
// is upgraded to "strict" and persisted; on an existing install missing
// config defaults to "standard" so upgrades do not surprise. Parse errors
// fail closed — the install aborts rather than silently widening trust.
func resolveMCPTrustPostureForInstall() config.MCPTrustPosture {
	cfg, present, err := config.Load()
	if err != nil {
		fatal("load global config: %v", err)
	}
	if present {
		return cfg.MCPTrustPosture
	}
	first, firstErr := config.IsFirstInstall()
	if firstErr != nil {
		// Hit only if os.Stat fails for reasons other than ENOENT. Treat
		// as existing install to avoid mis-tightening on a broken home.
		return config.PostureStandard
	}
	if first {
		cfg.MCPTrustPosture = config.PostureStrict
		if saveErr := cfg.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "warning: could not persist strict posture: %v\n", saveErr)
		} else {
			fmt.Println("  First install detected; mcp_trust_posture = strict (fresh defaults).")
		}
		return cfg.MCPTrustPosture
	}
	return config.PostureStandard
}

// mcpDiscoveredNames returns the Name field of each entry. Used for
// install's summary line.
func mcpDiscoveredNames(servers []lease.MCPDiscoveredServer) []string {
	if len(servers) == 0 {
		return nil
	}
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		out = append(out, s.Name)
	}
	return out
}
