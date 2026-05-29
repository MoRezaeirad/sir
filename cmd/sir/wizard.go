package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// wizard.go implements `sir wizard` / `sir install --global`: a step-by-step
// onboarding flow that lets the user choose which agents to protect and which
// repositories to cover, then performs the install.
//
// Architectural honesty (verified against pkg/hooks/evaluate_io.go and
// pkg/lease/lease.go): sir's hooks live in the agents' global config files
// (~/.claude, ~/.codex, ~/.gemini). Once installed they fire in EVERY repo any
// agent runs in — including repos cloned later — with no per-repo install step.
// An unleashed repo automatically evaluates against lease.DefaultLease(), a
// full guard lease (sensitive-path asks, secret-in-session network/push
// blocking, postinstall hashing, hook-tamper detection). The ONLY thing a
// per-repo lease adds over that default is DenyRawSecretReads (the
// personal-profile redacted-secret-view behavior).
//
// Therefore the wizard does NOT build a filesystem watcher or a clone daemon:
// the first time an agent runs in a new repo IS the detection point. Scope
// selection here is about (a) which agents get hooks and (b) which existing
// repos get a seeded personal-profile lease up front. Future clones are
// covered by the global hooks at neutral-guard until they get a lease.

type wizardScope int

const (
	scopeThisRepo wizardScope = iota
	scopeDirectory
	scopeEverywhere
)

func cmdWizard(projectRoot, mode string, args []string) {
	fmt.Println(ansiBold("sir setup wizard"))
	fmt.Println()

	if !isInteractiveTerminal() {
		// Non-interactive (piped / CI / no TTY): the wizard is a UX layer, so
		// degrade to the deterministic install for the current repo. Honors
		// the same fail-closed defaults as `sir install`.
		fmt.Println("  Non-interactive terminal detected; running the standard per-repo install.")
		fmt.Println("  Use `sir wizard` from an interactive shell for agent/scope selection.")
		fmt.Println()
		cmdInstall(projectRoot, mode)
		return
	}

	// Step 1 — agents.
	detected := detectInstalledAgents()
	if len(detected) == 0 {
		fatal("no supported agents detected on this machine.\n  Install Claude Code, Gemini CLI, or Codex, then re-run sir wizard.")
	}
	chosenAgents, remember, confirmed := runAgentChecklist(detected)
	if !confirmed {
		fmt.Println("Wizard cancelled. Nothing changed.")
		return
	}
	if len(chosenAgents) == 0 {
		fatal("no agents selected. Re-run `sir wizard` and select at least one with Space.")
	}

	// Step 2 — scope.
	scope, scopeRoot, ok := promptWizardScope(projectRoot)
	if !ok {
		fmt.Println("Wizard cancelled. Nothing changed.")
		return
	}

	// Step 3 — confirm and perform.
	fmt.Println()
	fmt.Println(ansiBold("Plan"))
	for _, ag := range chosenAgents {
		fmt.Printf("  Install hooks  %s  (%s)\n", ag.Name(), ag.ConfigPath())
	}
	switch scope {
	case scopeThisRepo:
		fmt.Printf("  Seed lease     %s  (this repo)\n", projectRoot)
	case scopeDirectory:
		fmt.Printf("  Seed leases    every git repo under %s\n", scopeRoot)
	case scopeEverywhere:
		fmt.Printf("  Seed leases    every git repo under %s\n", scopeRoot)
		fmt.Println("  Coverage       global hooks already protect every other repo (incl. future clones)")
	}
	fmt.Println()
	if !confirmYesNo("Proceed?", true) {
		fmt.Println("Wizard cancelled. Nothing changed.")
		return
	}

	// Perform the install for the chosen agent set in a single pass via the
	// shared install body. Passing the agent set as an override (rather than
	// re-entering cmdInstall once per --agent) means MCP discovery uses the
	// union scope plus project-local `.mcp.json` (wizardMCPScope), so project
	// MCP servers are wrapped/approved just like a bare `sir install` would —
	// the per-agent path deliberately omits project-local and would skip them.
	// skipPreview suppresses cmdInstall's own Proceed? prompt since the wizard
	// already confirmed the plan above.
	runInstall(projectRoot, mode, installOptions{skipPreview: true}, chosenAgents, wizardMCPScope(chosenAgents))

	// Persist the remembered-agent choice only after a confirmed, successful
	// install. Doing it right after the agent checklist (the earlier
	// behavior) mutated ~/.sir/config.json even when the user then cancelled
	// at the scope picker or the Proceed? prompt — changing future
	// `sir install` behavior after a run that printed "Nothing changed."
	// cmdInstall fatals on failure, so reaching here means the install
	// succeeded.
	if remember {
		persistRememberedInstallAgents(chosenAgents)
	}

	// Seed leases for the chosen scope beyond the current repo.
	if scope == scopeDirectory || scope == scopeEverywhere {
		seedLeasesUnderRoot(scopeRoot, projectRoot)
	}

	fmt.Println()
	fmt.Println(ansiBold("Wizard complete."))
	fmt.Println("  Run any installed agent in any repo — sir is invisible until something dangerous happens.")
	if scope == scopeEverywhere {
		fmt.Println("  New clones are covered automatically the first time an agent runs in them")
		fmt.Println("  (neutral guard). To give a repo the redacted-secret-view default up front,")
		fmt.Println("  run `sir install` inside it.")
	}
	fmt.Println()
	fmt.Println("Check anytime:  sir status   ·   sir posture")
}

// promptWizardScope asks the user how broadly to protect. Returns the chosen
// scope, the resolved root directory for directory/everywhere scopes, and ok
// (false on cancel).
func promptWizardScope(projectRoot string) (wizardScope, string, bool) {
	home := mustHomeDir()
	items := []checklistItem{
		{Label: "This repository only", Detail: projectRoot, Checked: true},
		{Label: "All git repos under a directory", Detail: "you'll confirm the path"},
		{Label: "Everywhere (all repos + future clones)", Detail: "global hooks; seed existing repos under home"},
	}
	picked, ok := runRadio("How widely should sir protect?", items)
	if !ok {
		return scopeThisRepo, "", false
	}
	switch picked {
	case 0:
		return scopeThisRepo, "", true
	case 1:
		root := promptLine("Directory to scan for git repos", filepath.Dir(projectRoot))
		root = expandHome(strings.TrimSpace(root), home)
		if root == "" {
			return scopeThisRepo, "", false
		}
		return scopeDirectory, root, true
	default:
		return scopeEverywhere, home, true
	}
}

// seedLeasesUnderRoot walks root for git repositories and seeds a
// personal-profile lease (DenyRawSecretReads on) in each that does not already
// have one. The repo at skipRoot is skipped because the caller already
// installed it. Coverage gaps (permission errors, the depth cap) are reported,
// not silently swallowed.
func seedLeasesUnderRoot(root, skipRoot string) {
	repos, skipped := findGitRepos(root)
	if len(repos) == 0 {
		fmt.Printf("  No git repositories found under %s.\n", root)
	}
	seeded, already := 0, 0
	for _, repo := range repos {
		if repo == skipRoot {
			continue
		}
		leasePath := filepath.Join(session.StateDir(repo), "lease.json")
		if _, err := lease.Load(leasePath); err == nil {
			already++
			continue
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "  warning: could not read existing lease for %s: %v\n", repo, err)
			continue
		}
		l := lease.DefaultLease()
		l.DenyRawSecretReads = true
		if err := os.MkdirAll(session.StateDir(repo), 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not create state dir for %s: %v\n", repo, err)
			continue
		}
		if err := l.Save(leasePath); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not seed lease for %s: %v\n", repo, err)
			continue
		}
		if _, err := hooks.SessionStart(repo, l); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not initialize session for %s: %v\n", repo, err)
		}
		seeded++
	}
	fmt.Printf("  Seeded %d repo(s); %d already had a lease.\n", seeded, already)
	if len(skipped) > 0 {
		fmt.Printf("  Skipped %d path(s) (permission or scan-depth limit):\n", len(skipped))
		for _, s := range skipped {
			fmt.Fprintf(os.Stderr, "    %s\n", s)
		}
	}
}

// maxWizardScanDepth bounds the repo walk so a wizard run on a deep home dir
// does not turn into an unbounded filesystem crawl. Depth is counted in path
// separators below root.
const maxWizardScanDepth = 6

// findGitRepos walks root and returns directories containing a `.git` entry.
// It does not descend into a repo once found (nested submodules are part of
// their parent). Returns discovered repos and a list of skipped paths
// (permission errors, depth-capped directories) for honest reporting.
func findGitRepos(root string) (repos []string, skipped []string) {
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s (%v)", path, err))
			return filepath.SkipDir
		}
		if !info.IsDir() {
			return nil
		}
		// Depth cap relative to root.
		if strings.Count(filepath.Clean(path), string(os.PathSeparator))-rootDepth > maxWizardScanDepth {
			skipped = append(skipped, fmt.Sprintf("%s (beyond scan depth %d)", path, maxWizardScanDepth))
			return filepath.SkipDir
		}
		if _, statErr := os.Stat(filepath.Join(path, ".git")); statErr == nil {
			repos = append(repos, path)
			return filepath.SkipDir // don't descend into a repo
		}
		return nil
	})
	if err != nil {
		skipped = append(skipped, fmt.Sprintf("%s (%v)", root, err))
	}
	return repos, skipped
}

// expandHome replaces a leading ~ with home.
func expandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

// hasFlag reports whether flag appears in args.
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// confirmYesNo prints a [Y/n] / [y/N] prompt (per defaultYes) in cooked mode
// and returns the user's choice. Empty input takes the default.
func confirmYesNo(prompt string, defaultYes bool) bool {
	suffix := "[Y/n]"
	if !defaultYes {
		suffix = "[y/N]"
	}
	fmt.Printf("%s %s ", prompt, suffix)
	var answer string
	fmt.Scanln(&answer)
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer == "" {
		return defaultYes
	}
	return answer == "y" || answer == "yes"
}

// promptLine reads a single line of input with a default shown in parentheses.
// Empty input returns def. Uses a line reader (not Scanln) so paths with
// spaces survive.
func promptLine(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s (%s): ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return def
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}
