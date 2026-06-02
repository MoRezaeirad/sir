package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/agent"
)

// init wires agent-specific post-install hooks into their specs. Kept in
// cmd/sir because ensureCodexFeatureFlag lives here — pulling it into
// pkg/agent would create a circular import with cmd/sir's helpers.
func init() {
	agent.NewCodexAgent().GetSpec().PostInstallFunc = func(homeDir string, skipPrompt bool) {
		codexConfigPath := filepath.Join(homeDir, ".codex", "config.toml")
		codexDebugf("running codex post-install hook with config=%s skipPrompt=%v", codexConfigPath, skipPrompt)
		ensureCodexFeatureFlag(codexConfigPath, skipPrompt)
	}
}

// ensureCodexFeatureFlag checks ~/.codex/config.toml for
// `hooks = true` under [features] and, if missing, asks the user
// whether to add it. When the flag is absent sir's hook commands still
// register but Codex won't actually fire them until the user enables the
// feature flag.
func ensureCodexFeatureFlag(configPath string, skipPrompt bool) {
	codexDebugf("ensureCodexFeatureFlag path=%s skipPrompt=%v", configPath, skipPrompt)
	status, lines, err := codexHooksFlagStatus(configPath)
	codexDebugf("codexHooksFlagStatus=%d err=%v", status, err)
	switch status {
	case codexFlagAlreadyEnabled:
		codexDebugf("codex hooks already enabled; no feature-flag write needed")
		return
	case codexFlagLegacyEnabled:
		fmt.Printf("  %s uses the deprecated `codex_hooks = true` key. Codex prints a deprecation warning on every run.\n", configPath)
		if !skipPrompt && !promptYesNo("  Migrate it to the canonical `hooks = true`? [y/N] ") {
			fmt.Println("  [ ] Skipped. Hooks still work via the legacy alias but Codex will keep warning.")
			return
		}
		codexDebugf("migrating legacy codex_hooks -> canonical hooks in %s", configPath)
		newLines := migrateCodexLegacyHooksFlag(lines)
		out := strings.Join(newLines, "\n")
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		if err := os.WriteFile(configPath, []byte(out), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: could not write %s: %v\n", configPath, err)
			return
		}
		fmt.Printf("  [x] Migrated codex_hooks -> hooks=true in %s\n", configPath)
		return
	case codexFlagUnreadable:
		codexDebugf("codex config unreadable: %v", err)
		fmt.Fprintf(os.Stderr, "  WARNING: could not read %s: %v\n", configPath, err)
		fmt.Fprintln(os.Stderr, "  Codex hooks require `hooks = true` under [features] in this file.")
		return
	case codexFlagMissingFile:
		fmt.Printf("  %s does not exist. Codex hooks require hooks=true under [features].\n", configPath)
		if !skipPrompt && !promptYesNo("  Create it now? [y/N] ") {
			fmt.Println("  [ ] Skipped. Hooks are installed but will NOT fire until you enable hooks=true.")
			return
		}
		codexDebugf("creating missing codex config at %s", configPath)
		if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: could not create %s dir: %v\n", filepath.Dir(configPath), err)
			return
		}
		body := "[features]\nhooks = true\n"
		if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: could not write %s: %v\n", configPath, err)
			return
		}
		fmt.Printf("  [x] Created %s with hooks=true\n", configPath)
	case codexFlagNeedsEnable:
		fmt.Printf("  %s exists but hooks is not enabled. Codex hooks require `hooks = true` under [features].\n", configPath)
		if !skipPrompt && !promptYesNo("  Add/enable it now? [y/N] ") {
			fmt.Println("  [ ] Skipped. Hooks are installed but will NOT fire until you enable hooks=true.")
			return
		}
		codexDebugf("updating codex config in-place to enable hooks=true")
		newLines := insertCodexHooksFlag(lines)
		out := strings.Join(newLines, "\n")
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		if err := os.WriteFile(configPath, []byte(out), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: could not write %s: %v\n", configPath, err)
			return
		}
		fmt.Printf("  [x] Enabled hooks=true in %s\n", configPath)
	}
}

type codexFlagStatus int

const (
	codexFlagAlreadyEnabled codexFlagStatus = iota
	codexFlagNeedsEnable
	codexFlagMissingFile
	codexFlagUnreadable
	// codexFlagLegacyEnabled means the deprecated `codex_hooks = true` key is
	// present (and enabled) but the canonical `hooks = true` is not. Codex
	// 0.135 still honors the alias but prints a deprecation warning on every
	// invocation; sir offers to migrate it to the canonical key.
	codexFlagLegacyEnabled
)

// codexHooksFlagStatus inspects a Codex config.toml file (line-by-line)
// without a TOML library) and reports whether [features] contains an
// enabled hook feature flag. It accepts the canonical `hooks=true` flag and
// the legacy `codex_hooks=true` compatibility key. Returns the file lines for
// in-place mutation when the flag needs to be added.
func codexHooksFlagStatus(path string) (codexFlagStatus, []string, error) {
	codexDebugf("scanning codex config for feature flag: %s", path)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			codexDebugf("codex config missing: %s", path)
			return codexFlagMissingFile, nil, nil
		}
		codexDebugf("cannot open codex config %s: %v", path, err)
		return codexFlagUnreadable, nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		codexDebugf("scan error reading codex config %s: %v", path, err)
		return codexFlagUnreadable, nil, err
	}

	inFeatures := false
	canonicalEnabled := false
	legacyEnabled := false
	for _, raw := range lines {
		trim := strings.TrimSpace(raw)
		if strings.HasPrefix(trim, "#") || trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			inFeatures = trim == "[features]"
			continue
		}
		if !inFeatures {
			continue
		}
		key, value := parseTOMLStringKeyValue(trim)
		switch key {
		case "hooks":
			codexDebugf("found canonical feature key hooks=%s in %s", value, path)
			if strings.EqualFold(value, "true") {
				canonicalEnabled = true
			}
		case "codex_hooks":
			codexDebugf("found legacy feature key codex_hooks=%s in %s", value, path)
			if strings.EqualFold(value, "true") {
				legacyEnabled = true
			}
		}
	}
	// Canonical wins: if hooks=true is present the deprecation warning is gone,
	// regardless of any stale codex_hooks key alongside it.
	if canonicalEnabled {
		codexDebugf("codex canonical hooks flag enabled in %s", path)
		return codexFlagAlreadyEnabled, lines, nil
	}
	if legacyEnabled {
		codexDebugf("only legacy codex_hooks=true present in %s; migration offered", path)
		return codexFlagLegacyEnabled, lines, nil
	}
	return codexFlagNeedsEnable, lines, nil
}

func parseTOMLStringKeyValue(line string) (string, string) {
	if !strings.Contains(line, "=") {
		return "", ""
	}
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", ""
	}
	key := strings.TrimSpace(parts[0])
	if key == "" {
		return "", ""
	}
	rest := strings.TrimSpace(parts[1])
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = strings.TrimSpace(rest[:i])
	}
	rest = strings.TrimSpace(rest)
	if (strings.HasPrefix(rest, "\"") && strings.HasSuffix(rest, "\"")) ||
		(strings.HasPrefix(rest, "'") && strings.HasSuffix(rest, "'")) {
		rest = strings.Trim(rest, "\"'")
	}
	return key, rest
}

// insertCodexHooksFlag returns a new line slice with hooks=true
// inserted under an existing [features] section, or with [features] and
// the flag appended if no such section exists. Preserves all unrelated
// content verbatim.
func insertCodexHooksFlag(lines []string) []string {
	codexDebugf("insertCodexHooksFlag input line count=%d", len(lines))
	featuresIdx := -1
	for i, raw := range lines {
		trim := strings.TrimSpace(raw)
		if trim == "[features]" {
			featuresIdx = i
			break
		}
	}
	if featuresIdx < 0 {
		codexDebugf("no [features] section found; appending new section")
		out := append([]string(nil), lines...)
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, "[features]", "hooks = true")
		return out
	}

	end := len(lines)
	for i := featuresIdx + 1; i < len(lines); i++ {
		trim := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			end = i
			break
		}
	}
	for i := featuresIdx + 1; i < end; i++ {
		key, _ := parseTOMLStringKeyValue(strings.TrimSpace(lines[i]))
		if key == "hooks" {
			codexDebugf("replacing existing hooks key at line %d", i)
			out := append([]string(nil), lines...)
			out[i] = "hooks = true"
			return out
		}
	}

	out := append([]string(nil), lines[:featuresIdx+1]...)
	out = append(out, "hooks = true")
	out = append(out, lines[featuresIdx+1:]...)
	return out
}

// migrateCodexLegacyHooksFlag rewrites a `codex_hooks = true` line under
// [features] to the canonical `hooks = true`, preserving leading indentation.
// If a canonical `hooks` key already exists elsewhere in [features], the legacy
// line is dropped instead of duplicated. Unrelated content is preserved verbatim.
func migrateCodexLegacyHooksFlag(lines []string) []string {
	featuresIdx := -1
	for i, raw := range lines {
		if strings.TrimSpace(raw) == "[features]" {
			featuresIdx = i
			break
		}
	}
	if featuresIdx < 0 {
		return lines
	}
	end := len(lines)
	for i := featuresIdx + 1; i < len(lines); i++ {
		trim := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			end = i
			break
		}
	}
	// Distinguish an ENABLED canonical key from a present-but-disabled one. If
	// `hooks = true` already exists, the legacy line is redundant and dropped.
	// But if only `hooks = false` exists (alongside `codex_hooks = true`),
	// dropping the legacy line would leave hooks DISABLED — so instead we flip
	// that canonical line to true and drop the legacy line.
	canonicalEnabled := false
	canonicalDisabledIdx := -1
	for i := featuresIdx + 1; i < end; i++ {
		key, value := parseTOMLStringKeyValue(strings.TrimSpace(lines[i]))
		if key != "hooks" {
			continue
		}
		if strings.EqualFold(value, "true") {
			canonicalEnabled = true
			break
		}
		canonicalDisabledIdx = i
	}
	out := make([]string, 0, len(lines))
	for i, raw := range lines {
		key := ""
		if i > featuresIdx && i < end {
			key, _ = parseTOMLStringKeyValue(strings.TrimSpace(raw))
		}
		// Flip a present-but-disabled canonical `hooks = false` to true so the
		// migration never silently disables hooks. A legacy-enabled config
		// (codex_hooks = true) with a disabled canonical key is treated as
		// enabled — for a security runtime, erring toward hooks-on is fail-safe.
		if i == canonicalDisabledIdx && !canonicalEnabled {
			indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
			out = append(out, indent+"hooks = true")
			continue
		}
		if key != "codex_hooks" {
			out = append(out, raw)
			continue
		}
		// Drop the legacy line when a canonical hooks key is (or was just made)
		// enabled; otherwise rewrite the legacy line in place to canonical.
		if canonicalEnabled || canonicalDisabledIdx >= 0 {
			continue
		}
		indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
		out = append(out, indent+"hooks = true")
	}
	return out
}

// codexHookTrust summarizes whether Codex has recorded trust for sir's hooks.
//
// Codex 0.135/0.136 require the user to review and trust each hook (the
// "Hooks need review" prompt) before it will fire interactively. Trust is
// recorded in config.toml under [hooks.state] keyed by
// "<hooks.json path>:<event>:<group>:<idx>" with a trusted_hash. An event with
// no trust entry will not fire until the user accepts the review prompt; a
// stale entry (hooks.json changed since trust) likewise stops the hook firing.
type codexHookTrust struct {
	configReadable bool   // could we read config.toml at all
	hasFeaturesGate bool  // [hooks.state] present with ≥1 codex hooks.json entry
	trustedEvents  map[string]bool // snake_case event token -> trusted
}

// codexEventTrustToken maps a sir wire event name to the snake_case token
// Codex uses in [hooks.state] keys.
var codexEventTrustToken = map[string]string{
	"PreToolUse":        "pre_tool_use",
	"PermissionRequest": "permission_request",
	"PostToolUse":       "post_tool_use",
	"SessionStart":      "session_start",
	"UserPromptSubmit":  "user_prompt_submit",
	"Stop":              "stop",
}

// readCodexHookTrust scans config.toml's [hooks.state] for trust entries that
// reference hooksJSONPath. trustedEvents is keyed by the snake_case event token
// and records only events that have BOTH a state-table header AND a non-empty
// trusted_hash on the following line(s).
//
// Important: sir cannot recompute Codex's per-hook trusted_hash (it is Codex's
// own canonical hash of the exact hook definition), so the presence of a hash
// does NOT prove it matches the current hooks.json — Codex re-verifies that at
// session start. callers must not claim hooks are "trusted" with certainty;
// they can only report whether a trust entry exists. A header with an empty or
// missing trusted_hash is treated as not-trusted (the stale/cleared case).
func readCodexHookTrust(configPath, hooksJSONPath string) (codexHookTrust, error) {
	out := codexHookTrust{trustedEvents: map[string]bool{}}
	f, err := os.Open(configPath)
	if err != nil {
		return out, err
	}
	defer f.Close()
	out.configReadable = true

	prefix := "[hooks.state.\"" + hooksJSONPath + ":"
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	currentEvent := "" // event whose trusted_hash we're still looking for
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, prefix) {
			out.hasFeaturesGate = true
			// line: [hooks.state."<path>:<event>:<group>:<idx>"]
			rest := strings.TrimPrefix(line, prefix)
			rest = strings.TrimSuffix(rest, "\"]")
			currentEvent = ""
			if i := strings.Index(rest, ":"); i >= 0 {
				currentEvent = rest[:i]
			}
			continue
		}
		// A new [table] header ends the current trust block.
		if strings.HasPrefix(line, "[") {
			currentEvent = ""
			continue
		}
		if currentEvent == "" {
			continue
		}
		if key, value := parseTOMLStringKeyValue(line); key == "trusted_hash" && strings.TrimSpace(value) != "" {
			out.trustedEvents[currentEvent] = true
			currentEvent = ""
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func codexDebugf(format string, args ...interface{}) {
	if os.Getenv("SIR_DEBUG_HOOKS") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "DEBUG codex-install: "+format+"\n", args...)
}

func promptYesNo(msg string) bool {
	fmt.Print(msg)
	var confirm string
	fmt.Scanln(&confirm)
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	return confirm == "y" || confirm == "yes"
}
