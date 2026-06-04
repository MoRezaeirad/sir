package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/provider"
	"github.com/somoore/sir/pkg/sdk"
)

// cmdProvider handles: sir provider <subcommand> [args...]
func cmdProvider(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, providerUsage)
		os.Exit(1)
	}
	switch args[0] {
	// Lifecycle management
	case "list":
		cmdProviderList(args[1:])
	case "install":
		cmdProviderInstall(args[1:])
	case "uninstall":
		cmdProviderUninstall(args[1:])
	case "enable":
		cmdProviderEnable(args[1:])
	case "disable":
		cmdProviderDisable(args[1:])
	case "use":
		cmdProviderUse(args[1:])
	case "swap":
		cmdProviderSwap(args[1:])
	case "authoritative":
		cmdProviderAuthoritative(args[1:])
	case "advisory":
		cmdProviderAdvisory(args[1:])
	case "configure":
		cmdProviderConfigure(args[1:])
	case "status":
		cmdProviderStatus(args[1:])
	// Development / validation tools (existing)
	case "validate":
		cmdProviderValidate(args[1:])
	case "test":
		cmdProviderTest(args[1:])
	case "verify-containment":
		cmdProviderVerifyContainment(args[1:])
	case "health":
		cmdProviderHealth(args[1:])
	case "scaffold":
		cmdProviderScaffold(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown provider subcommand: %s\n\n%s\n", args[0], providerUsage)
		os.Exit(1)
	}
}

const providerUsage = `sir provider — manage SIR providers (policy engines, sandboxes, observability)

Lifecycle:
  sir provider list [--kind <kind>]           list registered providers
  sir provider install <manifest.yaml>        register + validate a provider
  sir provider uninstall <name>               remove registration (files kept)
  sir provider enable <name>                  enable a registered provider
  sir provider disable <name>                 disable without removing
  sir provider use <name>                     set as active (exclusive kinds)
  sir provider swap <old> <new>               atomically swap active provider
  sir provider authoritative <name> [--on-failure ask|deny] [--yes]
                                              make a policy provider the DECISION
                                              point (its verdict replaces native)
  sir provider advisory <name> [--yes]        demote back to advisory (default)
  sir provider configure <name> --set k=v     set provider-specific config
  sir provider status [<name>]                health check and active status

Development:
  sir provider validate <manifest.yaml>       validate manifest schema
  sir provider test <manifest.yaml>           run fixture round-trips
  sir provider verify-containment <manifest>  prove an effect provider really contains
  sir provider health [directory]             health check providers in dir
  sir provider scaffold --name <n> --kind <k> create new provider template

Provider kinds: policy_provider  effect_provider  signal_provider
                advisory_provider  export_provider`

// ─── Lifecycle commands ──────────────────────────────────────────────────────

func cmdProviderList(args []string) {
	kind := ""
	showAll := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--kind":
			if i+1 >= len(args) {
				fatal("--kind requires a value")
			}
			kind = args[i+1]
			i++
		case "--all":
			showAll = true
		}
	}
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	entries := reg.Providers
	if kind != "" {
		var filtered []provider.Entry
		for _, e := range entries {
			if e.Kind == kind {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}
	if !showAll {
		var enabled []provider.Entry
		for _, e := range entries {
			if e.Enabled {
				enabled = append(enabled, e)
			}
		}
		if len(enabled) > 0 || len(entries) == 0 {
			entries = enabled
		}
	}
	if len(entries) == 0 {
		fmt.Println("No providers registered. Use `sir provider install <manifest.yaml>` to add one.")
		return
	}
	fmt.Printf("%-30s %-20s %-10s %-10s %s\n", "NAME", "KIND", "VERSION", "STATUS", "HEALTH")
	fmt.Printf("%-30s %-20s %-10s %-10s %s\n",
		strings.Repeat("-", 30), strings.Repeat("-", 20),
		strings.Repeat("-", 10), strings.Repeat("-", 10), strings.Repeat("-", 10))
	simulated := false
	for _, e := range entries {
		status := "inactive"
		if e.Enabled {
			status = "active"
		}
		health := e.Health.Status
		// Enforcement honesty: flag simulated effect providers so the listing
		// never implies capability plumbing is real OS enforcement.
		if e.Kind == "effect_provider" && entryDeclaresContainment(e) && providerEnforcement(e) != "real" {
			health = strings.TrimSpace(health + " (simulated)")
			simulated = true
		}
		fmt.Printf("%-30s %-20s %-10s %-10s %s\n",
			e.Name, e.Kind, e.Version, status, health)
	}
	if simulated {
		fmt.Println()
		fmt.Println("  (simulated) = effect provider declares contain/block capability but applies")
		fmt.Println("                no real OS-level enforcement — capability plumbing only.")
	}
}

func cmdProviderInstall(args []string) {
	if len(args) == 0 {
		fatal("usage: sir provider install <manifest.yaml>")
	}
	manifestPath, err := filepath.Abs(args[0])
	if err != nil {
		fatal("resolve path: %v", err)
	}

	// Validate manifest before registering.
	m, issues := loadAndValidateManifest(manifestPath)
	if len(issues) > 0 {
		for _, iss := range issues {
			fmt.Fprintf(os.Stderr, "error: %s\n", iss)
		}
		os.Exit(1)
	}

	// Resolve entrypoint to absolute path.
	dir := filepath.Dir(manifestPath)
	entrypoint, err := filepath.Abs(filepath.Join(dir, m.Entrypoint))
	if err != nil {
		fatal("resolve entrypoint: %v", err)
	}

	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}

	e := provider.Entry{
		Name:         m.Name,
		Kind:         m.Kind,
		Version:      m.Version,
		ManifestPath: manifestPath,
		Entrypoint:   entrypoint,
		Platforms:    m.Platforms,
		Capabilities: m.Capabilities,
		Enabled:      true,
		InstalledBy:  "sir provider install",
	}
	if err := reg.Add(e); err != nil {
		fatal("%v", err)
	}

	// Run a quick health check.
	healthy, reason := provider.HealthCheck(e)
	healthStatus := provider.HealthHealthy
	if !healthy {
		healthStatus = provider.HealthUnhealthy
		fmt.Fprintf(os.Stderr, "warning: health check failed: %s\n", reason)
	}
	reg.UpdateHealth(m.Name, healthStatus, reason)

	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
	fmt.Printf("Installed provider: %s (%s) — %s\n", m.Name, m.Kind, healthStatus)
	if e.Kind == "effect_provider" || e.Kind == "policy_provider" {
		fmt.Printf("Use `sir provider use %s` to make it the active %s.\n", m.Name, m.Kind)
	}
}

func cmdProviderUninstall(args []string) {
	if len(args) == 0 {
		fatal("usage: sir provider uninstall <name>")
	}
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	if err := reg.Remove(args[0]); err != nil {
		fatal("%v", err)
	}
	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
	fmt.Printf("Uninstalled provider: %s (files not deleted)\n", args[0])
}

func cmdProviderEnable(args []string) {
	if len(args) == 0 {
		fatal("usage: sir provider enable <name>")
	}
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	if err := reg.Enable(args[0]); err != nil {
		fatal("%v", err)
	}
	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
	fmt.Printf("Enabled: %s\n", args[0])
}

func cmdProviderDisable(args []string) {
	if len(args) == 0 {
		fatal("usage: sir provider disable <name>")
	}
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	if err := reg.Disable(args[0]); err != nil {
		fatal("%v", err)
	}
	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
	fmt.Printf("Disabled: %s\n", args[0])
}

func cmdProviderUse(args []string) {
	if len(args) == 0 {
		fatal("usage: sir provider use <name>")
	}
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	e, ok := reg.ByName(args[0])
	if !ok {
		fatal("provider %q not found", args[0])
	}
	kind := e.Kind
	if err := reg.Use(args[0]); err != nil {
		fatal("%v", err)
	}
	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
	fmt.Printf("Active %s: %s\n", kind, args[0])
}

func cmdProviderSwap(args []string) {
	if len(args) < 2 {
		fatal("usage: sir provider swap <old> <new>")
	}
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	if err := reg.Swap(args[0], args[1]); err != nil {
		fatal("%v", err)
	}
	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
	fmt.Printf("Swapped: %s → %s\n", args[0], args[1])
}

// cmdProviderAuthoritative promotes a policy provider to authoritative (PDP
// delegation): its verdict REPLACES the native decision. Because this is a
// security-posture change, it prints what it means and requires confirmation
// (or --yes).
func cmdProviderAuthoritative(args []string) {
	name := ""
	onFailure := provider.OnFailureAsk
	autoYes := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--on-failure":
			if i+1 >= len(args) {
				fatal("--on-failure requires a value (ask|deny)")
			}
			onFailure = args[i+1]
			i++
		case "--yes", "-y":
			autoYes = true
		default:
			if name == "" {
				name = args[i]
			} else {
				fatal("unexpected argument %q", args[i])
			}
		}
	}
	if name == "" {
		fatal("usage: sir provider authoritative <name> [--on-failure ask|deny] [--yes]")
	}

	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	e, ok := reg.ByName(name)
	if !ok {
		fatal("provider %q not found", name)
	}
	// Validate up front so the warning isn't printed for an invalid request.
	if e.Kind != provider.KindPolicy {
		fatal("only a policy_provider can be authoritative; %q is a %s", name, e.Kind)
	}
	if !e.Enabled {
		fatal("provider %q must be enabled first: run `sir provider use %s`", name, name)
	}
	if onFailure != provider.OnFailureAsk && onFailure != provider.OnFailureDeny {
		fatal("--on-failure must be ask or deny, got %q", onFailure)
	}

	fmt.Printf(`Make %q the AUTHORITATIVE policy provider?

  • Its verdict will REPLACE SIR's native decision — including GRANTING actions
    the native engine would gate. External policy becomes the decision point.
  • If it is unreachable / times out / returns nothing, SIR fails closed (%s).
  • These integrity floors still apply regardless: SIR-state tamper, posture-file
    writes, secret-exfil egress, DNS-tunnel, MCP-injection, delegation-after-
    injection, opaque-shell.
  • Run the provider WARM (a localhost sidecar/daemon), not spawn-per-call.

Type 'y' to confirm: `, name, onFailure)
	if !confirmYes(autoYes) {
		fmt.Println("Cancelled.")
		return
	}

	if err := reg.SetAuthority(name, provider.AuthorityAuthoritative, onFailure); err != nil {
		fatal("%v", err)
	}
	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
	fmt.Printf("%s is now AUTHORITATIVE (on-failure: %s). Verify: sir provider status %s\n", name, onFailure, name)
}

// cmdProviderAdvisory demotes a policy provider back to advisory (the default):
// its verdict becomes input the native engine composes, never the final word.
func cmdProviderAdvisory(args []string) {
	name := ""
	autoYes := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--yes", "-y":
			autoYes = true
		default:
			if name == "" {
				name = args[i]
			} else {
				fatal("unexpected argument %q", args[i])
			}
		}
	}
	if name == "" {
		fatal("usage: sir provider advisory <name> [--yes]")
	}

	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	e, ok := reg.ByName(name)
	if !ok {
		fatal("provider %q not found", name)
	}
	if !e.IsAuthoritative() {
		fmt.Printf("%s is already advisory — nothing to do.\n", name)
		return
	}

	fmt.Printf("Demote %q from authoritative back to advisory? SIR's native engine resumes making the final decision.\nType 'y' to confirm: ", name)
	if !confirmYes(autoYes) {
		fmt.Println("Cancelled.")
		return
	}

	if err := reg.SetAuthority(name, provider.AuthorityAdvisory, ""); err != nil {
		fatal("%v", err)
	}
	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
	fmt.Printf("%s is now advisory.\n", name)
}

func cmdProviderConfigure(args []string) {
	// Usage: sir provider configure <name> --set key=value [--set key2=val2]
	if len(args) < 3 {
		fatal("usage: sir provider configure <name> --set key=value")
	}
	name := args[0]
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	changed := false
	for i := 1; i < len(args); i++ {
		if args[i] == "--set" && i+1 < len(args) {
			kv := args[i+1]
			idx := strings.IndexByte(kv, '=')
			if idx < 0 {
				fatal("--set requires key=value, got: %s", kv)
			}
			k, v := kv[:idx], kv[idx+1:]
			if err := reg.Configure(name, k, v); err != nil {
				fatal("%v", err)
			}
			fmt.Printf("Set %s.%s = %s\n", name, k, v)
			changed = true
			i++
		}
	}
	if !changed {
		fatal("no --set flags provided")
	}
	if err := reg.Save(); err != nil {
		fatal("save registry: %v", err)
	}
}

func cmdProviderStatus(args []string) {
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}

	entries := reg.Providers
	if len(args) > 0 {
		e, ok := reg.ByName(args[0])
		if !ok {
			fatal("provider %q not found", args[0])
		}
		entries = []provider.Entry{*e}
	}

	for _, e := range entries {
		fmt.Printf("Provider: %s\n", e.Name)
		fmt.Printf("  Kind:       %s\n", e.Kind)
		fmt.Printf("  Version:    %s\n", e.Version)
		fmt.Printf("  Enabled:    %v\n", e.Enabled)
		if e.IsAuthoritative() {
			fmt.Printf("  Authority:  AUTHORITATIVE (verdict replaces native; on-failure: %s)\n", e.FailureVerdict())
		} else if e.Kind == provider.KindPolicy {
			fmt.Printf("  Authority:  advisory\n")
		}
		fmt.Printf("  Entrypoint: %s\n", e.Entrypoint)
		// Enforcement honesty: surface simulated effect providers explicitly so a
		// real OS-level enforcer is never confused with capability plumbing.
		if e.Kind == "effect_provider" && entryDeclaresContainment(e) {
			switch providerEnforcement(e) {
			case "real":
				fmt.Printf("  Enforcement: real (applies OS-level containment)\n")
			default:
				fmt.Printf("  Enforcement: simulated — capability plumbing, not real OS enforcement\n")
			}
		}
		// Live health check.
		healthy, reason := provider.HealthCheck(e)
		if healthy {
			fmt.Printf("  Health:     healthy\n")
			reg.UpdateHealth(e.Name, provider.HealthHealthy, "")
		} else {
			fmt.Printf("  Health:     unhealthy — %s\n", reason)
			reg.UpdateHealth(e.Name, provider.HealthUnhealthy, reason)
		}
		if len(e.Config) > 0 {
			fmt.Printf("  Config:\n")
			for k, v := range e.Config {
				fmt.Printf("    %s = %s\n", k, v)
			}
		}
		fmt.Println()
	}
	_ = reg.Save() // persist health check results; non-fatal
}

func cmdProviderValidate(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: sir provider validate <manifest.yaml>\n")
		os.Exit(1)
	}
	m, issues := loadAndValidateManifest(args[0])
	if m != nil {
		fmt.Printf("provider: %s (%s)\n", m.Name, m.Kind)
		fmt.Printf("version:  %s\n", m.Version)
		fmt.Printf("protocol: %s\n", m.Protocol)
	}
	// Advisory NOTE (does not fail validation): an effect provider that declares
	// contain/block capability but omits an explicit enforcement signal defaults
	// to "simulated". Recommend declaring it explicitly so consumers can tell a
	// real OS-level enforcer apart from capability plumbing.
	if m != nil && m.Kind == sdk.KindEffectProvider && declaresContainment(m) && m.Enforcement == "" {
		fmt.Printf("NOTE: effect provider declares contain/block capability but no enforcement signal.\n")
		fmt.Printf("      It defaults to enforcement:simulated. Add `enforcement: simulated` (capability\n")
		fmt.Printf("      plumbing only) or `enforcement: real` (applies OS-level containment) to be explicit.\n")
	}
	if len(issues) == 0 {
		fmt.Println("ok: manifest is valid")
		return
	}
	for _, iss := range issues {
		fmt.Fprintf(os.Stderr, "error: %s\n", iss)
	}
	os.Exit(1)
}

// declaresContainment reports whether a manifest's capabilities declare
// contain:true or block:true — the capabilities that require an honesty signal.
func declaresContainment(m *sdk.ProviderManifest) bool {
	if m == nil || m.Capabilities == nil {
		return false
	}
	contain, _ := m.Capabilities["contain"].(bool)
	block, _ := m.Capabilities["block"].(bool)
	return contain || block
}

// entryDeclaresContainment reports whether a registered provider's persisted
// capabilities declare contain:true or block:true. The registry stores
// capabilities as decoded JSON, so booleans may arrive as bool or any.
func entryDeclaresContainment(e provider.Entry) bool {
	return capTrue(e.Capabilities, "contain") || capTrue(e.Capabilities, "block")
}

func capTrue(caps map[string]any, key string) bool {
	if caps == nil {
		return false
	}
	b, _ := caps[key].(bool)
	return b
}

// providerEnforcement resolves an effect provider's enforcement honesty signal.
// The manifest's top-level enforcement field is the authoritative source, so we
// re-read it from disk; if unavailable we fall back to the capabilities mirror
// persisted in the registry. Absent everywhere means "simulated".
func providerEnforcement(e provider.Entry) string {
	if e.ManifestPath != "" {
		if m, issues := loadAndValidateManifest(e.ManifestPath); m != nil && len(issues) == 0 {
			if m.Enforcement != "" {
				return m.Enforcement
			}
		}
	}
	if s, ok := e.Capabilities["enforcement"].(string); ok && s != "" {
		return s
	}
	return "simulated"
}

// cmdProviderVerifyContainment proves that an effect provider REALLY contains —
// it asks the provider to demonstrate containment (run a contained action and
// confirm the boundary held), not merely declare the capability. This is the
// evidence behind an `enforcement: real` manifest claim: a provider that cannot
// demonstrate containment must not be trusted to enforce.
func cmdProviderVerifyContainment(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: sir provider verify-containment <manifest.yaml> [--write-capture <case-dir>]\n")
		os.Exit(1)
	}
	writeCaptureDir := ""
	var positional []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--write-capture" && i+1 < len(args) {
			writeCaptureDir = args[i+1]
			i++
			continue
		}
		positional = append(positional, args[i])
	}
	if len(positional) == 0 {
		fatal("usage: sir provider verify-containment <manifest.yaml> [--write-capture <case-dir>]")
	}
	manifestPath, err := filepath.Abs(positional[0])
	if err != nil {
		fatal("resolve path: %v", err)
	}
	m, issues := loadAndValidateManifest(manifestPath)
	if len(issues) > 0 {
		for _, iss := range issues {
			fmt.Fprintf(os.Stderr, "error: %s\n", iss)
		}
		os.Exit(1)
	}
	if m.Kind != sdk.KindEffectProvider {
		fatal("verify-containment requires an effect_provider, got %s", m.Kind)
	}
	entrypoint, err := filepath.Abs(filepath.Join(filepath.Dir(manifestPath), m.Entrypoint))
	if err != nil {
		fatal("resolve entrypoint: %v", err)
	}

	fmt.Printf("verifying containment: %s\n", m.Name)
	proof, err := provider.VerifyContainment(provider.Entry{Name: m.Name, Entrypoint: entrypoint})
	if err != nil && !proof.Verified {
		fmt.Fprintf(os.Stderr, "containment NOT verified: %v\n", err)
	}
	for k, v := range proof.Evidence {
		fmt.Printf("  %s: %v\n", k, v)
	}
	if proof.Verified {
		fmt.Printf("VERIFIED: %s demonstrably contains (enforcement:real is justified)\n", m.Name)
		if writeCaptureDir != "" {
			if err := writeContainmentCapture(writeCaptureDir, m.Name, proof); err != nil {
				fatal("write capture: %v", err)
			}
			fmt.Printf("wrote capture proof: %s/capture.json\n", writeCaptureDir)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "NOT VERIFIED: %s did not demonstrate containment", m.Name)
	if proof.Reason != "" {
		fmt.Fprintf(os.Stderr, " — %s", proof.Reason)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "An enforcement:real claim requires demonstrated containment. Fix the provider or declare enforcement:simulated.")
	os.Exit(1)
}

// writeContainmentCapture writes a harness capture.json generated from a REAL
// containment verification. The capture scores `enforces` (contained mode +
// demonstrated provider_enforcement:real) and records the actual evidence —
// so the capture tier and the enforcement-honesty CI gate are backed by a real
// run, not a hand-authored claim. This is the capture runner for one provider.
func writeContainmentCapture(dir, providerName string, proof provider.ContainmentProof) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	caseID := filepath.Base(dir)
	capture := map[string]any{
		"_capture_note": fmt.Sprintf(
			"Generated by `sir provider verify-containment` from a REAL containment run of %s. "+
				"The provider executed an egress command inside a --network=none Docker jail and the "+
				"network boundary held (network_blocked=true). enforcement:real is demonstrated, not declared.",
			providerName),
		"case_id":               caseID,
		"mode":                  "contained",
		"provider_capabilities": []string{"contain", "record"},
		"provider_enforcement":  "real",
		"_containment_evidence": proof.Evidence,
		"_provider":             providerName,
		"signals": []map[string]any{{
			"schema_version": "sir.signal.v0",
			"signal_id":      "cap-" + caseID,
			"signal_time":    "2026-05-31T00:00:00Z",
			"source": map[string]any{
				"kind": providerName, "reliability": "declared_intent", "timing": "pre_exec",
				"provider": providerName, "provider_version": "0.2.0",
			},
			"session":     map[string]any{"session_id": "sess_" + caseID},
			"actor_claim": map[string]any{"kind": "ai_coding_agent", "name": "claude-code"},
			"action_claim": map[string]any{
				"type":   "network_connect",
				"target": map[string]any{"display": "wget http://example.com", "sensitivity": "external_network"},
			},
		}},
		"expected": map[string]any{"enforceability": "enforces", "verdict": "ask"},
	}
	data, err := json.MarshalIndent(capture, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "capture.json"), append(data, '\n'), 0o644)
}

func cmdProviderTest(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: sir provider test <manifest.yaml>\n")
		os.Exit(1)
	}
	path := args[0]
	m, issues := loadAndValidateManifest(path)
	if len(issues) > 0 {
		for _, iss := range issues {
			fmt.Fprintf(os.Stderr, "error: %s\n", iss)
		}
		os.Exit(1)
	}

	dir := filepath.Dir(path)
	ep := filepath.Join(dir, m.Entrypoint)

	fmt.Printf("testing provider: %s\n", m.Name)

	caps, err := queryProviderCapabilities(ep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: capability query failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("capabilities ok:", string(caps))

	failures := 0
	isSignalProvider := m.Kind == sdk.KindSignalProvider
	for _, fix := range m.Fixtures {
		fixPath := fix
		if !filepath.IsAbs(fixPath) {
			fixPath = filepath.Join(dir, fix)
		}
		data, err := os.ReadFile(fixPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: fixture %s not found: %v\n", fix, err)
			failures++
			continue
		}
		if isSignalProvider {
			// Feed the fixture as a native source event; validate the emitted signal.
			if err := testSignalFixture(ep, data, fix, m); err != nil {
				fmt.Fprintf(os.Stderr, "error: fixture %s: %v\n", fix, err)
				failures++
				continue
			}
		} else {
			var obj map[string]any
			if err := json.Unmarshal(data, &obj); err != nil {
				fmt.Fprintf(os.Stderr, "error: fixture %s is not valid JSON: %v\n", fix, err)
				failures++
				continue
			}
			// Run the full round-trip based on the fixture's schema_version.
			sv, _ := obj["schema_version"].(string)
			var rtErr error
			switch sv {
			case sdk.SchemaEffectReqV0:
				rtErr = testEffectFixture(ep, data)
			case "sir.policy_request.v0":
				rtErr = testPolicyFixture(ep, data)
			case "sir.advisory_request.v0":
				rtErr = testAdvisoryFixture(ep, data)
			}
			if rtErr != nil {
				fmt.Fprintf(os.Stderr, "error: fixture %s: %v\n", fix, rtErr)
				failures++
				continue
			}
		}
		fmt.Printf("fixture ok: %s\n", fix)
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d fixture(s) failed\n", failures)
		os.Exit(1)
	}
	fmt.Println("ok: provider test passed")
}

var validKinds = map[string]bool{
	sdk.KindSignalProvider:   true,
	sdk.KindEffectProvider:   true,
	sdk.KindPolicyProvider:   true,
	sdk.KindAdvisoryProvider: true,
	sdk.KindExportProvider:   true,
}

var validProtocols = map[string]bool{
	"stdio-json": true,
}

func loadAndValidateManifest(path string) (*sdk.ProviderManifest, []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []string{"cannot read file: " + err.Error()}
	}

	m, err := parseProviderYAML(data)
	if err != nil {
		return nil, []string{"parse error: " + err.Error()}
	}

	var issues []string
	if m.SchemaVersion != sdk.SchemaProviderV0 {
		issues = append(issues, "schema_version must be "+sdk.SchemaProviderV0+", got: "+m.SchemaVersion)
	}
	if m.Name == "" {
		issues = append(issues, "name is required")
	}
	if !validKinds[m.Kind] {
		issues = append(issues, "invalid kind: "+m.Kind)
	}
	if m.Version == "" {
		issues = append(issues, "version is required")
	}
	if !validProtocols[m.Protocol] {
		issues = append(issues, "invalid protocol: "+m.Protocol)
	}
	if m.Entrypoint == "" {
		issues = append(issues, "entrypoint is required")
	} else {
		// API_SDK §5: validate entrypoint is executable (check against manifest dir).
		ep := filepath.Join(filepath.Dir(path), m.Entrypoint)
		if info, err := os.Stat(ep); err != nil {
			issues = append(issues, "entrypoint not found: "+ep)
		} else if info.Mode()&0o111 == 0 {
			issues = append(issues, "entrypoint not executable: "+ep)
		}
	}
	if m.Capabilities == nil {
		issues = append(issues, "capabilities block is required")
	}
	// Enforcement honesty signal: if present, it must be a known value. Absent is
	// allowed and conceptually equivalent to "simulated".
	if m.Enforcement != "" && m.Enforcement != "simulated" && m.Enforcement != "real" {
		issues = append(issues, "invalid enforcement: "+m.Enforcement+" (must be simulated|real)")
	}
	// Validate fixture references exist.
	for _, fix := range m.Fixtures {
		fixPath := fix
		if !filepath.IsAbs(fixPath) {
			fixPath = filepath.Join(filepath.Dir(path), fix)
		}
		if _, err := os.Stat(fixPath); err != nil {
			issues = append(issues, "fixture not found: "+fix)
		}
	}
	return m, issues
}

// parseProviderYAML parses the minimal YAML subset used in provider manifests
// without any external dependency. Handles flat string scalars, bracket-style
// lists, and block-style lists at one level of nesting.
func parseProviderYAML(data []byte) (*sdk.ProviderManifest, error) {
	m := &sdk.ProviderManifest{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	var currentKey string
	capsRaw := map[string]any{}

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		if indent == 0 {
			if strings.HasSuffix(trimmed, ":") {
				currentKey = strings.TrimSuffix(trimmed, ":")
				continue
			}
			kv := strings.SplitN(trimmed, ": ", 2)
			if len(kv) < 2 {
				continue
			}
			key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
			currentKey = key
			switch key {
			case "schema_version":
				m.SchemaVersion = val
			case "name":
				m.Name = val
			case "kind":
				m.Kind = val
			case "version":
				m.Version = val
			case "protocol":
				m.Protocol = val
			case "entrypoint":
				m.Entrypoint = val
			case "enforcement":
				m.Enforcement = val
			case "platforms":
				m.Platforms = parseBracketList(val)
			case "fixtures":
				m.Fixtures = parseBracketList(val)
			}
		} else if indent >= 2 {
			if strings.HasPrefix(trimmed, "- ") {
				item := strings.TrimPrefix(trimmed, "- ")
				switch currentKey {
				case "platforms":
					m.Platforms = append(m.Platforms, item)
				case "fixtures":
					m.Fixtures = append(m.Fixtures, item)
				default:
					if capsRaw[currentKey] == nil {
						capsRaw[currentKey] = []string{item}
					} else if sl, ok := capsRaw[currentKey].([]string); ok {
						capsRaw[currentKey] = append(sl, item)
					}
				}
			} else {
				kv := strings.SplitN(trimmed, ": ", 2)
				if len(kv) == 2 {
					key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
					if strings.HasPrefix(val, "[") {
						capsRaw[key] = parseBracketList(val)
					} else {
						switch val {
						case "true":
							capsRaw[key] = true
						case "false":
							capsRaw[key] = false
						default:
							capsRaw[key] = val
						}
					}
				}
			}
		}
	}

	if len(capsRaw) > 0 {
		m.Capabilities = capsRaw
	}
	return m, scanner.Err()
}

func parseBracketList(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// testEffectFixture sends an effect request fixture to the provider and validates
// the response. An honest "unavailable" or "not_supported" response is PASS —
// providers that cannot apply an effect must say so, not silently succeed.
func testEffectFixture(entrypoint string, requestData []byte) error {
	var obj map[string]any
	if err := json.Unmarshal(requestData, &obj); err != nil {
		return fmt.Errorf("fixture is not valid JSON: %w", err)
	}
	compact, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	requestedID, _ := obj["effect_id"].(string)

	input := `{"op":"capabilities"}` + "\n" + string(compact) + "\n"
	cmd := newProviderCommand(entrypoint)
	cmd.Stdin = strings.NewReader(input)
	pythonPath := "sdk/python"
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPath = pythonPath + ":" + existing
	}
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonPath)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("provider exited with error: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return fmt.Errorf("expected 2 output lines (capabilities + effect_result), got %d", len(lines))
	}

	var result sdk.EffectResult
	if err := json.Unmarshal([]byte(lines[1]), &result); err != nil {
		return fmt.Errorf("effect result is not valid JSON: %w", err)
	}
	return validateEffectResult(result, requestedID)
}

// testPolicyFixture sends a policy request fixture to the provider and validates
// the returned sir.policy_verdict.v0 (verdict enum, is_advisory).
func testPolicyFixture(entrypoint string, requestData []byte) error {
	out, err := roundTripProvider(entrypoint, requestData)
	if err != nil {
		return err
	}
	var resp struct {
		SchemaVersion string `json:"schema_version"`
		Verdict       string `json:"verdict"`
		IsAdvisory    bool   `json:"is_advisory"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return fmt.Errorf("policy verdict is not valid JSON: %w", err)
	}
	if resp.SchemaVersion != "sir.policy_verdict.v0" {
		return fmt.Errorf("schema_version must be sir.policy_verdict.v0, got %q", resp.SchemaVersion)
	}
	if resp.Verdict != "allow" && resp.Verdict != "ask" && resp.Verdict != "deny" {
		return fmt.Errorf("verdict %q is not a valid enum value (allow|ask|deny)", resp.Verdict)
	}
	if !resp.IsAdvisory {
		return fmt.Errorf("is_advisory must be true (policy providers are advisory only)")
	}
	return nil
}

// testAdvisoryFixture sends an advisory request fixture to the provider and
// validates the returned sir.advisory_signal.v0 (risk_level enum, is_advisory).
func testAdvisoryFixture(entrypoint string, requestData []byte) error {
	out, err := roundTripProvider(entrypoint, requestData)
	if err != nil {
		return err
	}
	var resp struct {
		SchemaVersion string `json:"schema_version"`
		RiskLevel     string `json:"risk_level"`
		IsAdvisory    bool   `json:"is_advisory"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return fmt.Errorf("advisory signal is not valid JSON: %w", err)
	}
	if resp.SchemaVersion != "sir.advisory_signal.v0" {
		return fmt.Errorf("schema_version must be sir.advisory_signal.v0, got %q", resp.SchemaVersion)
	}
	switch resp.RiskLevel {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("risk_level %q is not a valid enum value (low|medium|high|critical)", resp.RiskLevel)
	}
	if !resp.IsAdvisory {
		return fmt.Errorf("is_advisory must be true (advisory providers cannot lower deterministic risk)")
	}
	return nil
}

// roundTripProvider sends a capabilities probe + the compacted fixture and
// returns the second output line (the provider's response to the fixture).
func roundTripProvider(entrypoint string, requestData []byte) (string, error) {
	var obj map[string]any
	if err := json.Unmarshal(requestData, &obj); err != nil {
		return "", fmt.Errorf("fixture is not valid JSON: %w", err)
	}
	compact, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	input := `{"op":"capabilities"}` + "\n" + string(compact) + "\n"
	cmd := newProviderCommand(entrypoint)
	cmd.Stdin = strings.NewReader(input)
	pythonPath := "sdk/python"
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPath = pythonPath + ":" + existing
	}
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonPath)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("provider exited with error: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("expected 2 output lines (capabilities + response), got %d", len(lines))
	}
	return lines[1], nil
}

var validEffectStatuses = map[string]bool{
	sdk.EffectApplied:      true,
	sdk.EffectUnavailable:  true,
	sdk.EffectFailed:       true,
	sdk.EffectNotSupported: true,
}

func validateEffectResult(result sdk.EffectResult, requestedEffectID string) error {
	if result.SchemaVersion != sdk.SchemaEffectResV0 {
		return fmt.Errorf("schema_version must be %s, got %q", sdk.SchemaEffectResV0, result.SchemaVersion)
	}
	if requestedEffectID != "" && result.EffectID != requestedEffectID {
		return fmt.Errorf("effect_id mismatch: sent %q, got %q", requestedEffectID, result.EffectID)
	}
	if !validEffectStatuses[result.Status] {
		return fmt.Errorf("status %q is not a valid enum value", result.Status)
	}
	return nil
}

// testSignalFixture feeds a native event fixture to the provider and validates
// that it emits a conformant sir.signal.v0. m is used to check reliability/timing
// conformance (§6/§7: emitted must be within declared set).
func testSignalFixture(entrypoint string, eventData []byte, fixLabel string, m *sdk.ProviderManifest) error {
	// Re-compact the fixture to a single JSON line before sending.
	var obj map[string]any
	if err := json.Unmarshal(eventData, &obj); err != nil {
		return fmt.Errorf("fixture is not valid JSON: %w", err)
	}
	compact, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	// Send capabilities + the event as two newline-delimited JSON lines.
	input := `{"op":"capabilities"}` + "\n" + string(compact) + "\n"
	cmd := newProviderCommand(entrypoint)
	cmd.Stdin = strings.NewReader(input)
	pythonPath := "sdk/python"
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPath = pythonPath + ":" + existing
	}
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonPath)

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("provider exited with error: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	// First line is the capabilities response; second is the emitted signal.
	if len(lines) < 2 {
		return fmt.Errorf("expected 2 output lines (capabilities + signal), got %d", len(lines))
	}
	signalLine := lines[1]

	var sig sdk.Signal
	if err := json.Unmarshal([]byte(signalLine), &sig); err != nil {
		return fmt.Errorf("emitted output is not valid JSON: %w", err)
	}
	return validateSignal(sig, m)
}

var validReliabilities = map[string]bool{
	sdk.ReliabilityDeclaredIntent:   true,
	sdk.ReliabilityMediatedAction:   true,
	sdk.ReliabilityObservedRuntime:  true,
	sdk.ReliabilityEnforcedBoundary: true,
	sdk.ReliabilityAdvisorySignal:   true,
	sdk.ReliabilityUserDecision:     true,
	sdk.ReliabilityAdminPolicy:      true,
}

var validTimings = map[string]bool{
	sdk.TimingPreExec:    true,
	sdk.TimingDuringExec: true,
	sdk.TimingPostExec:   true,
	sdk.TimingUnknown:    true,
}

// validateSignal checks a signal satisfies the sir.signal.v0 required-field,
// enum conformance, and manifest conformance (§6/§7) rules.
func validateSignal(sig sdk.Signal, m *sdk.ProviderManifest) error {
	if sig.SchemaVersion != sdk.SchemaSignalV0 {
		return fmt.Errorf("schema_version must be %s, got %q", sdk.SchemaSignalV0, sig.SchemaVersion)
	}
	if sig.SignalID == "" {
		return fmt.Errorf("signal_id is required")
	}
	if sig.SignalTime == "" {
		return fmt.Errorf("signal_time is required")
	}
	if sig.Source.Kind == "" {
		return fmt.Errorf("source.kind is required")
	}
	if !validReliabilities[sig.Source.Reliability] {
		return fmt.Errorf("source.reliability %q is not a valid enum value", sig.Source.Reliability)
	}
	if !validTimings[sig.Source.Timing] {
		return fmt.Errorf("source.timing %q is not a valid enum value", sig.Source.Timing)
	}
	if sig.ActionClaim == nil {
		return fmt.Errorf("action_claim is required")
	}
	// Conformance §6/§7: emitted signal's reliability/timing must be within
	// the manifest's declared set. Providers must never claim more than they have.
	if err := validateSignalConformance(sig, m); err != nil {
		return err
	}
	return nil
}

// validateSignalConformance checks that the emitted signal's reliability and
// timing are within the set the manifest declared — honesty enforcement.
func validateSignalConformance(sig sdk.Signal, m *sdk.ProviderManifest) error {
	if m == nil || m.Capabilities == nil {
		return nil
	}
	// Extract declared reliabilities and timings from manifest capabilities.
	declaredRel := toStringSet(m.Capabilities["signal_reliability"])
	declaredTiming := toStringSet(m.Capabilities["timing"])

	if len(declaredRel) > 0 && !declaredRel[sig.Source.Reliability] {
		return fmt.Errorf("emitted reliability %q not in manifest declared set %v", sig.Source.Reliability, sortedKeys(declaredRel))
	}
	if len(declaredTiming) > 0 && !declaredTiming[sig.Source.Timing] {
		return fmt.Errorf("emitted timing %q not in manifest declared set %v", sig.Source.Timing, sortedKeys(declaredTiming))
	}
	return nil
}

func toStringSet(v any) map[string]bool {
	out := map[string]bool{}
	switch val := v.(type) {
	case []string:
		for _, s := range val {
			out[s] = true
		}
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// queryProviderCapabilities spawns the provider and sends {"op":"capabilities"}.
// Sets PYTHONPATH to include sdk/python so Python providers can import sir_sdk.
func queryProviderCapabilities(entrypoint string) ([]byte, error) {
	cmd := newProviderCommand(entrypoint)
	cmd.Stdin = strings.NewReader(`{"op":"capabilities"}` + "\n")
	// Inject sdk/python into PYTHONPATH so providers can do: import sir_sdk
	pythonPath := "sdk/python"
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPath = pythonPath + ":" + existing
	}
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonPath)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	line := strings.TrimSpace(string(out))
	var resp sdk.CapabilitiesResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return nil, fmt.Errorf("provider returned invalid JSON: %w", err)
	}
	if resp.SchemaVersion != sdk.SchemaCapabilitiesV0 {
		return nil, fmt.Errorf("provider returned wrong schema_version: %s", resp.SchemaVersion)
	}
	return []byte(line), nil
}

func newProviderCommand(entrypoint string) *exec.Cmd {
	return exec.Command(entrypoint) // #nosec G702 -- provider entrypoints are manifest-validated executable paths launched without a shell.
}
