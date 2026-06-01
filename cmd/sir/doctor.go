package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// doctorHealthV2 holds v2-specific status fields for the JSON probe.
type doctorHealthV2 struct {
	SirCoreEvalPresent  bool   `json:"sir_core_eval_present"`
	SirCoreEvalCallable bool   `json:"sir_core_eval_callable"`
	ActiveEngine        string `json:"active_engine"`
	ProviderCount       int    `json:"provider_count"`
}

// doctorHealth is a read-only health probe suitable for CI gating. `sir doctor`
// (no flag) repairs; `sir doctor --json` only reports, and exits non-zero when
// unhealthy so a pipeline can fail closed without sir mutating anything.
type doctorHealth struct {
	Healthy     bool            `json:"healthy"`
	Installed   bool            `json:"installed"`
	DenyAll     bool            `json:"deny_all"`
	LedgerValid bool            `json:"ledger_valid"`
	BinaryOK    bool            `json:"binary_ok"`
	Issues      []string        `json:"issues,omitempty"`
	V2          *doctorHealthV2 `json:"v2,omitempty"`
}

func doctorHealthJSON(projectRoot string) {
	h := doctorHealth{LedgerValid: true, BinaryOK: true, Issues: []string{}}
	if snap, err := buildStatusSnapshot(projectRoot); err == nil {
		h.Installed = snap.installed
		if snap.ledgerVerifyErr != nil {
			h.LedgerValid = false
			h.Issues = append(h.Issues, "ledger chain invalid")
		}
		if snap.state != nil && snap.state.DenyAll {
			h.DenyAll = true
			h.Issues = append(h.Issues, "session in deny-all (run `sir doctor` or `sir unlock`)")
		}
	} else {
		h.Issues = append(h.Issues, "cannot load status: "+err.Error())
	}
	if inspectDoctorBinaryIntegrity().issue {
		h.BinaryOK = false
		h.Issues = append(h.Issues, "binary integrity mismatch (run `sir verify`)")
	}
	h.Healthy = len(h.Issues) == 0
	// v2 fields: Rust kernel status (best-effort, never makes h.Healthy false).
	h.V2 = buildV2HealthFields()
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(h)
	if !h.Healthy {
		os.Exit(1)
	}
}

func cmdDoctor(projectRoot string, args ...string) {
	for _, a := range args {
		switch a {
		case "--json":
			doctorHealthJSON(projectRoot)
			return
		default:
			fatal("usage: sir doctor [--json]")
		}
	}
	policy, err := loadManagedPolicyForCLI()
	if err != nil {
		fatal("load managed policy: %v", err)
	}
	l, err := loadLeaseForDoctor(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}

	fmt.Println(ac(auditBold, "sir doctor"))
	fmt.Println()
	if policy != nil {
		fmt.Printf("  %s\n", managedPolicyNotice(policy))
		fmt.Println("  Local baseline refresh is disabled under managed mode.")
		fmt.Println()
	}

	state, err := session.Load(projectRoot)
	if err != nil {
		bootstrap, bootstrapErr := doctorNoSessionBootstrap(projectRoot, policy, l)
		if bootstrapErr != nil {
			if bootstrap != nil {
				printDoctorLines(bootstrap.lines)
			}
			fatal("%v", bootstrapErr)
		}
		state = bootstrap.state
		printDoctorLines(bootstrap.lines)
		printDoctorMCPStatus(discoverMCPInventory(projectRoot))
		printDoctorOperability(projectRoot, state, 0, nil)
		binaryCheck := inspectDoctorBinaryIntegrity()
		printDoctorLines(binaryCheck.lines)
		fmt.Println()
		if binaryCheck.issue {
			fmt.Println(ac(auditBoldYellow, "sir doctor") + " — recovery complete, but attention needed")
			fmt.Println()
			fmt.Println("  Session state:      " + ac(auditGreen, "initialized"))
			fmt.Printf("  Binary integrity:   %s\n", ac(auditBoldRed, binaryCheck.summary))
			fmt.Println()
			fmt.Println(ac(auditDim, "Run 'sir verify' for full hash details, then reinstall sir to refresh ~/.sir/binary-manifest.json."))
		} else {
			fmt.Println(ac(auditBoldGreen, "sir doctor") + " — recovery complete")
			fmt.Println()
			fmt.Println("  Session initialized.")
			fmt.Println()
			fmt.Println(ac(auditDim, "sir is operational. Type 'claude' to resume."))
		}
		_ = state
		return
	}

	repair, repairedLease, repairErr := runDoctorRepairs(projectRoot, policy, l, state)
	if repairErr != nil {
		if repair != nil {
			printDoctorLines(repair.preAuditLines)
			printDoctorLines(repair.preOperability)
			printDoctorLines(repair.lateLines)
		}
		fatal("%v", repairErr)
	}
	_ = repairedLease
	fixed := repair.fixed
	printDoctorLines(repair.preAuditLines)

	statuses := collectAgentStatus()
	_, schemaFixed := printDoctorAgentChecks(statuses)
	fixed = fixed || schemaFixed

	printDoctorMCPStatus(discoverMCPInventory(projectRoot))
	printDoctorLines(repair.preOperability)
	ledgerCount, ledgerErr := ledger.Verify(projectRoot)
	if ledgerErr != nil {
		fmt.Printf("  WARNING: ledger verification failed: %v\n", ledgerErr)
	}
	printDoctorOperability(projectRoot, state, ledgerCount, repair.runtimeInspection)
	binaryCheck := inspectDoctorBinaryIntegrity()
	printDoctorLines(binaryCheck.lines)
	printDoctorLines(repair.lateLines)

	saveErr := saveDoctorState(projectRoot, state)
	if saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save session: %v\n", saveErr)
	}

	fmt.Println()
	hookStatus := "intact"
	if fixed {
		hookStatus = "repaired where needed"
	}
	hasTransientRestrictions := state.HasTransientRestrictions()
	if fixed {
		if hasTransientRestrictions || binaryCheck.issue {
			fmt.Println(ac(auditBoldYellow, "sir doctor") + " — recovery complete, but attention needed")
			fmt.Println()
			fmt.Printf("  Hook configuration: %s\n", ac(auditYellow, hookStatus))
			fmt.Println("  Lease integrity:    " + ac(auditGreen, "verified"))
			if binaryCheck.issue {
				fmt.Printf("  Binary integrity:   %s\n", ac(auditBoldRed, binaryCheck.summary))
			}
			if hasTransientRestrictions {
				if state.SecretSession {
					fmt.Println("  Session state:      " + ac(auditYellow, "transient restrictions active (secret session)"))
				} else {
					fmt.Println("  Session state:      " + ac(auditYellow, "transient restrictions active"))
				}
			} else {
				fmt.Println("  Session state:      " + ac(auditGreen, "normal"))
			}
			fmt.Println()
			if binaryCheck.issue {
				fmt.Println(ac(auditDim, "Run 'sir verify' for full hash details, then reinstall sir to refresh ~/.sir/binary-manifest.json."))
			}
			if hasTransientRestrictions {
				fmt.Println(ac(auditDim, "Run 'sir unlock' to clear transient runtime restrictions."))
			}
		} else {
			fmt.Println(ac(auditBoldGreen, "sir doctor") + " — recovery complete")
			fmt.Println()
			fmt.Println(ac(auditDim, "sir is operational. Type 'claude' to resume."))
		}
	} else if hasTransientRestrictions || binaryCheck.issue {
		fmt.Println(ac(auditBoldYellow, "sir doctor") + " — attention needed")
		fmt.Println()
		fmt.Printf("  Hook configuration: %s\n", ac(auditGreen, hookStatus))
		fmt.Println("  Lease integrity:    " + ac(auditGreen, "verified"))
		if binaryCheck.issue {
			fmt.Printf("  Binary integrity:   %s\n", ac(auditBoldRed, binaryCheck.summary))
		}
		if hasTransientRestrictions {
			if state.SecretSession {
				fmt.Println("  Session state:      " + ac(auditYellow, "transient restrictions active (secret session)"))
			} else {
				fmt.Println("  Session state:      " + ac(auditYellow, "transient restrictions active"))
			}
		} else {
			fmt.Println("  Session state:      " + ac(auditGreen, "normal"))
		}
		fmt.Println()
		if binaryCheck.issue {
			fmt.Println(ac(auditDim, "Run 'sir verify' for full hash details, then reinstall sir to refresh ~/.sir/binary-manifest.json."))
		}
		if hasTransientRestrictions {
			fmt.Println(ac(auditDim, "Run 'sir unlock' to clear transient runtime restrictions."))
		}
	} else {
		fmt.Println(ac(auditBoldGreen, "sir doctor") + " — all clear")
		fmt.Println()
		fmt.Printf("  Hook configuration: %s\n", ac(auditGreen, hookStatus))
		fmt.Println("  Lease integrity:    " + ac(auditGreen, "verified"))
		fmt.Println("  Session state:      " + ac(auditGreen, "normal"))
		fmt.Println()
		fmt.Println(ac(auditDim, "Nothing to fix."))
	}

	// v2 provider health — best-effort, human output only, skipped when
	// examples/providers is absent (keeps --json / CI path unaffected).
	printDoctorProviderHealth()

	// v2 Rust kernel check — reports sir-core-eval presence and callability.
	printDoctorRustKernel()
}

// printDoctorProviderHealth appends a v2 provider health section to doctor output.
// It is best-effort: if the provider directory is missing or a probe fails,
// the section is silently skipped so `sir doctor --json` and CI gates are unaffected.
func printDoctorProviderHealth() {
	const dir = "examples/providers"
	manifests, err := findProviderManifests(dir)
	if err != nil || len(manifests) == 0 {
		return
	}
	fmt.Println()
	fmt.Println(ac(auditBold, "v2 provider health"))
	fmt.Println()
	for _, mpath := range manifests {
		m, issues := loadAndValidateManifest(mpath)
		if m == nil || len(issues) > 0 {
			fmt.Printf("  %-26s unhealthy (manifest invalid)\n", filepath.Base(filepath.Dir(mpath)))
			continue
		}
		ep := filepath.Join(filepath.Dir(mpath), m.Entrypoint)
		capsRaw, err := queryProviderCapabilities(ep)
		if err != nil {
			fmt.Printf("  %-26s unavailable (%s)\n", m.Name, err)
			continue
		}
		caps := summarizeCapabilities(capsRaw)
		fmt.Printf("  %-26s healthy    %s\n", m.Name, caps)
	}
}

// buildV2HealthFields probes the v2 Rust kernel and returns structured health fields.
func buildV2HealthFields() *doctorHealthV2 {
	v2 := &doctorHealthV2{}
	engine := os.Getenv("SIR_ENGINE")
	if engine == "" {
		engine = "go"
	}
	v2.ActiveEngine = engine

	home, _ := os.UserHomeDir()
	installDir := os.Getenv("SIR_INSTALL_DIR")
	if installDir == "" {
		installDir = filepath.Join(home, ".local", "bin")
	}
	candidates := []string{
		"target/release/sir-core-eval",
		"target/debug/sir-core-eval",
		filepath.Join(installDir, "sir-core-eval"),
	}
	evalPath := ""
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			evalPath = c
			break
		}
	}
	v2.SirCoreEvalPresent = evalPath != ""
	if evalPath != "" {
		probe := `{"case_id":"doctor-probe","mode":"hook_gate","signals":[],"evasion_flags":{},"prior_taint":[],"provider_capabilities":[]}` + "\n"
		cmd := exec.Command(evalPath) // #nosec G702 -- sir-core-eval path is selected from fixed repo/install candidates and launched without a shell.
		cmd.Stdin = strings.NewReader(probe)
		out, err := cmd.Output()
		v2.SirCoreEvalCallable = err == nil && len(strings.TrimSpace(string(out))) > 0
	}
	if manifests, err := findProviderManifests("examples/providers"); err == nil {
		v2.ProviderCount = len(manifests)
	}
	return v2
}

// printDoctorRustKernel checks that sir-core-eval is present and callable.
// This supports the trust story: the Rust decision kernel should be reachable.
func printDoctorRustKernel() {
	fmt.Println()
	fmt.Println(ac(auditBold, "v2 Rust kernel"))
	fmt.Println()

	// Check both repo-local build output and installed location.
	installDir := os.Getenv("SIR_INSTALL_DIR")
	if installDir == "" {
		home, _ := os.UserHomeDir()
		installDir = filepath.Join(home, ".local", "bin")
	}
	candidates := []string{
		"target/release/sir-core-eval",
		"target/debug/sir-core-eval",
		filepath.Join(installDir, "sir-core-eval"),
	}
	evalPath := ""
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			evalPath = c
			break
		}
	}

	if evalPath == "" {
		fmt.Printf("  sir-core-eval:    %s\n", ac(auditBoldRed, "not found"))
		fmt.Println("  Run: cargo build --release -p sir-core")
		fmt.Println()
		return
	}
	fmt.Printf("  sir-core-eval:    %s (%s)\n", ac(auditGreen, "present"), evalPath)

	// Attempt a capability probe by sending a minimal evaluation.
	probe := `{"case_id":"doctor-probe","mode":"hook_gate","signals":[],"evasion_flags":{},"prior_taint":[],"provider_capabilities":[]}` + "\n"
	cmd := exec.Command(evalPath) // #nosec G702 -- sir-core-eval path is selected from fixed repo/install candidates and launched without a shell.
	cmd.Stdin = strings.NewReader(probe)
	out, err := cmd.Output()
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		fmt.Printf("  Rust kernel:      %s (probe failed: %v)\n", ac(auditBoldRed, "unreachable"), err)
	} else {
		fmt.Printf("  Rust kernel:      %s\n", ac(auditGreen, "callable"))
	}

	engine := os.Getenv("SIR_ENGINE")
	if engine == "" {
		engine = "go (default; set SIR_ENGINE=rust to route runtime decisions to Rust)"
	}
	fmt.Printf("  active engine:    %s\n", engine)
	fmt.Println()
}

type doctorBinaryIntegrityCheck struct {
	issue   bool
	summary string
	lines   []string
}

func inspectDoctorBinaryIntegrity() doctorBinaryIntegrityCheck {
	status, err := inspectBinaryIntegrity()
	if err != nil {
		return doctorBinaryIntegrityCheck{
			issue:   true,
			summary: "manifest error",
			lines: []string{
				fmt.Sprintf("  WARNING: binary integrity manifest could not be loaded: %v", err),
			},
		}
	}
	if status == nil {
		return doctorBinaryIntegrityCheck{}
	}
	if status.allOK() {
		return doctorBinaryIntegrityCheck{}
	}

	lines := []string{"  WARNING: binary integrity check failed:"}
	if status.sirErr != nil {
		lines = append(lines, fmt.Sprintf("    - sir: could not read %s: %v", status.sirPath, status.sirErr))
	} else if status.sirHash != status.manifest.SirSHA256 {
		lines = append(lines, fmt.Sprintf("    - sir: manifest %s, disk %s", shortHash(status.manifest.SirSHA256), shortHash(status.sirHash)))
	}
	if status.misterCoreErr != nil {
		lines = append(lines, fmt.Sprintf("    - mister-core: could not read %s: %v", status.misterCorePath, status.misterCoreErr))
	} else if status.misterCoreHash != status.manifest.MisterCoreSHA256 {
		lines = append(lines, fmt.Sprintf("    - mister-core: manifest %s, disk %s", shortHash(status.manifest.MisterCoreSHA256), shortHash(status.misterCoreHash)))
	}
	return doctorBinaryIntegrityCheck{
		issue:   true,
		summary: "mismatch",
		lines:   lines,
	}
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
}

func loadLeaseForDoctor(projectRoot string) (*lease.Lease, error) {
	if policy, err := loadManagedPolicyForCLI(); err != nil {
		return nil, err
	} else if policy != nil {
		return policy.CloneLease()
	}
	stateDir := session.StateDir(projectRoot)
	leasePath := filepath.Join(stateDir, "lease.json")
	l, err := lease.Load(leasePath)
	if err != nil {
		return lease.DefaultLease(), nil
	}
	return l, nil
}
