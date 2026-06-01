package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/kernel"
	"github.com/somoore/sir/pkg/sdk"
)

// cmdHarness handles: sir harness <subcommand> [args...]
func cmdHarness(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: sir harness run [--engine go|rust|both] [--tier fixture|capture] <fixtures/cases>\n")
		os.Exit(1)
	}
	switch args[0] {
	case "run":
		cmdHarnessRun(args[1:])
	case "capture-generate":
		cmdHarnessCaptureGenerate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown harness subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func cmdHarnessRun(args []string) {
	dir := "harness/fixtures/cases"
	engine := "go"
	tier := "fixture"

	for i, a := range args {
		switch a {
		case "--engine":
			if i+1 < len(args) {
				engine = args[i+1]
			}
		case "--tier":
			if i+1 < len(args) {
				tier = args[i+1]
			}
		default:
			if !strings.HasPrefix(a, "--") {
				dir = a
			}
		}
	}

	if tier != "fixture" && tier != "capture" {
		fmt.Fprintf(os.Stderr, "error: --tier must be fixture or capture\n")
		os.Exit(1)
	}
	if tier == "capture" {
		runCaptureTier(dir)
		return
	}

	if engine != "go" && engine != "rust" && engine != "both" {
		fmt.Fprintf(os.Stderr, "error: --engine must be go, rust, or both\n")
		os.Exit(1)
	}

	cases, err := loadCases(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading cases: %v\n", err)
		os.Exit(1)
	}
	if len(cases) == 0 {
		fmt.Fprintf(os.Stderr, "no cases found in %s\n", dir)
		os.Exit(1)
	}

	if checkConformance(cases) {
		fmt.Fprintln(os.Stderr, "harness: conformance check failed — fix the fixtures above")
		os.Exit(1)
	}

	if engine == "both" {
		runParityCheck(cases, dir)
		return
	}

	fmt.Printf("engine: %s\n\n", engine)
	fmt.Printf("%-34s %-14s %-10s %s\n", "case_id", "mode", "score", "reason")
	fmt.Println(strings.Repeat("-", 110))

	summaryByMode := map[string]*modeSummary{}
	var rows []harnessRow

	for _, c := range cases {
		var sc, reason string
		if engine == "rust" {
			out, rerr := evalWithRust(c)
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "rust eval error for %s: %v\n", c.CaseID, rerr)
				os.Exit(1)
			}
			sc = out.Enforceability
			reason = fmt.Sprintf("verdict=%s decision_class=%s", out.Verdict, out.DecisionClass)
		} else {
			sc, reason = scoreCase(c)
		}

		r := harnessRow{CaseID: c.CaseID, Mode: c.Mode, Score: sc, Reason: reason}
		rows = append(rows, r)
		fmt.Printf("%-34s %-14s %-10s %s\n", r.CaseID, r.Mode, r.Score, r.Reason)

		if summaryByMode[c.Mode] == nil {
			summaryByMode[c.Mode] = &modeSummary{Mode: c.Mode}
		}
		switch sc {
		case "enforces":
			summaryByMode[c.Mode].Enforces++
		case "detects":
			summaryByMode[c.Mode].Detects++
		case "blind":
			summaryByMode[c.Mode].Blind++
		}
	}

	printModeBoundarySummary(summaryByMode)

	var summaries []modeSummary
	for _, s := range summaryByMode {
		summaries = append(summaries, *s)
	}

	report := map[string]any{"results": rows, "mode_summary": summaries, "engine": engine}
	out := filepath.Join(filepath.Dir(dir), "report.json")
	b, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(out, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write report: %v\n", err)
	} else {
		fmt.Printf("\nWrote %s\n", out)
	}
}

// rustEvalInput is the wire format for sir-core-eval.
type rustEvalInput struct {
	CaseID                  string                 `json:"case_id"`
	Mode                    string                 `json:"mode"`
	Signals                 []sdk.Signal           `json:"signals"`
	EvasionFlags            rustEvasionFlags       `json:"evasion_flags"`
	PriorTaint              []string               `json:"prior_taint"`
	ProviderCapabilities    []string               `json:"provider_capabilities"`
	ResolvedActorKind       string                 `json:"resolved_actor_kind,omitempty"`
	PolicyVerdicts          []kernel.PolicyVerdict `json:"policy_verdicts,omitempty"`
	ProviderEnforcement     string                 `json:"provider_enforcement,omitempty"`
	ProviderEnforcedActions []string               `json:"provider_enforced_actions,omitempty"`
}

type rustEvasionFlags struct {
	SpanStripped          bool `json:"span_stripped"`
	SpanForged            bool `json:"span_forged"`
	DetachedChild         bool `json:"detached_child"`
	HookMissing           bool `json:"hook_missing"`
	RequiredEffectUnavail bool `json:"required_effect_unavailable"`
	FailClosed            bool `json:"fail_closed"`
}

// rustEvalOutput holds the parity fields from sir-core-eval.
type rustEvalOutput struct {
	Verdict        string                 `json:"verdict"`
	DecisionClass  string                 `json:"decision_class"`
	Enforceability string                 `json:"enforceability"`
	Attribution    string                 `json:"attribution"`
	SpoofingRisk   string                 `json:"spoofing_risk"`
	PolicyRules    []string               `json:"policy_rules"`
	Effects        []kernel.PlannedEffect `json:"effects"`
	ActionType     string                 `json:"action_type"`
	Sensitivity    string                 `json:"sensitivity"`
	NewTaint       []string               `json:"new_taint"`
}

// findRustEval locates the sir-core-eval binary using the same lookup order
// as sir doctor, so `sir harness --engine rust` works after `make install`.
func findRustEval() (string, error) {
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
	// Also check PATH.
	if p, err := exec.LookPath("sir-core-eval"); err == nil {
		candidates = append(candidates, p)
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("sir-core-eval not found (checked target/, %s, PATH); run: cargo build -p sir-core", installDir)
}

// evalWithRust sends a harness case to sir-core-eval and returns the output.
func evalWithRust(c harnessCase) (*rustEvalOutput, error) {
	bin, err := findRustEval()
	if err != nil {
		return nil, err
	}

	inp := rustEvalInput{
		CaseID:  c.CaseID,
		Mode:    c.Mode,
		Signals: c.Signals,
		EvasionFlags: rustEvasionFlags{
			SpanStripped:          c.SpanStripped,
			SpanForged:            c.SpanForged,
			DetachedChild:         c.DetachedChild,
			HookMissing:           c.HookMissing,
			RequiredEffectUnavail: c.RequiredEffectUnavail,
			FailClosed:            c.FailClosed,
		},
		PriorTaint:              c.PriorTaint,
		ProviderCapabilities:    c.ProviderCapabilities,
		ResolvedActorKind:       c.ResolvedActorKind,
		PolicyVerdicts:          c.PolicyVerdicts,
		ProviderEnforcement:     c.ProviderEnforcement,
		ProviderEnforcedActions: c.ProviderEnforcedActions,
	}

	inBytes, err := json.Marshal(inp)
	if err != nil {
		return nil, err
	}

	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader(string(inBytes) + "\n")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sir-core-eval: %w", err)
	}

	var result rustEvalOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &result); err != nil {
		return nil, fmt.Errorf("parse rust output: %w", err)
	}
	return &result, nil
}

// parityMismatch describes a field-level divergence between Go and Rust.
type parityMismatch struct {
	CaseID string
	Field  string
	Go     string
	Rust   string
}

// runParityCheck runs both engines and compares the six deterministic fields.
func runParityCheck(cases []harnessCase, dir string) {
	if checkConformance(cases) {
		fmt.Fprintln(os.Stderr, "harness: conformance check failed — fix the fixtures above")
		os.Exit(1)
	}
	fmt.Println("engine: both (parity check)")
	fmt.Println()
	fmt.Printf("%-34s %-10s %-10s %-14s %s\n", "case_id", "go_enf", "rust_enf", "verdict", "status")
	fmt.Println(strings.Repeat("-", 100))

	var mismatches []parityMismatch
	passed := 0

	sort.Slice(cases, func(i, j int) bool { return cases[i].CaseID < cases[j].CaseID })

	for _, c := range cases {
		// Go evaluation
		goEnf, _ := scoreCase(c)
		goOut := kernel.Evaluate(kernel.EvaluationInput{
			CaseID:  c.CaseID,
			Mode:    c.Mode,
			Signals: c.Signals,
			Evasion: kernel.EvasionFlags{
				SpanStripped:          c.SpanStripped,
				SpanForged:            c.SpanForged,
				DetachedChild:         c.DetachedChild,
				HookMissing:           c.HookMissing,
				RequiredEffectUnavail: c.RequiredEffectUnavail,
				FailClosed:            c.FailClosed,
			},
			PriorTaint:              c.PriorTaint,
			ProviderCapabilities:    c.ProviderCapabilities,
			ResolvedActorKind:       c.ResolvedActorKind,
			PolicyVerdicts:          c.PolicyVerdicts,
			ProviderEnforcement:     c.ProviderEnforcement,
			ProviderEnforcedActions: c.ProviderEnforcedActions,
		})

		// Rust evaluation
		rustOut, err := evalWithRust(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rust eval error for %s: %v\n", c.CaseID, err)
			os.Exit(1)
		}

		// Compare the six parity fields (NOT decision_id or timestamp).
		status := "OK"
		var caseMismatches []parityMismatch

		checkField := func(field, goVal, rustVal string) {
			if goVal != rustVal {
				caseMismatches = append(caseMismatches, parityMismatch{c.CaseID, field, goVal, rustVal})
			}
		}

		checkField("verdict", goOut.Verdict, rustOut.Verdict)
		checkField("decision_class", goOut.DecisionClass, rustOut.DecisionClass)
		checkField("enforceability", goOut.Enforceability, rustOut.Enforceability)
		checkField("attribution", goOut.Attribution, rustOut.Attribution)
		checkField("spoofing_risk", goOut.SpoofingRisk, rustOut.SpoofingRisk)
		checkField("policy_rules", strings.Join(goOut.PolicyRules, ","), strings.Join(rustOut.PolicyRules, ","))
		// Effects are security-critical: block/contain/required/fail_closed must match.
		checkField("effects", normalizeEffects(goOut.Effects), normalizeEffects(rustOut.Effects))
		// new_taint drives cross-action decisions in later turns — must agree.
		goTaint := sortedJoin(goOut.NewTaint)
		rustTaint := sortedJoin(rustOut.NewTaint)
		checkField("new_taint", goTaint, rustTaint)

		// Verify against expected snapshot: prevents both engines agreeing on wrong answer.
		if c.Expected != nil {
			exp := c.Expected
			checkExpected := func(field, got, want string) {
				if want == "" {
					return
				}
				if got != want {
					caseMismatches = append(caseMismatches, parityMismatch{c.CaseID, "expected." + field, got, want})
				}
			}
			// Check Go against expected.
			checkExpected("verdict(go)", goOut.Verdict, exp.Verdict)
			checkExpected("enforceability(go)", goOut.Enforceability, exp.Enforceability)
			checkExpected("decision_class(go)", goOut.DecisionClass, exp.DecisionClass)
			// Two-stage scoring: attribution and spoofing_risk checked separately
			// from verdict so mis-attribution can't hide behind a correct-looking verdict.
			checkExpected("attribution(go)", goOut.Attribution, exp.Attribution)
			checkExpected("spoofing_risk(go)", goOut.SpoofingRisk, exp.SpoofingRisk)
			// Policy rules: pointer nil = skip; non-nil (even empty) = assert.
			if exp.PolicyRules != nil {
				checkExpected("policy_rules(go)", strings.Join(goOut.PolicyRules, ","), strings.Join(*exp.PolicyRules, ","))
			}
			if exp.Effects != nil {
				checkExpected("effects(go)", normalizeEffects(goOut.Effects), normalizeEffects(*exp.Effects))
			}
			// Check Rust against expected.
			checkExpected("verdict(rust)", rustOut.Verdict, exp.Verdict)
			checkExpected("enforceability(rust)", rustOut.Enforceability, exp.Enforceability)
			checkExpected("decision_class(rust)", rustOut.DecisionClass, exp.DecisionClass)
			checkExpected("attribution(rust)", rustOut.Attribution, exp.Attribution)
			checkExpected("spoofing_risk(rust)", rustOut.SpoofingRisk, exp.SpoofingRisk)
			if exp.PolicyRules != nil {
				checkExpected("policy_rules(rust)", strings.Join(rustOut.PolicyRules, ","), strings.Join(*exp.PolicyRules, ","))
			}
			if exp.Effects != nil {
				checkExpected("effects(rust)", normalizeEffects(rustOut.Effects), normalizeEffects(*exp.Effects))
			}
		}

		if len(caseMismatches) > 0 {
			status = "MISMATCH"
			mismatches = append(mismatches, caseMismatches...)
		} else {
			passed++
		}

		fmt.Printf("%-34s %-10s %-10s %-14s %s\n",
			c.CaseID, goEnf, rustOut.Enforceability, goOut.Verdict, status)
	}

	fmt.Println()
	fmt.Printf("Parity: %d/%d cases match\n", passed, len(cases))

	if len(mismatches) > 0 {
		fmt.Println()
		fmt.Println("MISMATCHES:")
		for _, m := range mismatches {
			fmt.Printf("  [%s] %s: go=%q rust=%q\n", m.CaseID, m.Field, m.Go, m.Rust)
		}
		os.Exit(1)
	}
	fmt.Println("All cases match. Rust parity confirmed.")
}

// modeHonesty is the canonical enforcement guarantee map from pkg/kernel.
var modeHonesty = kernel.ModeEnforcementGuarantee

func printModeBoundarySummary(byMode map[string]*modeSummary) {
	fmt.Println()
	fmt.Println("Mode boundary summary (bare-laptop honesty):")
	fmt.Println(strings.Repeat("-", 100))
	fmt.Printf("%-14s %9s %9s %9s  %s\n", "mode", "enforces", "detects", "blind", "guarantee")
	fmt.Println(strings.Repeat("-", 100))

	order := []string{"observe", "advise", "hook_gate", "os_observed", "mediated", "contained", "managed"}
	for _, mode := range order {
		s := byMode[mode]
		if s == nil {
			continue
		}
		guarantee := modeHonesty[mode]
		if guarantee == "" {
			guarantee = "unknown"
		}
		fmt.Printf("%-14s %9d %9d %9d  %s\n", mode, s.Enforces, s.Detects, s.Blind, guarantee)
	}
	fmt.Println()
	fmt.Println("Legend:")
	fmt.Println("  enforces -- SIR can prevent the action in this mode")
	fmt.Println("  detects  -- SIR can observe and record, but cannot prevent")
	fmt.Println("  blind    -- SIR has no signal; cannot act or record")
	fmt.Println()
	fmt.Println("Bare-laptop note: hook_gate is the highest mode available without a sandbox or OS enforcement")
	fmt.Println("provider. span-strip, span-forge, detached-child, and hook-missing cases reveal its limits.")
}

// harnessExpected holds optional expected output for snapshot/regression testing.
// When present, harness verifies both engines agree AND match the expected values.
// This prevents Go and Rust from agreeing on the wrong answer.
//
// For PolicyRules and Effects, presence of the field (even as an empty slice)
// means "assert this value" (Option C). When the JSON field is absent, the
// pointer is nil and no assertion is made. When the JSON field is present but
// empty ("policy_rules": []), assertion checks that the result is empty.
//
// For two-stage scoring (sprint item 4): Attribution and SpoofingRisk let fixtures
// assert attribution correctness separately from policy verdict correctness.
// A mis-attribution hidden behind a correct-looking verdict will now break a
// fixture, not silently pass. Both fields are optional — absent means skip check.
type harnessExpected struct {
	Verdict        string                  `json:"verdict,omitempty"`
	DecisionClass  string                  `json:"decision_class,omitempty"`
	Enforceability string                  `json:"enforceability,omitempty"`
	Attribution    string                  `json:"attribution,omitempty"`
	SpoofingRisk   string                  `json:"spoofing_risk,omitempty"`
	PolicyRules    *[]string               `json:"policy_rules"` // nil=skip check; []string{}=assert empty
	Effects        *[]kernel.PlannedEffect `json:"effects"`      // nil=skip check; []PlannedEffect{}=assert empty
}

type harnessRow struct {
	CaseID string `json:"case_id"`
	Mode   string `json:"mode"`
	Score  string `json:"score"`
	Reason string `json:"reason"`
}

type modeSummary struct {
	Mode     string `json:"mode"`
	Enforces int    `json:"enforces"`
	Detects  int    `json:"detects"`
	Blind    int    `json:"blind"`
}

// harnessCase mirrors case.json. Signals uses sdk.Signal. PriorTaint enables
// cross-action taint testing.
type harnessCase struct {
	CaseID                string   `json:"case_id"`
	Title                 string   `json:"title"`
	Mode                  string   `json:"mode"`
	SensitiveSource       bool     `json:"sensitive_source"`
	IrreversibleSink      bool     `json:"irreversible_sink"`
	RequiredEffectUnavail bool     `json:"required_effect_unavailable"`
	FailClosed            bool     `json:"fail_closed"`
	SpanStripped          bool     `json:"span_stripped"`
	SpanForged            bool     `json:"span_forged"`
	DetachedChild         bool     `json:"detached_child"`
	HookMissing           bool     `json:"hook_missing"`
	SharedShell           bool     `json:"shared_shell"`
	PriorTaint            []string `json:"prior_taint"`           // for cross-action taint tests
	ProviderCapabilities  []string `json:"provider_capabilities"` // effects available: "block", "contain"
	// ProviderEnforcement is "real" when the effect provider demonstrably enforces,
	// "simulated"/"" when it only declares the capability. Gates whether a declared
	// block/contain yields enforces — fixtures use it to prove the soundness fix.
	ProviderEnforcement string `json:"provider_enforcement,omitempty"`
	// ProviderEnforcedActions optionally scopes the provider's real enforcement
	// to a subset of action types (item 8: action-scoped capability). Empty =
	// enforces every action (backward-compatible default). Fixtures use it to
	// prove an uncovered action degrades enforces→detects.
	ProviderEnforcedActions []string `json:"provider_enforced_actions,omitempty"`
	// ResolvedActorKind is set when the orchestrator has fused a shell/unknown
	// signal with agent-session evidence and resolved the actor to ai_coding_agent.
	// Fixtures use this field to prove the resolution-triggers-rule invariant.
	ResolvedActorKind string `json:"resolved_actor_kind,omitempty"`
	// PolicyVerdicts lets a fixture inject advisory policy-provider verdicts (e.g.
	// an OPA deny) so the harness exercises policy composition through both kernels.
	PolicyVerdicts []kernel.PolicyVerdict `json:"policy_verdicts,omitempty"`
	Expected       *harnessExpected       `json:"expected,omitempty"` // optional expected output for snapshot testing
	Signals        []sdk.Signal           `json:"signals"`
}

func loadCases(dir string) ([]harnessCase, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var cases []harnessCase
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name(), "case.json")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var c harnessCase
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("case %s: %w", e.Name(), err)
		}
		cases = append(cases, c)
	}
	return cases, nil
}

// modeActiveProviders defines which signal providers are realistic for each mode.
// A fixture carrying a signal from a provider not in its mode's active set is
// a conformance violation: it pre-solves correlation the kernel cannot establish.
// hook_gate mode: only hook/shell/mcp pre-exec providers; no OS sensor.
// os_observed mode: only OS sensors; no pre-exec hooks.
// mediated mode: mediated runner + OS sensors (both layers).
// contained/managed/observe/advise: any provider.
var modeActiveProviders = map[string]map[string]bool{
	"hook_gate": {
		"claude_hook":          true,
		"claude_code_hook":     true,
		"sir-claude-code-hook": true,
		"shell_wrapper":        true,
		"sir-shell-wrapper":    true,
		"sir_shell_wrapper":    true,
		"sir-mcp-proxy":        true,
		"mcp_proxy":            true,
	},
	"os_observed": {
		"os_file_sensor":    true,
		"os_network_sensor": true,
		"os_process_sensor": true,
		"os_sensor":         true,
		"network_sensor":    true,
	},
	"mediated": {
		"sir_shell_wrapper": true,
		"sir-shell-wrapper": true,
		"sir_mediated":      true,
		"mediated_runner":   true,
		"os_file_sensor":    true,
		"os_network_sensor": true,
		"os_process_sensor": true,
		"os_sensor":         true,
		"network_sensor":    true,
	},
	// contained, managed, observe, advise: not restricted — any provider valid.
}

// conformanceIssues returns provider names in the case's signals that are not
// active for the case's mode. Returns empty slice when the case is conformant.
// Empty provider name or modes without a restricted set are always conformant.
func conformanceIssues(c harnessCase) []string {
	active, restricted := modeActiveProviders[c.Mode]
	if !restricted {
		return nil
	}
	var violations []string
	seen := map[string]bool{}
	for _, s := range c.Signals {
		p := s.Source.Provider
		if p == "" {
			continue
		}
		if !active[p] && !seen[p] {
			violations = append(violations, p)
			seen[p] = true
		}
	}
	return violations
}

// checkConformance reports cases carrying signals from providers that are not
// active in the case's mode (a fixture pre-solving correlation the kernel could
// not establish in that mode). It returns true when any case is non-conformant.
//
// A non-conformant fixture is a hard failure, not a warning: as the case count
// grows, a correlation-pre-solving fixture must not be able to merge under an
// ignored warning. Callers exit non-zero so CI (`make kernel-parity`/`make
// check`) blocks it. A genuine OS-sensor-only scenario belongs in `os_observed`
// (or `mediated`) mode, not `hook_gate`.
func checkConformance(cases []harnessCase) bool {
	failed := false
	for _, c := range cases {
		issues := conformanceIssues(c)
		if len(issues) == 0 {
			continue
		}
		if !failed {
			fmt.Fprintln(os.Stderr, "CONFORMANCE FAILURES (signals from providers not active in case mode):")
			failed = true
		}
		fmt.Fprintf(os.Stderr, "  [%s] mode=%s: impossible provider(s): %s\n",
			c.CaseID, c.Mode, strings.Join(issues, ", "))
	}
	if failed {
		fmt.Fprintln(os.Stderr, "  These fixtures pre-solve correlation the kernel cannot establish in this mode.")
		fmt.Fprintln(os.Stderr, "  Move the case to a mode whose deployed sensors can realistically emit these signals")
		fmt.Fprintln(os.Stderr, "  (e.g. os_observed for OS-sensor signals), or remove the impossible signal.")
		fmt.Fprintln(os.Stderr, "")
	}
	return failed
}

// scoreCase is a thin wrapper over kernel.AnalyzeEnforceability.
func scoreCase(c harnessCase) (score, reason string) {
	result := kernel.AnalyzeEnforceability(kernel.EnforceabilityInput{
		Mode:                 c.Mode,
		Signals:              c.Signals,
		ProviderCapabilities: c.ProviderCapabilities,
		ProviderEnforcement:  c.ProviderEnforcement,
		EnforcedActions:      c.ProviderEnforcedActions,
		EvasionFlags: kernel.EvasionFlags{
			SpanStripped:          c.SpanStripped,
			SpanForged:            c.SpanForged,
			DetachedChild:         c.DetachedChild,
			HookMissing:           c.HookMissing,
			RequiredEffectUnavail: c.RequiredEffectUnavail,
			FailClosed:            c.FailClosed,
		},
	})
	return result.Class, result.Reason
}

// sortedJoin sorts a string slice and joins with commas for deterministic comparison.
func sortedJoin(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	cp := make([]string, len(ss))
	copy(cp, ss)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// normalizeEffects converts effects to a stable sorted string for comparison.
// Format: "block:required:fail_closed,record:required:best_effort"
func normalizeEffects(effects []kernel.PlannedEffect) string {
	if len(effects) == 0 {
		return ""
	}
	parts := make([]string, len(effects))
	for i, e := range effects {
		req := "best_effort"
		if e.Required {
			req = "required"
		}
		fc := "best_effort"
		if e.FailClosed {
			fc = "fail_closed"
		}
		parts[i] = fmt.Sprintf("%s:%s:%s", e.Type, req, fc)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func hasSignal(c harnessCase, reliability, timing string) bool {
	for _, s := range c.Signals {
		if reliability != "" && s.Source.Reliability != reliability {
			continue
		}
		if timing != "" && s.Source.Timing != timing {
			continue
		}
		return true
	}
	return false
}

var _ = sdk.Signal{}
var _ = filepath.Join

// scoreRank maps enforceability class to a numeric rank (higher = stronger).
func scoreRank(class string) int {
	switch class {
	case "enforces":
		return 3
	case "detects":
		return 2
	case "blind":
		return 1
	}
	return 0
}

// captureCaseResult holds the comparison result for one case in the capture tier.
type captureCaseResult struct {
	CaseID        string `json:"case_id"`
	FixtureScore  string `json:"fixture_score"`
	CaptureScore  string `json:"capture_score"`
	Status        string `json:"status"` // "ok", "regression", "optimism"
	CaptureReason string `json:"capture_reason"`
}

// runCaptureTier scores each case with a capture.json alongside its fixture
// case.json. CI fails (exit 1) if any case's capture score is worse than its
// fixture score — an honesty regression test.
//
// "optimism" cases (capture > fixture) are logged but do not fail CI. They
// document where the adapter thinks it enforces but the fixture knows better
// (e.g. span-forge: adapter cannot detect a forged span, scores optimistically).
func runCaptureTier(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", dir, err)
		os.Exit(1)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	fmt.Println("tier: capture")
	fmt.Println()
	fmt.Printf("%-34s %-10s %-10s %-12s %s\n", "case_id", "fixture", "capture", "status", "capture_reason")
	fmt.Println(strings.Repeat("-", 120))

	var results []captureCaseResult
	regressions := 0

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		casePath := filepath.Join(dir, e.Name(), "case.json")
		capturePath := filepath.Join(dir, e.Name(), "capture.json")

		caseData, err := os.ReadFile(casePath)
		if err != nil {
			continue
		}
		var c harnessCase
		if err := json.Unmarshal(caseData, &c); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", casePath, err)
			continue
		}
		fixtureScore, _ := scoreCase(c)

		if _, err := os.Stat(capturePath); err != nil {
			fmt.Printf("%-34s %-10s %-10s %-12s %s\n", c.CaseID, fixtureScore, "-", "no_capture", "capture.json absent — skipped")
			continue
		}

		captureData, err := os.ReadFile(capturePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read capture %s: %v\n", capturePath, err)
			continue
		}
		var cc harnessCase
		if err := json.Unmarshal(captureData, &cc); err != nil {
			fmt.Fprintf(os.Stderr, "parse capture %s: %v\n", capturePath, err)
			continue
		}
		captureScore, captureReason := scoreCase(cc)

		status := "ok"
		if scoreRank(captureScore) < scoreRank(fixtureScore) {
			status = "REGRESSION"
			regressions++
		} else if scoreRank(captureScore) > scoreRank(fixtureScore) {
			status = "optimism"
		}

		results = append(results, captureCaseResult{
			CaseID:        c.CaseID,
			FixtureScore:  fixtureScore,
			CaptureScore:  captureScore,
			Status:        status,
			CaptureReason: captureReason,
		})
		fmt.Printf("%-34s %-10s %-10s %-12s %s\n", c.CaseID, fixtureScore, captureScore, status, captureReason)
	}

	fmt.Println()
	fmt.Printf("Capture tier: %d cases with capture results, %d regressions\n", len(results), regressions)
	fmt.Println()
	fmt.Println("Legend:")
	fmt.Println("  ok         — capture confirms fixture claim")
	fmt.Println("  optimism   — capture scores higher than fixture (adapter lacks adversarial knowledge)")
	fmt.Println("  REGRESSION — capture scores lower than fixture (fixture claim was too optimistic)")
	fmt.Println()
	fmt.Println("Note: 'optimism' cases are expected honesty gaps (e.g. span-forge: adapter cannot")
	fmt.Println("detect forged spans, so it scores 'enforces' while fixture (knowing the forge) scores 'detects').")
	fmt.Println("These are documented limits, not bugs. REGRESSION cases fail CI.")

	captureReport := map[string]any{
		"tier":        "capture",
		"results":     results,
		"regressions": regressions,
	}
	reportPath := filepath.Join(filepath.Dir(dir), "capture-report.json")
	b, _ := json.MarshalIndent(captureReport, "", "  ")
	if err := os.WriteFile(reportPath, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write capture report: %v\n", err)
	} else {
		fmt.Printf("\nWrote %s\n", reportPath)
	}

	if regressions > 0 {
		fmt.Println()
		fmt.Fprintf(os.Stderr, "FAIL: %d capture regression(s) — fixture claimed more than adapter delivers.\n", regressions)
		os.Exit(1)
	}
}
