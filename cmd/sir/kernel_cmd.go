package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/kernel"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/provider"
	"github.com/somoore/sir/pkg/sdk"
)

// cmdKernel handles: sir kernel <subcommand> [args...]
//
// Deviation from PLAN wording: the PLAN names sir replay, sir why, sir status.
// These names collide with existing v1 commands on this branch. They are
// namespaced under sir kernel <sub> to remain additive. They can be promoted
// to top-level commands when v1 is retired.
func cmdKernel(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: sir kernel <replay|why|status> [args...]\n")
		os.Exit(1)
	}
	switch args[0] {
	case "replay":
		cmdKernelReplay(args[1:])
	case "why":
		cmdKernelWhy(args[1:])
	case "status":
		cmdKernelStatus(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown kernel subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

type kernelReplayOptions struct {
	dir                 string
	mode                string
	engine              string
	useProviders        bool
	providersDir        string
	includeUnregistered bool
}

func parseKernelReplayOptions(args []string) kernelReplayOptions {
	opts := kernelReplayOptions{
		dir:          "harness/fixtures/cases",
		mode:         kernel.ModeHookGate,
		engine:       os.Getenv("SIR_ENGINE"),
		providersDir: "examples/providers",
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--mode":
			if i+1 < len(args) {
				opts.mode = args[i+1]
				i++
			}
		case "--engine":
			if i+1 < len(args) {
				opts.engine = args[i+1]
				i++
			}
		case "--use-providers":
			opts.useProviders = true
		case "--providers-dir":
			if i+1 < len(args) {
				opts.providersDir = args[i+1]
				i++
			}
		case "--include-unregistered":
			opts.includeUnregistered = true
		default:
			switch {
			case strings.HasPrefix(a, "--mode="):
				opts.mode = strings.TrimPrefix(a, "--mode=")
			case strings.HasPrefix(a, "--engine="):
				opts.engine = strings.TrimPrefix(a, "--engine=")
			case strings.HasPrefix(a, "--providers-dir="):
				opts.providersDir = strings.TrimPrefix(a, "--providers-dir=")
			case !strings.HasPrefix(a, "--"):
				opts.dir = a
			}
		}
	}
	return opts
}

// cmdKernelReplay processes harness cases through the v2 kernel and writes evidence.
func cmdKernelReplay(args []string) {
	opts := parseKernelReplayOptions(args)

	// Derive provider_capabilities from real provider health queries.
	var liveProviderCaps []string
	if opts.useProviders {
		liveProviderCaps = collectProviderCapabilities(opts.providersDir, opts.includeUnregistered)
		source := "active registry"
		if opts.includeUnregistered {
			source += " + " + opts.providersDir
		}
		fmt.Printf("Provider capabilities (from %s): %v\n\n", source, liveProviderCaps)
	}
	// engine=both routes to harness for parity testing (no ledger writes).
	if opts.engine == "both" {
		cmdHarnessRun(append([]string{"--engine", "both"}, opts.dir))
		return
	}

	cases, err := loadCases(opts.dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading cases: %v\n", err)
		os.Exit(1)
	}
	if len(cases) == 0 {
		fmt.Fprintf(os.Stderr, "no cases found in %s\n", opts.dir)
		os.Exit(1)
	}

	ledger, err := kernel.OpenLedger(kernel.DefaultLedgerPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening ledger: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%-34s %-8s %-14s %-14s %s\n", "case_id", "verdict", "enforceability", "attribution", "policy rules")
	fmt.Println(strings.Repeat("-", 110))

	sort.Slice(cases, func(i, j int) bool { return cases[i].CaseID < cases[j].CaseID })

	for _, c := range cases {
		caseMode := c.Mode
		if caseMode == "" {
			caseMode = opts.mode
		}

		// Use live provider capabilities if --use-providers was set;
		// otherwise fall back to fixture-declared provider_capabilities.
		providerCaps := c.ProviderCapabilities
		if opts.useProviders && len(liveProviderCaps) > 0 {
			providerCaps = liveProviderCaps
		}

		// Under --use-providers, invoke the active policy providers for LIVE
		// verdicts so replay exercises real policy composition (OPA/Cedar/policy-
		// pack) rather than fixture-baked policy_verdicts. Fail-open: an empty or
		// failed live provider result leaves PolicyVerdicts empty and records
		// provider evidence; native policy is used.
		policyVerdicts := c.PolicyVerdicts
		var providerFailures []kernel.ProviderEvidence
		if opts.useProviders {
			live, failures := collectLivePolicyVerdicts(opts.providersDir, opts.includeUnregistered, c, caseMode)
			providerFailures = failures
			policyVerdicts = live
		}

		in := kernel.EvaluationInput{
			CaseID:                  c.CaseID,
			Mode:                    caseMode,
			Signals:                 c.Signals,
			PriorTaint:              c.PriorTaint,
			ProviderCapabilities:    providerCaps,
			ResolvedActorKind:       c.ResolvedActorKind,
			PolicyVerdicts:          policyVerdicts,
			ProviderEnforcement:     c.ProviderEnforcement,
			ProviderEnforcedActions: c.ProviderEnforcedActions,
			Evasion: kernel.EvasionFlags{
				SpanStripped:          c.SpanStripped,
				SpanForged:            c.SpanForged,
				DetachedChild:         c.DetachedChild,
				HookMissing:           c.HookMissing,
				RequiredEffectUnavail: c.RequiredEffectUnavail,
				FailClosed:            c.FailClosed,
			},
		}

		var evalOut kernel.EvaluationOutput
		baseVerdict := ""
		if opts.engine == "rust" {
			// Rust replay: call sir-core-eval and write ledger entries.
			// Apply --mode override and live provider capabilities if active.
			rc := c
			rc.Mode = caseMode
			rc.ProviderCapabilities = providerCaps
			rc.PolicyVerdicts = policyVerdicts
			rc.ProviderEnforcement = in.ProviderEnforcement
			rc.ProviderEnforcedActions = in.ProviderEnforcedActions
			rout, err := evalWithRust(rc)
			if err != nil {
				fmt.Fprintf(os.Stderr, "rust eval error for %s: %v\n", c.CaseID, err)
				os.Exit(1)
			}
			evalOut = kernel.EvaluationOutput{
				Verdict:        rout.Verdict,
				DecisionClass:  rout.DecisionClass,
				Enforceability: rout.Enforceability,
				Attribution:    rout.Attribution,
				PolicyRules:    rout.PolicyRules,
				Effects:        rout.Effects,
				ActionType:     rout.ActionType,
				Sensitivity:    rout.Sensitivity,
				NewTaint:       rout.NewTaint,
			}
			if len(policyVerdicts) > 0 {
				rcBase := rc
				rcBase.PolicyVerdicts = nil
				baseOut, err := evalWithRust(rcBase)
				if err != nil {
					fmt.Fprintf(os.Stderr, "rust base eval error for %s: %v\n", c.CaseID, err)
					os.Exit(1)
				}
				baseVerdict = baseOut.Verdict
			}
		} else {
			// Go replay: use the Go reference kernel.
			evalOut = kernel.Evaluate(in)
			if len(policyVerdicts) > 0 {
				baseIn := in
				baseIn.PolicyVerdicts = nil
				baseVerdict = kernel.Evaluate(baseIn).Verdict
			}
		}

		// Build a Decision for ledger. Go stamps id+time (pure/stateful split).
		decision := kernel.Decision{
			DecisionID:     fmt.Sprintf("dec-%s", c.CaseID[:min8(len(c.CaseID))]),
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Mode:           caseMode,
			Verdict:        evalOut.Verdict,
			DecisionClass:  evalOut.DecisionClass,
			PolicyRules:    kernel.NativePolicyRules(evalOut.PolicyRules),
			Effects:        evalOut.Effects,
			Enforceability: evalOut.Enforceability,
			Attribution:    evalOut.Attribution,
			ActionType:     evalOut.ActionType,
			Sensitivity:    evalOut.Sensitivity,
			BaseVerdict:    baseVerdict,
			DeveloperWorkflowFloor: kernel.DeveloperWorkflowFloorEvidence(
				in.PriorTaint, evalOut.ActionType, policyVerdicts, baseVerdict, evalOut.Verdict,
			),
			ProviderPolicyEvidence: kernel.BuildProviderPolicyEvidence(policyVerdicts, evalOut.Verdict, baseVerdict),
			ProviderEvidence:       providerFailures,
		}

		rules := strings.Join(kernel.NativePolicyRules(decision.PolicyRules), ", ")
		if rules == "" {
			rules = "(default allow)"
		}
		if len(decision.ProviderPolicyEvidence) > 0 {
			rules += " | providers: " + summarizeProviderPolicyEvidence(decision.ProviderPolicyEvidence)
		}
		if len(decision.ProviderEvidence) > 0 {
			rules += " | provider failures: " + summarizeProviderFailures(decision.ProviderEvidence)
		}
		fmt.Printf("%-34s %-8s %-14s %-14s %s\n",
			c.CaseID, decision.Verdict, decision.Enforceability, decision.Attribution, rules)

		if err := ledger.Append(c.CaseID, decision); err != nil {
			fmt.Fprintf(os.Stderr, "warning: ledger write failed: %v\n", err)
		}
	}

	fmt.Printf("\nLedger: %s\n", kernel.DefaultLedgerPath())
}

// cmdKernelWhy explains the last decision from the kernel ledger.
func cmdKernelWhy(args []string) {
	id := ""
	for i, a := range args {
		switch a {
		case "--id":
			if i+1 < len(args) {
				id = args[i+1]
			}
		case "--last":
			id = "" // explicit --last: show last entry (already default)
		}
	}

	ledger, err := kernel.OpenLedger(kernel.DefaultLedgerPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening ledger: %v\n", err)
		os.Exit(1)
	}

	if id != "" {
		entries, err := ledger.ReadAll()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading ledger: %v\n", err)
			os.Exit(1)
		}
		for _, e := range entries {
			if e.EntryID == id || e.Decision.DecisionID == id || e.CaseID == id {
				fmt.Print(kernel.Explain(e))
				return
			}
		}
		fmt.Fprintf(os.Stderr, "no entry found for id: %s\n", id)
		os.Exit(1)
	}

	entry, err := ledger.ReadLast()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading ledger: %v\n", err)
		os.Exit(1)
	}
	if entry == nil {
		fmt.Println("no decisions in ledger yet. run: sir kernel replay")
		return
	}
	fmt.Print(kernel.Explain(*entry))
}

// cmdKernelStatus shows current mode and provider health.
func cmdKernelStatus(args []string) {
	mode := kernel.ModeHookGate
	if ms, err := readModeState(); err == nil && ms != nil {
		mode = ms.Mode
	} else if env := os.Getenv("SIR_MODE"); env != "" {
		mode = env
	}

	// Engine status
	engine := os.Getenv("SIR_ENGINE")
	if engine == "" {
		engine = "go"
	}
	// Probe Rust kernel: presence is not callability. Do a real probe.
	evalStatus := "not found"
	if evalPath, err := findRustEval(); err == nil {
		probe := `{"case_id":"status-probe","mode":"hook_gate","signals":[],"evasion_flags":{},"prior_taint":[],"provider_capabilities":[]}` + "\n"
		cmd := exec.Command(evalPath)
		cmd.Stdin = strings.NewReader(probe)
		out, err := cmd.Output()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			evalStatus = "present (callable)"
		} else {
			evalStatus = "present (not callable)"
		}
	}

	fmt.Printf("Mode:           %s\n", mode)
	fmt.Printf("Guarantee:      %s\n", modeGuarantee(mode))
	fmt.Printf("Engine:         %s\n", engine)
	fmt.Printf("Rust kernel:    %s\n", evalStatus)
	fmt.Println()

	// Show last replay summary from ledger if available.
	ledger, err := kernel.OpenLedger(kernel.DefaultLedgerPath())
	if err == nil {
		if last, err := ledger.ReadLast(); err == nil && last != nil {
			fmt.Printf("Last decision: %s (%s) — case: %s\n",
				last.Decision.Verdict, last.Decision.Timestamp, last.CaseID)
		}
	}
	fmt.Println()

	// Provider health — reuse the same probe logic as `sir provider health`.
	// Skip gracefully if the providers directory is not present (e.g., when
	// running outside the repo or from a temp directory in tests).
	fmt.Println("Provider health:")
	fmt.Println(strings.Repeat("-", 70))
	if _, err := os.Stat("examples/providers"); err == nil {
		cmdProviderHealth([]string{"examples/providers"})
	} else {
		fmt.Println("(no providers directory; run from the repo root or set up providers)")
	}
}

// harnessCase re-declared for replay — mirrors the one in harness.go; both
// in package main so this is just a direct reference (no re-declaration needed).

// collectProviderCapabilities probes all providers in dir and collects the
// union of effect capabilities (block, contain, record, etc.) from healthy
// effect providers. This lets runtime replay derive capabilities from real
// providers rather than requiring them to be declared in fixture files.
// actionTypeToVerb maps a v2 signal action_claim.type to the v1 verb vocabulary
// that policy providers (policy-pack, OPA/Cedar bridges) evaluate against, so a
// live `sir kernel replay --use-providers` run produces meaningful verdicts. An
// action with no mapping passes through unchanged (an unknown verb simply won't
// match a provider's rules → allow).
var actionTypeToVerb = map[string]string{
	"vcs_push":        "push_origin",
	"vcs_commit":      "commit",
	"file_read":       "read_ref",
	"file_write":      "stage_write",
	"network_connect": "net_external",
	"network_fetch":   "net_external",
	"dns_lookup":      "dns_lookup",
}

var invokeKernelPolicyProviderForReplay = invokeKernelPolicyProvider

// collectLivePolicyVerdicts invokes active registered policy providers for a
// single case and returns their verdicts as kernel.PolicyVerdict. Used only
// behind `--use-providers`: it makes replay reflect what the selected lifecycle
// provider (`sir provider use/swap/disable`) actually returns, rather than the
// fixture-baked policy_verdicts. Errors are non-fatal (fail-open, like the hooks
// path). Directory scanning is opt-in dev behavior via --include-unregistered.
//
// This deliberately introduces nondeterminism (live provider state), so it is
// gated by the flag and never used on the `--engine both` parity path.
func collectLivePolicyVerdicts(dir string, includeUnregistered bool, c harnessCase, mode string) ([]kernel.PolicyVerdict, []kernel.ProviderEvidence) {
	actionType := kernel.PrimaryActionType(c.Signals)
	action := actionType
	if v, ok := actionTypeToVerb[actionType]; ok {
		action = v
	}
	actor := c.ResolvedActorKind
	if actor == "" {
		for _, s := range c.Signals {
			if s.ActorClaim != nil && s.ActorClaim.Kind != "" {
				actor = s.ActorClaim.Kind
				break
			}
		}
	}
	enf := kernel.AnalyzeEnforceability(kernel.EnforceabilityInput{Mode: mode, Signals: c.Signals})
	req := policy.PolicyRequest{
		Action:         action,
		Target:         kernel.DisplayTarget(c.Signals),
		ResolvedActor:  actor,
		Taint:          c.PriorTaint,
		Enforceability: enf.Class,
		Mode:           mode,
	}

	var out []kernel.PolicyVerdict
	var failures []kernel.ProviderEvidence
	seen := map[string]bool{}
	if reg, err := provider.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: load provider registry: %v\n", err)
		failures = append(failures, kernel.ProviderEvidence{
			Provider: "provider-registry",
			Kind:     provider.KindPolicy,
			Status:   "failed",
			Reason:   err.Error(),
			Behavior: "ignored; native policy used",
		})
	} else {
		for _, entry := range reg.Providers {
			seen[entry.Name] = true
		}
		active := reg.Active(provider.KindPolicy)
		if len(active) == 0 {
			for _, entry := range reg.Providers {
				if entry.Kind == provider.KindPolicy && !entry.Enabled {
					failures = append(failures, kernel.ProviderEvidence{
						Provider: entry.Name,
						Kind:     provider.KindPolicy,
						Status:   "disabled",
						Behavior: "not invoked; native policy used",
					})
				}
			}
		}
		for _, entry := range active {
			verdicts, failure := invokeKernelPolicyProviderForReplay(entry, req)
			out = append(out, verdicts...)
			if failure != nil {
				failures = append(failures, *failure)
			}
		}
	}
	if !includeUnregistered {
		return out, failures
	}
	manifests, err := findProviderManifests(dir)
	if err != nil {
		return out, failures
	}
	for _, mpath := range manifests {
		m, issues := loadAndValidateManifest(mpath)
		if m == nil || len(issues) > 0 || m.Kind != provider.KindPolicy {
			continue
		}
		if seen[m.Name] {
			continue
		}
		ep := filepath.Join(filepath.Dir(mpath), m.Entrypoint)
		verdicts, failure := invokeKernelPolicyProviderForReplay(provider.Entry{Name: m.Name, Kind: m.Kind, Entrypoint: ep}, req)
		out = append(out, verdicts...)
		if failure != nil {
			failures = append(failures, *failure)
		}
	}
	return out, failures
}

func invokeKernelPolicyProvider(entry provider.Entry, req policy.PolicyRequest) ([]kernel.PolicyVerdict, *kernel.ProviderEvidence) {
	verdicts, err := provider.InvokePolicy(entry, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sir: policy provider %s: %v\n", entry.Name, err)
		failure := providerFailureEvidence(entry.Name, provider.KindPolicy, err)
		return nil, &failure
	}
	out := make([]kernel.PolicyVerdict, 0, len(verdicts))
	for _, v := range verdicts {
		name := v.Provider
		if name == "" {
			name = entry.Name
		}
		out = append(out, kernel.PolicyVerdict{
			Provider:     name,
			Verdict:      v.Verdict,
			RulesMatched: v.RulesMatched,
			Reason:       v.Reason,
			IsAdvisory:   true,
		})
	}
	return out, nil
}

func providerFailureEvidence(name, kind string, err error) kernel.ProviderEvidence {
	reason := err.Error()
	status := "failed"
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(lower, "timed out") || strings.Contains(lower, "deadline exceeded"):
		status = "timeout"
	case strings.Contains(lower, "executable file not found") ||
		strings.Contains(lower, "no such file") ||
		strings.Contains(lower, "not found"):
		status = "unavailable"
	case strings.Contains(lower, "unmarshal") ||
		strings.Contains(lower, "invalid json") ||
		strings.Contains(lower, "wrong schema"):
		status = "invalid_output"
	}
	return kernel.ProviderEvidence{
		Provider: name,
		Kind:     kind,
		Status:   status,
		Reason:   reason,
		Behavior: "ignored; native policy used",
	}
}

func summarizeProviderPolicyEvidence(evidence []kernel.ProviderPolicyEvidence) string {
	var parts []string
	for _, ev := range evidence {
		part := ev.Provider + "=" + ev.Verdict
		if ev.Used {
			part += "(used)"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

func summarizeProviderFailures(evidence []kernel.ProviderEvidence) string {
	var parts []string
	for _, ev := range evidence {
		status := ev.Status
		if status == "" {
			status = "failed"
		}
		parts = append(parts, ev.Provider+"="+status)
	}
	return strings.Join(parts, ", ")
}

func collectProviderCapabilities(dir string, includeUnregistered bool) []string {
	capSet := map[string]bool{}
	seen := map[string]bool{}
	if reg, err := provider.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: load provider registry: %v\n", err)
	} else {
		for _, entry := range reg.Active(provider.KindEffect) {
			seen[entry.Name] = true
			mergeProviderCapabilities(capSet, entry.Entrypoint)
		}
	}
	if includeUnregistered {
		manifests, err := findProviderManifests(dir)
		if err != nil {
			return sortedCapabilityKeys(capSet)
		}
		for _, mpath := range manifests {
			m, issues := loadAndValidateManifest(mpath)
			if m == nil || len(issues) > 0 || m.Kind != "effect_provider" {
				continue
			}
			if seen[m.Name] {
				continue
			}
			ep := filepath.Join(filepath.Dir(mpath), m.Entrypoint)
			mergeProviderCapabilities(capSet, ep)
		}
	}
	return sortedCapabilityKeys(capSet)
}

func mergeProviderCapabilities(capSet map[string]bool, entrypoint string) {
	capsRaw, err := queryProviderCapabilities(entrypoint)
	if err != nil {
		return
	}
	// Parse the capabilities response to find true effect capabilities.
	var resp map[string]any
	if err := json.Unmarshal(capsRaw, &resp); err != nil {
		return
	}
	caps, _ := resp["capabilities"].(map[string]any)
	for _, effect := range []string{"block", "contain", "record", "nudge", "export", "redact"} {
		if v, ok := caps[effect]; ok {
			if b, ok := v.(bool); ok && b {
				capSet[effect] = true
			}
		}
	}
}

func sortedCapabilityKeys(capSet map[string]bool) []string {
	var result []string
	for k := range capSet {
		result = append(result, k)
	}
	sort.Strings(result)
	return result
}

func min8(n int) int {
	if n < 8 {
		return n
	}
	return 8
}

func modeGuarantee(mode string) string {
	switch mode {
	case kernel.ModeObserve:
		return "records only — no enforcement"
	case kernel.ModeAdvise:
		return "explains only — no enforcement"
	case kernel.ModeHookGate:
		return "enforces via cooperative pre-exec hooks; blind to detached children"
	case kernel.ModeOSObserved:
		return "detects post-hoc via OS sensor; cannot prevent"
	case kernel.ModeMediated:
		return "enforces when SIR launches/proxies the process"
	case kernel.ModeContained:
		return "enforces via sandbox/effect provider"
	case kernel.ModeManaged:
		return "enforces via signed policy + provider health"
	}
	return "unknown mode"
}

// dumpDecisionJSON writes a decision as indented JSON to stdout (debug helper).
func dumpDecisionJSON(d kernel.Decision) {
	b, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(b))
}

// loadCasesForReplay re-uses loadCases from harness.go (same package).
// sdk import needed to satisfy the Signals field type in the shared harnessCase.
var _ = sdk.Signal{}
var _ = filepath.Join
