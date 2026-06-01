package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/kernel"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/provider"
	"github.com/somoore/sir/pkg/sdk"
)

// policyReqFromFlags parses the common request flags shared by `sir policy test`
// and `sir policy explain`.
func policyReqFromFlags(args []string) (policy.PolicyRequest, string, string) {
	req := policy.PolicyRequest{Mode: "guard"}
	manifest := ""
	fixture := ""
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--provider":
			manifest = next()
		case "--fixture":
			fixture = next()
		case "--action":
			req.Action = next()
		case "--target":
			req.Target = next()
		case "--actor":
			req.ResolvedActor = next()
		case "--taint":
			if v := next(); v != "" {
				req.Taint = strings.Split(v, ",")
			}
		case "--mode":
			req.Mode = next()
		case "--enforceability":
			req.Enforceability = next()
		default:
			if !strings.HasPrefix(args[i], "--") && manifest == "" {
				manifest = args[i]
			}
		}
	}
	if fixture != "" {
		applyPolicyFixture(&req, fixture)
	}
	return req, manifest, fixture
}

// cmdPolicyProviderTest sends a single policy request to a policy provider and
// prints its verdict — lets policy-pack/OPA/Cedar authors debug one request
// without running a full sir guard cycle.
//
//	sir policy test --provider <manifest> --action push_origin --taint credential_access
func cmdPolicyProviderTest(args []string) {
	req, providerArg, fixture := policyReqFromFlags(args)
	if req.Action == "" {
		fatal("usage: sir policy test <provider|manifest.yaml> --action <verb> [--fixture request.json] [--target t] [--actor kind] [--taint a,b] [--mode m]")
	}
	if providerArg == "" {
		fatal("provider name or --provider <manifest.yaml> is required for `sir policy test`")
	}
	entry, kind := resolvePolicyProviderEntry(providerArg)
	if kind != sdk.KindPolicyProvider {
		fatal("`sir policy test` requires a policy_provider, got %s", kind)
	}
	providerReq := req
	providerReq.Action = actionForPolicyProvider(req.Action)

	fmt.Println("Policy request:")
	fmt.Printf("  action: %s\n", providerReq.Action)
	if fixture != "" {
		fmt.Printf("  fixture: %s\n", fixture)
	}
	if providerReq.Target != "" {
		fmt.Printf("  target: %s\n", providerReq.Target)
	}
	if providerReq.ResolvedActor != "" {
		fmt.Printf("  actor: %s\n", providerReq.ResolvedActor)
	}
	if len(providerReq.Taint) > 0 {
		fmt.Printf("  taint: %s\n", strings.Join(providerReq.Taint, ", "))
	}
	fmt.Printf("  mode: %s\n", providerReq.Mode)

	verdicts, err := provider.InvokePolicy(entry, providerReq)
	if err != nil {
		fmt.Println("Provider verdict:")
		fmt.Printf("  %s: unavailable\n", entry.Name)
		fmt.Printf("    reason: %v\n", err)
		fmt.Println("    behavior: ignored; native policy used")
		printPolicyTestFinal(req, nil)
		return
	}
	fmt.Println("Provider verdict:")
	if len(verdicts) == 0 {
		fmt.Printf("  %s: unavailable or no matching verdict\n", entry.Name)
		fmt.Println("    behavior: ignored; native policy used")
		printPolicyTestFinal(req, nil)
		return
	}
	for _, v := range verdicts {
		name := v.Provider
		if name == "" {
			name = entry.Name
		}
		fmt.Printf("  %s: %s\n", name, v.Verdict)
		if len(v.RulesMatched) > 0 {
			fmt.Printf("    rules: %s\n", strings.Join(v.RulesMatched, ", "))
		}
		if v.Reason != "" {
			fmt.Printf("    reason: %s\n", v.Reason)
		}
	}
	printPolicyTestFinal(req, verdicts)
}

// cmdPolicyExplain shows how a verdict would COMPOSE: it runs the real kernel
// composition (native floors → developer-workflow floor → advisory escalation)
// and prints each layer so authors can see why an advisory verdict was honored
// or suppressed.
//
//	sir policy explain --action vcs_commit --verdict opa=deny
//	sir policy explain --action vcs_push --taint credential_access --verdict opa=ask
func cmdPolicyExplain(args []string) {
	req, providerArg, _ := policyReqFromFlags(args)
	var advisoryVerdict, advisoryProvider string
	for i := 0; i < len(args); i++ {
		if args[i] == "--verdict" && i+1 < len(args) {
			kv := args[i+1]
			if idx := strings.IndexByte(kv, '='); idx > 0 {
				advisoryProvider, advisoryVerdict = kv[:idx], kv[idx+1:]
			} else {
				advisoryProvider, advisoryVerdict = "provider", kv
			}
			i++
		}
	}
	if req.Action == "" {
		fatal("usage: sir policy explain --action <action_type> [--taint a,b] [--verdict provider=allow|ask|deny] [--provider <name|manifest>]")
	}

	actor := req.ResolvedActor
	if actor == "" {
		actor = "ai_coding_agent"
	}
	// Build a synthetic signal for the action so the real kernel runs.
	sig := sdk.Signal{
		SchemaVersion: sdk.SchemaSignalV0,
		SignalID:      "explain-sig",
		Source:        sdk.Source{Kind: "explain", Reliability: sdk.ReliabilityDeclaredIntent, Timing: sdk.TimingPreExec},
		ActorClaim:    &sdk.ActorClaim{Kind: actor},
		ActionClaim: map[string]any{
			"type":   actionForKernel(req.Action),
			"target": map[string]any{"display": req.Target, "sensitivity": sensitivityForPolicyRequest(req)},
		},
	}
	in := kernel.EvaluationInput{
		Mode:       kernel.ModeHookGate,
		Signals:    []sdk.Signal{sig},
		PriorTaint: req.Taint,
	}

	// Base (no advisory verdict): the native + floor decision.
	base := kernel.Evaluate(in)

	fmt.Printf("action=%s actor=%s taint=%v\n\n", req.Action, actor, req.Taint)
	fmt.Printf("1. native decision (floors, low-confidence): %s\n", base.Verdict)
	floored := base.Verdict == "allow" && isExplainFloored(req.Taint, actionForKernel(req.Action))
	fmt.Printf("2. developer-workflow floor protects this action: %v\n", floored)

	var providerVerdicts []policy.PolicyVerdict
	if advisoryVerdict == "" && providerArg != "" {
		entry, kind := resolvePolicyProviderEntry(providerArg)
		if kind != sdk.KindPolicyProvider {
			fatal("`sir policy explain --provider` requires a policy_provider, got %s", kind)
		}
		providerReq := req
		providerReq.Action = actionForPolicyProvider(req.Action)
		verdicts, err := provider.InvokePolicy(entry, providerReq)
		if err != nil {
			fmt.Printf("3. policy provider: %s unavailable\n", entry.Name)
			fmt.Printf("   reason: %v\n", err)
			fmt.Printf("   → native policy used\n")
			fmt.Printf("\nfinal: %s\n", base.Verdict)
			return
		}
		providerVerdicts = verdicts
		if len(verdicts) == 0 {
			fmt.Printf("3. policy provider: %s unavailable or no matching verdict\n", entry.Name)
			fmt.Printf("   → native policy used\n")
			fmt.Printf("\nfinal: %s\n", base.Verdict)
			return
		}
		advisoryProvider = entry.Name
		advisoryVerdict = verdicts[0].Verdict
	}

	if advisoryVerdict == "" {
		fmt.Printf("3. no advisory verdict supplied\n")
		fmt.Printf("\nfinal: %s\n", base.Verdict)
		return
	}

	in.PolicyVerdicts = kernelVerdictsFromPolicy(providerVerdicts)
	if len(in.PolicyVerdicts) == 0 {
		in.PolicyVerdicts = []kernel.PolicyVerdict{{
			Provider: advisoryProvider, Verdict: advisoryVerdict,
			RulesMatched: []string{"explain-rule"}, IsAdvisory: true,
		}}
	}
	composed := kernel.Evaluate(in)
	fmt.Printf("3. advisory verdict: %s says %s\n", in.PolicyVerdicts[0].Provider, in.PolicyVerdicts[0].Verdict)
	if composed.Verdict == base.Verdict {
		if floored {
			fmt.Printf("   → suppressed by the developer-workflow floor (clean coding action)\n")
		} else if base.Verdict != "allow" {
			fmt.Printf("   → cannot change a native %s (advisory can only escalate allow→ask)\n", base.Verdict)
		} else {
			fmt.Printf("   → no change\n")
		}
	} else {
		fmt.Printf("   → escalated %s → %s\n", base.Verdict, composed.Verdict)
	}
	fmt.Printf("\nfinal: %s\n", composed.Verdict)
}

func applyPolicyFixture(req *policy.PolicyRequest, fixture string) {
	data, err := os.ReadFile(fixture)
	if err != nil {
		fatal("read fixture: %v", err)
	}
	var fromFixture policy.PolicyRequest
	if err := json.Unmarshal(data, &fromFixture); err != nil {
		fatal("parse fixture: %v", err)
	}
	if fromFixture.Mode == "" {
		fromFixture.Mode = req.Mode
	}
	*req = fromFixture
}

func resolvePolicyProviderEntry(arg string) (provider.Entry, string) {
	if arg == "" {
		fatal("provider is required")
	}
	if looksLikeManifestPath(arg) {
		manifestPath, err := filepath.Abs(arg)
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
		entrypoint, err := filepath.Abs(filepath.Join(filepath.Dir(manifestPath), m.Entrypoint))
		if err != nil {
			fatal("resolve entrypoint: %v", err)
		}
		return provider.Entry{Name: m.Name, Entrypoint: entrypoint}, m.Kind
	}
	reg, err := provider.Load()
	if err != nil {
		fatal("load registry: %v", err)
	}
	entry, ok := reg.ByName(arg)
	if !ok {
		fatal("provider %q not found in registry; use a manifest path or run `sir provider install`", arg)
	}
	return *entry, entry.Kind
}

func looksLikeManifestPath(arg string) bool {
	if strings.ContainsRune(arg, os.PathSeparator) || strings.HasSuffix(arg, ".yaml") || strings.HasSuffix(arg, ".yml") {
		return true
	}
	if _, err := os.Stat(arg); err == nil {
		return true
	}
	return false
}

func printPolicyTestFinal(req policy.PolicyRequest, verdicts []policy.PolicyVerdict) {
	out := evaluatePolicyRequest(req, verdicts)
	fmt.Println("Final Rust decision:")
	fmt.Printf("  verdict: %s\n", out.Verdict)
	if len(out.PolicyRules) > 0 {
		fmt.Printf("  rules: %s\n", strings.Join(out.PolicyRules, ", "))
	}
}

func evaluatePolicyRequest(req policy.PolicyRequest, verdicts []policy.PolicyVerdict) kernel.EvaluationOutput {
	actor := req.ResolvedActor
	if actor == "" {
		actor = "ai_coding_agent"
	}
	sig := sdk.Signal{
		SchemaVersion: sdk.SchemaSignalV0,
		SignalID:      "policy-test-sig",
		Source:        sdk.Source{Kind: "policy_test", Reliability: sdk.ReliabilityDeclaredIntent, Timing: sdk.TimingPreExec},
		ActorClaim:    &sdk.ActorClaim{Kind: actor},
		ActionClaim: map[string]any{
			"type":   actionForKernel(req.Action),
			"target": map[string]any{"display": req.Target, "sensitivity": sensitivityForPolicyRequest(req)},
		},
	}
	return kernel.Evaluate(kernel.EvaluationInput{
		Mode:           kernel.ModeHookGate,
		Signals:        []sdk.Signal{sig},
		PriorTaint:     req.Taint,
		PolicyVerdicts: kernelVerdictsFromPolicy(verdicts),
	})
}

func kernelVerdictsFromPolicy(verdicts []policy.PolicyVerdict) []kernel.PolicyVerdict {
	out := make([]kernel.PolicyVerdict, 0, len(verdicts))
	for _, v := range verdicts {
		out = append(out, kernel.PolicyVerdict{
			Provider:     v.Provider,
			Verdict:      v.Verdict,
			RulesMatched: v.RulesMatched,
			Reason:       v.Reason,
			IsAdvisory:   v.IsAdvisory,
		})
	}
	return out
}

func actionForPolicyProvider(action string) string {
	if v, ok := actionTypeToVerb[action]; ok {
		return v
	}
	return action
}

func actionForKernel(action string) string {
	switch action {
	case "push_origin", "push_remote":
		return "vcs_push"
	case "commit":
		return "vcs_commit"
	case "read_ref":
		return "file_read"
	case "stage_write":
		return "file_write"
	case "run_tests", "search_code", "dns_lookup":
		return action
	case "list_files":
		return "file_list"
	case "net_external", "net_allowlisted", "net_local":
		return "network_connect"
	default:
		return action
	}
}

func sensitivityForPolicyRequest(req policy.PolicyRequest) string {
	action := actionForKernel(req.Action)
	switch action {
	case "vcs_push":
		for _, t := range req.Taint {
			if t == "credential_access" {
				return "external_network"
			}
		}
		return "low"
	case "network_connect", "network_fetch", "dns_lookup":
		return "external_network"
	default:
		return "low"
	}
}

// isExplainFloored mirrors the kernel's developer-workflow floor for display.
func isExplainFloored(taint []string, action string) bool {
	for _, t := range taint {
		if t == "credential_access" {
			return false
		}
	}
	switch action {
	case "file_read", "file_write", "file_list", "run_tests", "search_code", "vcs_status", "vcs_diff", "vcs_commit":
		return true
	}
	return false
}
