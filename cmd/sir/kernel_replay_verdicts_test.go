package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/kernel"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/provider"
	"github.com/somoore/sir/pkg/sdk"
)

// TestActionTypeToVerb pins the v2-action → v1-verb mapping used by
// `sir kernel replay --use-providers` so live policy providers (which evaluate
// against the verb vocabulary) receive the right action for a v2 signal.
func TestActionTypeToVerb(t *testing.T) {
	cases := map[string]string{
		"vcs_push":        "push_origin",
		"vcs_commit":      "commit",
		"file_read":       "read_ref",
		"file_write":      "stage_write",
		"network_connect": "net_external",
		"network_fetch":   "net_external",
		"dns_lookup":      "dns_lookup",
	}
	for action, wantVerb := range cases {
		got, ok := actionTypeToVerb[action]
		if !ok {
			t.Errorf("actionTypeToVerb missing %q", action)
			continue
		}
		if got != wantVerb {
			t.Errorf("actionTypeToVerb[%q] = %q, want %q", action, got, wantVerb)
		}
	}
	// An unmapped action type must pass through unchanged (no panic, no entry).
	if _, ok := actionTypeToVerb["shell_exec"]; ok {
		t.Error("shell_exec should be unmapped (pass-through), not in the table")
	}
}

func TestParseKernelReplayOptionsSkipsFlagValues(t *testing.T) {
	t.Setenv("SIR_ENGINE", "go")

	opts := parseKernelReplayOptions([]string{
		"--mode", "mediated",
		"--engine", "rust",
		"--use-providers",
		"--providers-dir", "/tmp/providers",
		"--include-unregistered",
		"harness/custom",
	})

	if opts.dir != "harness/custom" {
		t.Fatalf("dir = %q, want harness/custom", opts.dir)
	}
	if opts.mode != "mediated" {
		t.Fatalf("mode = %q, want mediated", opts.mode)
	}
	if opts.engine != "rust" {
		t.Fatalf("engine = %q, want rust", opts.engine)
	}
	if !opts.useProviders || !opts.includeUnregistered {
		t.Fatalf("provider flags not parsed: %+v", opts)
	}
	if opts.providersDir != "/tmp/providers" {
		t.Fatalf("providersDir = %q, want /tmp/providers", opts.providersDir)
	}
}

func TestParseKernelReplayOptionsEqualsForms(t *testing.T) {
	t.Setenv("SIR_ENGINE", "go")

	opts := parseKernelReplayOptions([]string{
		"--mode=contained",
		"--engine=both",
		"--providers-dir=/tmp/equals-providers",
	})

	if opts.dir != "harness/fixtures/cases" {
		t.Fatalf("default dir = %q, want harness/fixtures/cases", opts.dir)
	}
	if opts.mode != "contained" || opts.engine != "both" || opts.providersDir != "/tmp/equals-providers" {
		t.Fatalf("unexpected parsed options: %+v", opts)
	}
}

func TestCollectLivePolicyVerdictsUsesActiveRegistry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	active := writeTestProvider(t, t.TempDir())
	disabled := writeTestProvider(t, t.TempDir())
	calls := stubReplayProviderInvocation(t, map[string]string{
		"registered-policy": "active-rule",
		"disabled-policy":   "disabled-rule",
	})
	reg := &provider.Registry{
		Providers: []provider.Entry{
			{Name: "registered-policy", Kind: provider.KindPolicy, Entrypoint: active, Enabled: true},
			{Name: "disabled-policy", Kind: provider.KindPolicy, Entrypoint: disabled, Enabled: false},
		},
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	verdicts, failures := collectLivePolicyVerdicts("", false, replayPolicyCase("vcs_push"), kernel.ModeHookGate)
	if len(verdicts) != 1 {
		t.Fatalf("verdicts: got %d, want 1: %+v", len(verdicts), verdicts)
	}
	if len(failures) != 0 {
		t.Fatalf("failures: got %+v, want none", failures)
	}
	if verdicts[0].Provider != "registered-policy" || verdicts[0].Verdict != "ask" {
		t.Fatalf("active provider verdict mismatch: %+v", verdicts[0])
	}
	if len(verdicts[0].RulesMatched) != 1 || verdicts[0].RulesMatched[0] != "active-rule" {
		t.Fatalf("active provider rule mismatch: %+v", verdicts[0])
	}
	if len(*calls) != 1 || (*calls)[0] != "registered-policy" {
		t.Fatalf("expected only active registered provider to be invoked, got %v", *calls)
	}
}

func TestCollectLivePolicyVerdictsRequiresIncludeUnregisteredForDirectoryScan(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	providerDir := filepath.Join(dir, "unregistered-policy")
	entrypoint := writeTestProvider(t, providerDir)
	calls := stubReplayProviderInvocation(t, map[string]string{
		"unregistered-policy": "dir-rule",
	})
	manifest := "schema_version: sir.provider.v0\n" +
		"name: unregistered-policy\n" +
		"kind: policy_provider\n" +
		"version: 0.1.0\n" +
		"protocol: stdio-json\n" +
		"entrypoint: " + filepath.Base(entrypoint) + "\n" +
		"platforms: [macos, linux]\n" +
		"capabilities:\n" +
		"  verdict_types: [allow, ask, deny]\n" +
		"  is_advisory: true\n"
	if err := os.WriteFile(filepath.Join(providerDir, "provider.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	if got, failures := collectLivePolicyVerdicts(dir, false, replayPolicyCase("vcs_push"), kernel.ModeHookGate); len(got) != 0 || len(failures) != 0 {
		t.Fatalf("unregistered providers must not be scanned by default: %+v", got)
	}
	if len(*calls) != 0 {
		t.Fatalf("unregistered provider invoked without --include-unregistered: %v", *calls)
	}
	got, failures := collectLivePolicyVerdicts(dir, true, replayPolicyCase("vcs_push"), kernel.ModeHookGate)
	if len(got) != 1 || got[0].Provider != "unregistered-policy" || got[0].RulesMatched[0] != "dir-rule" {
		t.Fatalf("include-unregistered verdict mismatch: %+v", got)
	}
	if len(failures) != 0 {
		t.Fatalf("failures: got %+v, want none", failures)
	}
	if len(*calls) != 1 || (*calls)[0] != "unregistered-policy" {
		t.Fatalf("expected one unregistered provider invocation, got %v", *calls)
	}
}

func TestCollectLivePolicyVerdictsRecordsProviderFailures(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	reg := &provider.Registry{
		Providers: []provider.Entry{
			{Name: "missing-policy", Kind: provider.KindPolicy, Entrypoint: filepath.Join(t.TempDir(), "missing-provider"), Enabled: true},
		},
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	verdicts, failures := collectLivePolicyVerdicts("", false, replayPolicyCase("vcs_push"), kernel.ModeHookGate)
	if len(verdicts) != 0 {
		t.Fatalf("verdicts: got %+v, want none", verdicts)
	}
	if len(failures) != 1 {
		t.Fatalf("failures: got %d, want 1: %+v", len(failures), failures)
	}
	if failures[0].Provider != "missing-policy" || failures[0].Status != "unavailable" {
		t.Fatalf("failure mismatch: %+v", failures[0])
	}
}

func TestCollectLivePolicyVerdictsRecordsDisabledPolicyWhenNoActiveProvider(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	providerDir := filepath.Join(dir, "disabled-policy")
	entrypoint := writeTestProvider(t, providerDir)
	manifest := "schema_version: sir.provider.v0\n" +
		"name: disabled-policy\n" +
		"kind: policy_provider\n" +
		"version: 0.1.0\n" +
		"protocol: stdio-json\n" +
		"entrypoint: " + filepath.Base(entrypoint) + "\n" +
		"platforms: [macos, linux]\n" +
		"capabilities:\n" +
		"  verdict_types: [allow, ask, deny]\n" +
		"  is_advisory: true\n"
	if err := os.WriteFile(filepath.Join(providerDir, "provider.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	calls := stubReplayProviderInvocation(t, map[string]string{"disabled-policy": "should-not-run"})
	reg := &provider.Registry{
		Providers: []provider.Entry{
			{Name: "disabled-policy", Kind: provider.KindPolicy, Entrypoint: entrypoint, Enabled: false},
		},
	}
	if err := reg.Save(); err != nil {
		t.Fatalf("save registry: %v", err)
	}

	verdicts, failures := collectLivePolicyVerdicts(dir, true, replayPolicyCase("vcs_push"), kernel.ModeHookGate)
	if len(verdicts) != 0 {
		t.Fatalf("verdicts: got %+v, want none", verdicts)
	}
	if len(failures) != 1 || failures[0].Provider != "disabled-policy" || failures[0].Status != "disabled" {
		t.Fatalf("disabled provider evidence mismatch: %+v", failures)
	}
	if len(*calls) != 0 {
		t.Fatalf("disabled registered provider must not be invoked through include-unregistered: %v", *calls)
	}
}

func replayPolicyCase(actionType string) harnessCase {
	return harnessCase{
		CaseID: "test-case",
		Mode:   "hook_gate",
		Signals: []sdk.Signal{
			{
				SchemaVersion: sdk.SchemaSignalV0,
				SignalID:      "sig-test",
				Source:        sdk.Source{Kind: "claude_hook", Reliability: sdk.ReliabilityDeclaredIntent, Timing: sdk.TimingPreExec},
				ActorClaim:    &sdk.ActorClaim{Kind: "ai_coding_agent", Name: "agent"},
				ActionClaim: map[string]any{
					"type":   actionType,
					"target": map[string]any{"display": actionType, "sensitivity": "low"},
				},
			},
		},
	}
}

func stubReplayProviderInvocation(t *testing.T, rules map[string]string) *[]string {
	t.Helper()
	var calls []string
	old := invokeKernelPolicyProviderForReplay
	invokeKernelPolicyProviderForReplay = func(entry provider.Entry, req policy.PolicyRequest) ([]kernel.PolicyVerdict, *kernel.ProviderEvidence) {
		calls = append(calls, entry.Name)
		rule := rules[entry.Name]
		if rule == "" {
			rule = "test-rule"
		}
		return []kernel.PolicyVerdict{{
			Provider:     entry.Name,
			Verdict:      "ask",
			RulesMatched: []string{rule},
			IsAdvisory:   true,
		}}, nil
	}
	t.Cleanup(func() {
		invokeKernelPolicyProviderForReplay = old
	})
	return &calls
}

func writeTestProvider(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir provider dir: %v", err)
	}
	path := filepath.Join(dir, "provider.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write provider: %v", err)
	}
	return path
}
