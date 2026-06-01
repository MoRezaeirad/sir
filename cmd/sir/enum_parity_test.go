package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/kernel"
	"github.com/somoore/sir/pkg/sdk"
)

// TestEnumParity verifies that the SIR enum vocabularies stay aligned across
// every surface that declares them: the Go SDK/kernel constants (the canonical
// source), the Python SDK, the Rust sir-core constants, and the JSON schemas.
//
// The Go constants are the canonical anchor. Each other surface must mirror
// them exactly. Changing a value in one place without updating the others
// fails this test, naming the surface and the diff.
//
// repoRoot(t) and readFile(t, root, rel) are shared helpers defined in
// public_contract_test.go.
func TestEnumParity(t *testing.T) {
	root := repoRoot(t)

	// Canonical sets, referenced directly from Go constants. Renaming or
	// removing any of these breaks compilation here, which is intentional.
	canonical := map[string][]string{
		"reliability": {
			sdk.ReliabilityDeclaredIntent, sdk.ReliabilityMediatedAction,
			sdk.ReliabilityObservedRuntime, sdk.ReliabilityEnforcedBoundary,
			sdk.ReliabilityAdvisorySignal, sdk.ReliabilityUserDecision,
			sdk.ReliabilityAdminPolicy,
		},
		"timing": {
			sdk.TimingPreExec, sdk.TimingDuringExec, sdk.TimingPostExec, sdk.TimingUnknown,
		},
		"effect_type": {
			sdk.EffectRecord, sdk.EffectNudge, sdk.EffectRedact, sdk.EffectPrompt,
			sdk.EffectBlock, sdk.EffectContain, sdk.EffectExport,
			sdk.EffectKillProcess, sdk.EffectRequestException,
		},
		"effect_status": {
			sdk.EffectApplied, sdk.EffectUnavailable, sdk.EffectFailed, sdk.EffectNotSupported,
		},
		"provider_kind": {
			sdk.KindSignalProvider, sdk.KindEffectProvider, sdk.KindPolicyProvider,
			sdk.KindAdvisoryProvider, sdk.KindExportProvider,
		},
		"mode": {
			kernel.ModeObserve, kernel.ModeAdvise, kernel.ModeHookGate,
			kernel.ModeOSObserved, kernel.ModeMediated, kernel.ModeContained,
			kernel.ModeManaged,
		},
		"verdict": {
			kernel.VerdictAllow, kernel.VerdictAsk, kernel.VerdictDeny,
		},
		"decision_class": {
			kernel.DecisionClassProceedAndReconcile, kernel.DecisionClassBlockAndWait,
			kernel.DecisionClassDenyNow, kernel.DecisionClassRecordPostHoc,
		},
		"enforceability": {
			kernel.ClassEnforces, kernel.ClassDetects, kernel.ClassBlind,
		},
	}

	pyConsts := readFile(t, root, "sdk/python/sir_sdk.py")
	rustSrc := readFile(t, root, "sir-core/src/lib.rs")

	check := func(category, surface string, got map[string]bool) {
		want := enumToSet(canonical[category])
		if !enumSetsEqual(want, got) {
			t.Errorf("%s enum mismatch in %s:\n  want: %v\n  got:  %v",
				category, surface, enumSorted(want), enumSorted(got))
		}
	}

	// reliability
	check("reliability", "Python SDK", pyEnumSet(pyConsts, "RELIABILITY_"))
	check("reliability", "Rust mod reliability", rustModEnumSet(rustSrc, "reliability"))
	check("reliability", "schema signal.source.reliability",
		schemaEnumSet(t, root, "sir.signal.v0.schema.json", "properties", "source", "properties", "reliability"))

	// timing
	check("timing", "Python SDK", pyEnumSet(pyConsts, "TIMING_"))
	check("timing", "Rust mod timing", rustModEnumSet(rustSrc, "timing"))
	check("timing", "schema signal.source.timing",
		schemaEnumSet(t, root, "sir.signal.v0.schema.json", "properties", "source", "properties", "timing"))

	// effect_type: Python EFFECT_*; schema effect_request.type.
	// (Rust has no effect-type module; it is not part of the pure decision path.)
	check("effect_type", "Python SDK", pyEnumSet(pyConsts, "EFFECT_"))
	check("effect_type", "schema effect_request.type",
		schemaEnumSet(t, root, "sir.effect_request.v0.schema.json", "properties", "type"))

	// effect_status: Python STATUS_*; schema effect_result.status.
	check("effect_status", "Python SDK", pyEnumSet(pyConsts, "STATUS_"))
	check("effect_status", "schema effect_result.status",
		schemaEnumSet(t, root, "sir.effect_result.v0.schema.json", "properties", "status"))

	// provider_kind: Python KIND_*; schema provider.kind.
	check("provider_kind", "Python SDK", pyEnumSet(pyConsts, "KIND_"))
	check("provider_kind", "schema provider.kind",
		schemaEnumSet(t, root, "sir.provider.v0.schema.json", "properties", "kind"))

	// mode / verdict / decision_class / enforceability are kernel-internal:
	// mirrored only in Rust (no Python SDK constant, no JSON schema enum).
	check("mode", "Rust mod modes", rustModEnumSet(rustSrc, "modes"))
	check("verdict", "Rust mod verdicts", rustModEnumSet(rustSrc, "verdicts"))
	check("decision_class", "Rust mod decision_classes", rustModEnumSet(rustSrc, "decision_classes"))
	check("enforceability", "Rust mod classes", rustModEnumSet(rustSrc, "classes"))
}

// pyEnumConstRe matches Python module-level string constants: NAME = "value".
var pyEnumConstRe = regexp.MustCompile(`(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*"([^"]+)"`)

// pyEnumSet collects values of Python constants whose name starts with prefix.
func pyEnumSet(src, prefix string) map[string]bool {
	out := map[string]bool{}
	for _, m := range pyEnumConstRe.FindAllStringSubmatch(src, -1) {
		if strings.HasPrefix(m[1], prefix) {
			out[m[2]] = true
		}
	}
	return out
}

// rustEnumConstRe matches Rust string constants: const NAME: &str = "value".
var rustEnumConstRe = regexp.MustCompile(`const\s+[A-Z][A-Z0-9_]*\s*:\s*&str\s*=\s*"([^"]+)"`)

// rustModEnumSet extracts the value set of a `pub mod NAME { ... }` block.
// The constant modules contain no nested braces, so a non-greedy match to the
// first closing brace captures exactly the module body.
func rustModEnumSet(src, modName string) map[string]bool {
	blockRe := regexp.MustCompile(`(?s)pub mod ` + regexp.QuoteMeta(modName) + `\s*\{(.*?)\}`)
	m := blockRe.FindStringSubmatch(src)
	out := map[string]bool{}
	if m == nil {
		return out // empty set -> mismatch reported by caller
	}
	for _, c := range rustEnumConstRe.FindAllStringSubmatch(m[1], -1) {
		out[c[1]] = true
	}
	return out
}

// schemaEnumSet navigates a JSON schema along keys and returns the enum value set.
func schemaEnumSet(t *testing.T, root, file string, path ...string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "schemas", file))
	if err != nil {
		t.Fatalf("read schema %s: %v", file, err)
	}
	var node any
	if err := json.Unmarshal(data, &node); err != nil {
		t.Fatalf("parse schema %s: %v", file, err)
	}
	for _, key := range path {
		m, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("schema %s: expected object at %q", file, key)
		}
		node, ok = m[key]
		if !ok {
			t.Fatalf("schema %s: missing key %q in path %v", file, key, path)
		}
	}
	m, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("schema %s: path %v is not an object", file, path)
	}
	arr, ok := m["enum"].([]any)
	if !ok {
		t.Fatalf("schema %s: no enum at path %v", file, path)
	}
	out := map[string]bool{}
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out[s] = true
		}
	}
	return out
}

func enumToSet(vals []string) map[string]bool {
	out := map[string]bool{}
	for _, v := range vals {
		out[v] = true
	}
	return out
}

func enumSetsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func enumSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
