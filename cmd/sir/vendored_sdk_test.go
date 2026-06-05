package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestVendoredProviderSDKMatchesSource guards the example providers that ship a
// copy of sir_sdk.py beside their entrypoint. Those vendored copies are what make
// the bundled providers work on a real off-repo install (where the canonical
// sdk/python/ does not exist on the spawned provider's PYTHONPATH). If a vendored
// copy drifts from the source of truth, the example silently runs an old SDK —
// so we pin them byte-for-byte to sdk/python/sir_sdk.py.
//
// To intentionally update them: re-copy sdk/python/sir_sdk.py into each provider
// directory in the same commit that changes the source.
func TestVendoredProviderSDKMatchesSource(t *testing.T) {
	root := repoRoot(t)

	source, err := os.ReadFile(filepath.Join(root, "sdk", "python", "sir_sdk.py"))
	if err != nil {
		t.Fatalf("read source sir_sdk.py: %v", err)
	}

	vendored := []string{
		filepath.Join("examples", "providers", "opa-authoritative", "sir_sdk.py"),
		filepath.Join("examples", "providers", "cedar-authoritative", "sir_sdk.py"),
	}
	for _, rel := range vendored {
		got, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Errorf("vendored SDK %s missing — bundled provider would fail-closed on a real install: %v", rel, err)
			continue
		}
		if string(got) != string(source) {
			t.Errorf("vendored SDK %s has drifted from sdk/python/sir_sdk.py; re-copy it in the same commit that changed the source", rel)
		}
	}
}
