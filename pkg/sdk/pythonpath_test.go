package sdk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSDKPythonPathIsAbsoluteAndIncludesProviderDir is the regression guard for
// the provider-spawn fail-closed bug: a CWD-relative "sdk/python" made every
// Python provider raise ModuleNotFoundError unless sir ran from the repo root,
// which silently fail-closed authoritative providers on every call. The fix is
// that the PYTHONPATH must (a) be absolute and (b) include the provider's own
// directory so a sir_sdk.py vendored beside the entrypoint resolves regardless
// of the spawned process's working directory.
func TestSDKPythonPathIsAbsoluteAndIncludesProviderDir(t *testing.T) {
	entrypoint := filepath.Join(t.TempDir(), "myprovider", "provider.py")
	got := SDKPythonPath(entrypoint)

	const prefix = "PYTHONPATH="
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("missing PYTHONPATH= prefix: %q", got)
	}
	value := strings.TrimPrefix(got, prefix)
	entries := strings.Split(value, string(os.PathListSeparator))

	// The provider's own directory must be present AND first (highest import
	// precedence) so a vendored sir_sdk.py beside the entrypoint wins. This is
	// the path real off-repo installs depend on — the bundled SDK directory does
	// not exist there.
	wantDir := filepath.Dir(entrypoint)
	if len(entries) == 0 || entries[0] != wantDir {
		t.Fatalf("provider dir must be first on PYTHONPATH for vendor precedence; got first=%q want=%q (entries=%v)", firstOr(entries), wantDir, entries)
	}

	// Every sir-injected entry must be absolute — the original bug was a bare
	// CWD-relative "sdk/python". With no operator PYTHONPATH set (this test does
	// not set one), all entries are sir-injected, so all must be absolute.
	if _, ok := os.LookupEnv("PYTHONPATH"); !ok {
		for _, e := range entries {
			if e != "" && !filepath.IsAbs(e) {
				t.Errorf("sir-injected PYTHONPATH entry must be absolute, got relative %q", e)
			}
		}
	}
}

// TestSDKPythonPathPreservesOperatorEnv ensures an operator-set PYTHONPATH is
// preserved (appended), never dropped.
func TestSDKPythonPathPreservesOperatorEnv(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "custom-libs")
	t.Setenv("PYTHONPATH", custom)

	got := SDKPythonPath("/abs/provider/provider.py")
	if !strings.Contains(got, custom) {
		t.Errorf("operator PYTHONPATH %q dropped from %q", custom, got)
	}
}

// TestSDKPythonPathNeverIncludesCWD is the security regression guard: the spawned
// provider inherits the agent's PROJECT working directory, so adding CWD/sdk/python
// to its import path would let a hostile repo plant sdk/python/sir_sdk.py and have a
// security-critical authoritative policy provider import project-controlled code
// (able to suppress or flip verdicts). The resolver must use only trusted locations
// — the provider's install-resolved dir and the SDK beside the sir binary — never
// CWD. Codex flagged the CWD fallback on PR #214.
func TestSDKPythonPathNeverIncludesCWD(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	cwdSDK := filepath.Join(cwd, "sdk", "python")

	// Empty PYTHONPATH so the only entries are sir-injected; an operator could
	// legitimately set a relative entry, but sir must never inject CWD itself.
	t.Setenv("PYTHONPATH", "")
	got := SDKPythonPath(filepath.Join(t.TempDir(), "prov", "provider.py"))

	for _, entry := range strings.Split(strings.TrimPrefix(got, "PYTHONPATH="), string(os.PathListSeparator)) {
		if entry == cwdSDK {
			t.Errorf("PYTHONPATH must not include the working-directory SDK %q (CWD-controlled import into a policy provider): %q", cwdSDK, got)
		}
	}
}

func firstOr(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}
