package sdk

import (
	"os"
	"path/filepath"
	"strings"
)

// SDKPythonPath returns the PYTHONPATH env entry ("PYTHONPATH=...") that makes
// a spawned Python provider able to `import sir_sdk` with no pip install and no
// manual PYTHONPATH from the operator.
//
// The Python SDK is a single vendorable file (sdk/python/sir_sdk.py). A provider
// may keep its own copy beside its entrypoint, or rely on the bundled one. This
// makes BOTH importable using ABSOLUTE paths so resolution never depends on the
// spawned process's working directory — which is the user's PROJECT directory,
// not sir's install tree.
//
// The earlier implementation used a CWD-relative "sdk/python", which silently
// fail-closed every provider unless sir happened to be run from the repo root.
// For any real install (or any agent hook firing inside a project dir), the
// import raised ModuleNotFoundError, the provider exited non-zero, and an
// authoritative provider then fail-closed on EVERY call. This restores the
// documented "vendor sir_sdk.py next to your provider" model.
//
// Search order (first match wins on `import sir_sdk`):
//  1. the provider's own directory (absolute, from the resolved entrypoint);
//  2. sdk/python resolved next to the sir binary (os.Executable), then <root>/
//     sdk/python, then CWD/sdk/python — covers checkout and SDK-shipping installs;
//  3. any pre-existing PYTHONPATH the operator set, appended last (preserved but
//     lowest precedence).
func SDKPythonPath(entrypoint string) string {
	var parts []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		parts = append(parts, p)
	}

	// 1. The provider's own directory (entrypoint is stored absolute at install).
	if entrypoint != "" {
		if abs, err := filepath.Abs(entrypoint); err == nil {
			add(filepath.Dir(abs))
		}
	}

	// 2. Bundled SDK, resolved absolutely relative to the sir BINARY only.
	//
	// SECURITY: we deliberately do NOT fall back to the current working
	// directory. The provider inherits the agent's project CWD, so adding
	// CWD/sdk/python would let a hostile repo plant sdk/python/sir_sdk.py and have
	// a security-critical authoritative policy provider import project-controlled
	// code — able to suppress or flip verdicts. Only trusted locations belong on a
	// policy provider's import path: the provider's own (install-resolved) dir
	// above, and the SDK shipped beside the sir binary here. A repo checkout is
	// already covered because bin/sir lives at <repo>/bin/sir, so the binary-
	// relative paths below resolve <repo>/sdk/python without trusting CWD.
	if exe, err := os.Executable(); err == nil {
		binDir := filepath.Dir(exe)
		add(filepath.Join(binDir, "sdk", "python"))               // alongside the binary
		add(filepath.Join(filepath.Dir(binDir), "sdk", "python")) // <root>/sdk/python (bin/sir → root)
	}

	// 3. Operator-provided PYTHONPATH, last.
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		for _, p := range strings.Split(existing, string(os.PathListSeparator)) {
			add(p)
		}
	}

	return "PYTHONPATH=" + strings.Join(parts, string(os.PathListSeparator))
}
