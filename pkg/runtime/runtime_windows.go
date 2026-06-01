//go:build windows

package runtime

import "fmt"

// runAgentWindows is the Windows containment entry point.
//
// Windows has no user-mode equivalent of sandbox-exec or Linux network
// namespaces, so OS-level containment is unavailable. `sir run` returns an
// informative error rather than silently launching uncontained; use
// `sir on` / hook_gate mode for Windows protection.
//
// Hook mediation, IFC taint tracking, the policy oracle, and the ledger all
// operate normally on Windows — only the below-hook OS boundary is absent.
// `sir status` reports this honestly under the "containment" field.
func runAgentWindows(projectRoot, bin string, opts Options) (int, error) {
	return 0, fmt.Errorf(
		"OS-level containment (sir run) is not available on Windows; " +
			"windows_hook_gate_only mode is active — hooks, IFC, and policy enforcement work normally. " +
			"Use 'sir on' to activate hook_gate protection, or run 'sir status' to see what is enforced",
	)
}
