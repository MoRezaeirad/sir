package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BuildDarwinProfile creates the sandbox-exec profile used by the macOS
// runtime launcher. The profile generation itself is platform-neutral so it
// stays available to cross-platform tests and benchmarks.
//
// Profile structure (Seatbelt: last matching rule wins):
//  1. (allow default) — grant everything as a baseline.
//  2. Deny outbound network, allow localhost and unix sockets.
//  3. Deny writes to sir-protected paths (hook config, posture files, etc).
//  4. Re-allow writes to agent session dirs within protected trees that the
//     sir hooks need to function (e.g. ~/.claude/session-env).
func BuildDarwinProfile(projectRoot string, opts Options) (string, error) {
	var profile strings.Builder
	profile.WriteString("(version 1)\n")
	profile.WriteString("(allow default)\n")
	profile.WriteString("(deny network-outbound)\n")
	profile.WriteString("(allow network-outbound (remote unix-socket))\n")
	profile.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
	guards, err := runProtectedWriteGuards(projectRoot)
	if err != nil {
		return "", err
	}
	for _, path := range guards.subpaths {
		profile.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", path))
	}
	for _, path := range guards.literals {
		profile.WriteString(fmt.Sprintf("(deny file-write* (literal %q))\n", path))
	}

	// Re-allow write access to session-env dirs that sir hooks need for their
	// own session tracking state. These live inside the protected agent config
	// trees (e.g. ~/.claude/session-env, ~/.gemini/session-env) but must remain
	// writable so hooks can initialize. Seatbelt evaluates rules last-first, so
	// these allow rules override the broader deny-subpath above them.
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		for _, rel := range []string{".claude/session-env", ".gemini/session-env", ".codex/session-env"} {
			p := filepath.Join(homeDir, rel)
			profile.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", p))
		}
	}
	return profile.String(), nil
}
