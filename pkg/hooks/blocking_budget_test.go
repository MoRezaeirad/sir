package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// TestBlockingBudget (BUDGET-1) is the golden regression harness for sir's
// friction surface: it pins the wire verdict of everyday developer commands on
// a fresh, clean session under the default lease, evaluated through the real
// oracle. Two reasons it exists:
//
//  1. The SILENT-ALLOW rows are the "invisible on normal coding" promise. They
//     must never silently regress to ask/deny — that is friction creeping back
//     in. A change that makes routine work prompt fails here.
//  2. The ASK/DENY rows are the documented friction points and the explicit
//     targets of the staged downgrades (NET-1/NET-2, NPX-1, REMOTE-1, …). When
//     a downgrade lands, the author flips exactly one row's `want` here — making
//     "we now block less" a reviewed, visible, single-line diff rather than an
//     invisible behavior change.
//
// Verdicts here are profile-independent (clean session, default lease); raw
// secret-read handling is profile-dependent and is covered by the secret-leak
// matrix (SECRET-1), not here.
func TestBlockingBudget(t *testing.T) {
	type row struct {
		name  string
		tool  string
		input map[string]interface{}
		want  policy.Verdict
		note  string // future-change marker for the staged downgrades
	}

	rows := []row{
		// --- SILENT ALLOW: the quiet path. These must never regress. ---
		{"read normal file", "Read", map[string]interface{}{"file_path": "main.go"}, policy.VerdictAllow, ""},
		{"edit normal file", "Edit", map[string]interface{}{"file_path": "main.go", "old_string": "a", "new_string": "b"}, policy.VerdictAllow, ""},
		{"run tests", "Bash", map[string]interface{}{"command": "go test ./..."}, policy.VerdictAllow, ""},
		{"git commit", "Bash", map[string]interface{}{"command": "git commit -m wip"}, policy.VerdictAllow, ""},
		{"list files", "Bash", map[string]interface{}{"command": "ls -la"}, policy.VerdictAllow, ""},
		{"grep code", "Bash", map[string]interface{}{"command": "grep -r foo ."}, policy.VerdictAllow, ""},
		{"curl loopback", "Bash", map[string]interface{}{"command": "curl localhost:3000/health"}, policy.VerdictAllow, ""},
		{"git push origin", "Bash", map[string]interface{}{"command": "git push origin main"}, policy.VerdictAllow, ""},

		// --- ASK: documented friction; staged-downgrade targets. ---
		{"push to unapproved remote", "Bash", map[string]interface{}{"command": "git push fork main"}, policy.VerdictAsk, "REMOTE-1: repeat to same remote becomes silent after first approval"},
		{"npx ephemeral", "Bash", map[string]interface{}{"command": "npx cowsay hi"}, policy.VerdictAsk, "NPX-1: same package reused in-session stops re-asking"},
		{"write posture file", "Write", map[string]interface{}{"file_path": "CLAUDE.md", "content": "x"}, policy.VerdictAsk, "FLOOR: posture writes always ask (never downgrade)"},

		// --- ASK: clean-session egress. NET-1/NET-2 flipped these from a hard
		// deny to an approval prompt for personal/team (the scanner was hardened
		// first, SCAN-1). strict/managed still forbid them -> deny. A secret
		// session still denies (the floor, asserted in TestObserve1/secret tests).
		{"curl external clean", "Bash", map[string]interface{}{"command": "curl https://api.example.com/x"}, policy.VerdictAsk, "NET-1: clean-session egress is now ask (personal/team); strict/managed still deny"},
		{"dns lookup clean", "Bash", map[string]interface{}{"command": "dig example.com"}, policy.VerdictAsk, "NET-2: clean-session dns is now ask (personal/team); strict/managed still deny"},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			projectRoot := t.TempDir()
			state := newTestSession(t, projectRoot)
			l := lease.DefaultLease()
			payload := &HookPayload{ToolName: r.tool, ToolInput: r.input, CWD: projectRoot}
			resp, err := evaluatePayload(payload, l, state, projectRoot)
			if err != nil {
				t.Fatalf("evaluatePayload: %v", err)
			}
			if resp.Decision != r.want {
				t.Errorf("blocking-budget drift: %q want %s, got %s (reason=%s)%s",
					r.name, r.want, resp.Decision, resp.Reason, noteSuffix(r.note))
			}
		})
	}
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return "\n  note: " + note
}
