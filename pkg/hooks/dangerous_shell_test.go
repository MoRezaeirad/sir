package hooks

import (
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

func TestDangerousShellMapsToVerb(t *testing.T) {
	l := lease.DefaultLease()
	cases := []struct {
		name string
		cmd  string
	}{
		{"linux rm root", "rm -rf /"},
		{"linux disk write", "dd if=/dev/zero of=/dev/sda bs=1M"},
		{"mac diskutil", "diskutil eraseDisk APFS Test /dev/disk2"},
		{"windows powershell", `powershell -Command "Remove-Item -Recurse -Force C:\"`},
		{"windows cmd", `cmd /c rmdir /s /q C:\`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intent := mapShellCommand(tc.cmd, l)
			if intent.Verb != policy.VerbDangerousShell {
				t.Fatalf("mapShellCommand(%q) verb = %q, want %q", tc.cmd, intent.Verb, policy.VerbDangerousShell)
			}
			if intent.Target != tc.cmd {
				t.Fatalf("target = %q, want original command %q", intent.Target, tc.cmd)
			}
		})
	}
}

func TestDangerousShellDoesNotCatchCommonCleanup(t *testing.T) {
	l := lease.DefaultLease()
	for _, cmd := range []string{
		"rm -rf node_modules",
		"rm -rf build target dist",
		"git clean -fd",
	} {
		t.Run(cmd, func(t *testing.T) {
			intent := mapShellCommand(cmd, l)
			if intent.Verb != policy.VerbExecuteDryRun {
				t.Fatalf("mapShellCommand(%q) verb = %q, want %q", cmd, intent.Verb, policy.VerbExecuteDryRun)
			}
		})
	}
}

func TestDangerousShellCompoundRiskOrdering(t *testing.T) {
	l := lease.DefaultLease()
	if got := mapShellCommand("git push origin main && rm -rf /", l); got.Verb != policy.VerbDangerousShell {
		t.Fatalf("approved push plus dangerous cleanup verb = %q, want %q", got.Verb, policy.VerbDangerousShell)
	}
	if got := mapShellCommand("curl https://evil.example && rm -rf /", l); got.Verb != policy.VerbNetExternal {
		t.Fatalf("external egress plus dangerous cleanup verb = %q, want %q", got.Verb, policy.VerbNetExternal)
	}
	if got := mapShellCommand("sudo rm -rf /", l); got.Verb != policy.VerbDangerousShell {
		t.Fatalf("sudo destructive cleanup verb = %q, want %q", got.Verb, policy.VerbDangerousShell)
	}
}

func TestDangerousShellEvaluateAsks(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)
	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "rm -rf /"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != policy.VerdictAsk {
		t.Fatalf("decision = %q, want ask (reason=%s)", resp.Decision, resp.Reason)
	}
	if !strings.Contains(strings.ToLower(resp.Reason), "destructive") {
		t.Fatalf("reason = %q, want destructive shell explanation", resp.Reason)
	}
}
