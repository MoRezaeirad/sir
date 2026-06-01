package hooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

func TestSirStateTamper(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	sirLedger := filepath.Join(home, ".sir", "projects", "abc123", "ledger.jsonl")
	sirRoot := filepath.Join(home, ".sir")

	cases := []struct {
		name     string
		intent   Intent
		wantDeny bool
	}{
		{"write to ~/.sir ledger denies", Intent{Verb: policy.VerbStageWrite, Target: sirLedger}, true},
		{"write to ~/.sir root denies", Intent{Verb: policy.VerbStageWrite, Target: sirRoot}, true},
		{"apply_patch list incl ~/.sir denies", Intent{Verb: policy.VerbStageWrite, Target: "src/main.go, " + sirLedger}, true},
		{"write to sir.yaml denies", Intent{Verb: policy.VerbStageWrite, Target: "config/sir.yaml"}, true},
		{"write to sir-posture denies", Intent{Verb: policy.VerbStageWrite, Target: ".sir-posture.json"}, true},
		{"delete_posture into ~/.sir denies", Intent{Verb: policy.VerbDeletePosture, Target: sirLedger}, true},
		// Must NOT fire:
		{"normal source write allowed", Intent{Verb: policy.VerbStageWrite, Target: "src/main.go"}, false},
		{"reading ~/.sir is not a write", Intent{Verb: policy.VerbReadRef, Target: sirLedger}, false},
		{"a file merely named with sir is not state", Intent{Verb: policy.VerbStageWrite, Target: "docs/elixir.md"}, false},
		{"empty target", Intent{Verb: policy.VerbStageWrite, Target: ""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, deny := sirStateTamper(tc.intent, t.TempDir())
			if deny != tc.wantDeny {
				t.Errorf("sirStateTamper(%+v) deny=%v, want %v", tc.intent, deny, tc.wantDeny)
			}
		})
	}
}

func bashPayload(cmd string) *HookPayload {
	return &HookPayload{ToolName: "Bash", ToolInput: map[string]interface{}{"command": cmd}}
}

// TestGitConfigSensitiveAsk_ProductionVerb pins the floor against the verb the
// PRODUCTION path actually assigns (via MapToolToIntent), not a hardcoded one.
// gitConfigSensitiveAsk self-guards on verb risk; if `git config` ever started
// mapping to a verb riskier than execute_dry_run, the self-guard would silently
// skip the gate and the floor would go dead. This test catches that regression.
func TestGitConfigSensitiveAsk_ProductionVerb(t *testing.T) {
	l := lease.DefaultLease()
	for _, cmd := range []string{
		"git config credential.helper store",
		"git config core.hooksPath .husky",
		"git -c credential.helper=evil status",
	} {
		payload := bashPayload(cmd)
		intent := MapToolToIntent(payload.ToolName, payload.ToolInput, l)
		if _, ask := gitConfigSensitiveAsk(payload, intent); !ask {
			t.Errorf("production path: %q (mapped verb %q) must ask — the floor is dead if it does not", cmd, intent.Verb)
		}
	}
}

func TestGitConfigSensitiveAsk(t *testing.T) {
	lowRisk := Intent{Verb: policy.VerbExecuteDryRun}

	cases := []struct {
		name    string
		payload *HookPayload
		intent  Intent
		wantAsk bool
	}{
		{"set credential.helper asks", bashPayload("git config credential.helper store"), lowRisk, true},
		{"global credential.helper asks", bashPayload("git config --global credential.helper '!evil.sh'"), lowRisk, true},
		{"set core.hooksPath asks (husky shape)", bashPayload("git config core.hooksPath .husky"), lowRisk, true},
		{"inline -c credential.helper asks", bashPayload("git -c credential.helper=evil status"), lowRisk, true},
		{"replace-all credential.helper asks", bashPayload("git config --replace-all credential.helper x"), lowRisk, true},
		// Must NOT fire:
		{"reading credential.helper is fine", bashPayload("git config --get credential.helper"), lowRisk, false},
		{"listing config is fine", bashPayload("git config --list"), lowRisk, false},
		{"benign config is fine", bashPayload("git config user.email a@b.com"), lowRisk, false},
		{"non-git command", bashPayload("echo credential.helper"), lowRisk, false},
		{"non-bash tool", &HookPayload{ToolName: "Write", ToolInput: map[string]interface{}{"command": "git config credential.helper store"}}, lowRisk, false},
		// High-risk verb self-guard: a push with inline helper is handled by the push gate.
		{"push with inline helper deferred to push gate", bashPayload("git -c credential.helper=evil push origin"), Intent{Verb: policy.VerbPushRemote}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, ask := gitConfigSensitiveAsk(tc.payload, tc.intent)
			if ask != tc.wantAsk {
				t.Errorf("gitConfigSensitiveAsk(%q) ask=%v, want %v", tc.payload.ToolInput["command"], ask, tc.wantAsk)
			}
		})
	}
}
