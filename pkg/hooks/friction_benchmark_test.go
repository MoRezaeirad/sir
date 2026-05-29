package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// TestFrictionBenchmark_NormalCodingIsSilent (FRICTION-1) is the quantified
// "invisible on normal coding" SLO: a realistic routine session — reads, edits,
// tests, builds, git status/commit/push-to-origin, greps, loopback curls —
// must produce ZERO prompts and ZERO blocks on the default (personal) profile.
// It is the aggregate counterpart to BUDGET-1 (which pins individual verdicts):
// if any everyday command starts prompting, the friction budget is blown and
// this fails. The corpus is deliberately broad so regressions in classification
// or policy surface here rather than in the field.
func TestFrictionBenchmark_NormalCodingIsSilent(t *testing.T) {
	type step struct {
		tool  string
		input map[string]interface{}
	}
	session := []step{
		{"Read", map[string]interface{}{"file_path": "cmd/sir/main.go"}},
		{"Read", map[string]interface{}{"file_path": "pkg/hooks/evaluate.go"}},
		{"Grep", map[string]interface{}{"pattern": "func Evaluate", "path": "."}},
		{"Edit", map[string]interface{}{"file_path": "pkg/hooks/evaluate.go", "old_string": "a", "new_string": "b"}},
		{"Write", map[string]interface{}{"file_path": "pkg/hooks/new_file.go", "content": "package hooks\n"}},
		{"Bash", map[string]interface{}{"command": "ls -la pkg/"}},
		{"Bash", map[string]interface{}{"command": "grep -rn TODO pkg/"}},
		{"Bash", map[string]interface{}{"command": "go build ./..."}},
		{"Bash", map[string]interface{}{"command": "go test ./pkg/hooks/"}},
		{"Bash", map[string]interface{}{"command": "go vet ./..."}},
		{"Bash", map[string]interface{}{"command": "git status"}},
		{"Bash", map[string]interface{}{"command": "git diff"}},
		{"Bash", map[string]interface{}{"command": "git add -A"}},
		{"Bash", map[string]interface{}{"command": "git commit -m 'wip'"}},
		{"Bash", map[string]interface{}{"command": "git push origin main"}},
		{"Bash", map[string]interface{}{"command": "curl localhost:8080/healthz"}},
		{"Bash", map[string]interface{}{"command": "cat go.mod"}},
	}

	projectRoot := t.TempDir()
	state := newTestSession(t, projectRoot)
	l := lease.DefaultLease()

	var prompts, blocks int
	for _, s := range session {
		s.input["__cwd"] = projectRoot // harmless extra key; CWD set on payload below
		resp, err := evaluatePayload(&HookPayload{ToolName: s.tool, ToolInput: s.input, CWD: projectRoot}, l, state, projectRoot)
		if err != nil {
			t.Fatalf("%s %v: %v", s.tool, s.input, err)
		}
		switch resp.Decision {
		case policy.VerdictAsk:
			prompts++
			t.Errorf("friction budget blown: %s %v prompted (reason=%s)", s.tool, s.input["command"], resp.Reason)
		case policy.VerdictDeny:
			blocks++
			t.Errorf("friction budget blown: %s %v blocked (reason=%s)", s.tool, s.input["command"], resp.Reason)
		}
	}
	if prompts != 0 || blocks != 0 {
		t.Fatalf("normal-coding SLO: want 0 prompts / 0 blocks, got %d prompts / %d blocks across %d steps", prompts, blocks, len(session))
	}
}
