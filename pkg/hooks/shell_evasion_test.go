package hooks

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hookclassify "github.com/somoore/sir/pkg/hooks/classify"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// TestShellEvasionCorpus is the P1.3 regression guard: every obfuscated command
// that hides an egress/exec verb (command substitution, backticks, eval,
// pipe-into-an-interpreter) must NOT be silently allowed, and every benign
// command that merely uses substitution/pipes in ordinary ways must stay
// allowed. It checks the same two mechanisms production uses: the decomposing
// classifier (mapShellCommand) and the opaque-exec escalation gate.
func TestShellEvasionCorpus(t *testing.T) {
	l := lease.DefaultLease()

	malicious := loadEvasionCorpus(t, "malicious.txt")
	benign := loadEvasionCorpus(t, "benign.txt")
	if len(malicious) == 0 || len(benign) == 0 {
		t.Fatal("evasion corpus empty — testdata/shell-evasion/{malicious,benign}.txt missing")
	}

	var leaked []string
	for _, cmd := range malicious {
		if !shellEffectivelyGated(cmd, l) {
			leaked = append(leaked, cmd)
		}
	}
	var overBlocked []string
	for _, cmd := range benign {
		if shellEffectivelyGated(cmd, l) {
			overBlocked = append(overBlocked, cmd)
		}
	}

	t.Logf("shell-evasion corpus: %d malicious, %d benign", len(malicious), len(benign))
	for _, c := range leaked {
		t.Errorf("EVASION SILENTLY ALLOWED: %q", c)
	}
	for _, c := range overBlocked {
		t.Errorf("BENIGN OVER-BLOCKED: %q", c)
	}
}

// shellEffectivelyGated returns true when the command would NOT be silently
// allowed — either the decomposing classifier surfaced a gated (ask/deny) verb,
// or the opaque-exec gate escalates it to ask. Mirrors evaluatePayload.
func shellEffectivelyGated(cmd string, l *lease.Lease) bool {
	intent := mapShellCommand(cmd, l)
	payload := &HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": cmd},
	}
	if _, escalate := opaqueShellEscalation(payload, intent); escalate {
		return true
	}
	return hookclassify.VerbRisk(intent.Verb) > hookclassify.VerbRisk(policy.VerbExecuteDryRun)
}

func loadEvasionCorpus(t *testing.T, name string) []string {
	t.Helper()
	path := filepath.Join(evasionRepoRoot(t), "testdata", "shell-evasion", name)
	f, err := os.Open(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("open corpus %s: %v", path, err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read corpus %s: %v", path, err)
	}
	return out
}

func evasionRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found from %s", dir)
		}
		dir = parent
	}
}
