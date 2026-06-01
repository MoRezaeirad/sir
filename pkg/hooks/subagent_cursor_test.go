package hooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func TestEvaluateSubagentStart_CursorSubagentNameAlias(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	if err := l.Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	state := session.NewState(projectRoot)
	state.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
	if err := state.Save(); err != nil {
		t.Fatalf("save session: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cursor", "subagent-start.json"))
	if err != nil {
		t.Fatalf("read cursor fixture: %v", err)
	}
	out, err := runSubagentStartRawForTest(t, projectRoot, agent.NewCursorAgent(), raw)
	if err != nil {
		t.Fatalf("EvaluateSubagentStart: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("clean cursor subagent should allow silently, got %q", out)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected cursor subagent decision in ledger")
	}
	last := entries[len(entries)-1]
	if last.Target != "reviewer" {
		t.Fatalf("ledger target = %q, want cursor subagent_name reviewer", last.Target)
	}
	if last.Decision != "allow" {
		t.Fatalf("ledger decision = %q, want allow", last.Decision)
	}
}
