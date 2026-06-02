package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// TestDoctorSweepAll_ClearsWedgedSessionRegardlessOfCwd reproduces the
// deny-all-per-session bug: a session wedged in project A is NOT cleared by a
// plain `sir doctor` run from project B (different sha256(cwd) → different
// session.json). It then verifies the cross-project sweep behind
// `sir doctor --all` clears it regardless of the caller's cwd.
func TestDoctorSweepAll_ClearsWedgedSessionRegardlessOfCwd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// RebaselineAllProjects uses os.UserHomeDir(); ensure no override leaks in.
	t.Setenv(session.StateHomeEnvVar, "")

	wedged := filepath.Join(home, "projWedged")
	if err := os.MkdirAll(wedged, 0o755); err != nil {
		t.Fatal(err)
	}

	// Real posture file the session tracks. We seed the session with a STALE
	// hash for it so CheckPostureIntegrity would fail (the re-trip mechanism),
	// not just an empty posture set.
	postureFile := filepath.Join(wedged, "tracked.json")
	if err := os.WriteFile(postureFile, []byte(`{"current":true}`), 0o644); err != nil {
		t.Fatal(err)
	}

	st := session.NewState(wedged)
	st.PostureHashes = map[string]string{"tracked.json": "sha256:stale-does-not-match"}
	st.SetDenyAll("posture file tampered: tracked.json")
	if !st.DenyAll {
		t.Fatal("precondition: deny-all should be set")
	}
	if err := st.Save(); err != nil {
		t.Fatalf("save wedged session: %v", err)
	}
	// Lease declares the posture file so the sweep rehashes it.
	l := &lease.Lease{PostureFiles: []string{"tracked.json"}}
	if err := l.Save(filepath.Join(session.StateDir(wedged), "lease.json")); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	// Sanity: before the sweep, integrity FAILS (stale hash) and deny-all set.
	pre, err := session.Load(wedged)
	if err != nil {
		t.Fatalf("reload wedged: %v", err)
	}
	if !pre.DenyAll {
		t.Fatal("wedged session should still be deny-all before sweep")
	}
	if drift := hooks.CheckPostureIntegrity(wedged, pre, l); len(drift) == 0 {
		t.Fatal("precondition: posture integrity should FAIL before sweep (stale hash)")
	}

	// The sweep behind `sir doctor --all` — note we never cd into `wedged`.
	summary, err := hooks.RebaselineAllProjects()
	if err != nil {
		t.Fatalf("RebaselineAllProjects: %v", err)
	}
	if summary.DenyAllCleared < 1 {
		t.Fatalf("expected at least 1 deny-all cleared, got %d (skipped %d)", summary.DenyAllCleared, len(summary.Skipped))
	}

	post, err := session.Load(wedged)
	if err != nil {
		t.Fatalf("reload after sweep: %v", err)
	}
	// Deny-all cleared AND the baseline refreshed, so a subsequent integrity
	// check passes — i.e. the session will NOT immediately re-trip. This is the
	// property that distinguishes a real fix from just flipping the bool.
	if post.DenyAll {
		t.Errorf("deny-all should be cleared by the cross-project sweep, still set")
	}
	if drift := hooks.CheckPostureIntegrity(wedged, post, l); len(drift) != 0 {
		t.Errorf("posture integrity should PASS after sweep (baseline refreshed), got drift: %v", drift)
	}
}
