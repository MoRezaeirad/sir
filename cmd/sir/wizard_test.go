package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkGitRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git in %s: %v", dir, err)
	}
}

// TestFindGitRepos_FindsReposAndDoesNotDescend verifies the walk discovers
// each repo root and does not recurse into a repo (a nested .git under an
// already-found repo is part of that repo, not a separate result).
func TestFindGitRepos_FindsReposAndDoesNotDescend(t *testing.T) {
	root := t.TempDir()
	mkGitRepo(t, filepath.Join(root, "alpha"))
	mkGitRepo(t, filepath.Join(root, "nested", "beta"))
	// A submodule-like nested repo inside alpha must NOT be returned separately.
	mkGitRepo(t, filepath.Join(root, "alpha", "vendor", "sub"))
	// A plain directory with no .git is ignored.
	if err := os.MkdirAll(filepath.Join(root, "not-a-repo"), 0o755); err != nil {
		t.Fatal(err)
	}

	repos, _ := findGitRepos(root)

	got := map[string]bool{}
	for _, r := range repos {
		got[r] = true
	}
	if !got[filepath.Join(root, "alpha")] {
		t.Errorf("expected to find alpha repo; got %v", repos)
	}
	if !got[filepath.Join(root, "nested", "beta")] {
		t.Errorf("expected to find nested/beta repo; got %v", repos)
	}
	if got[filepath.Join(root, "alpha", "vendor", "sub")] {
		t.Errorf("must not descend into alpha to find vendor/sub; got %v", repos)
	}
	if got[filepath.Join(root, "not-a-repo")] {
		t.Errorf("non-repo dir should not be reported; got %v", repos)
	}
}

// TestFindGitRepos_RespectsDepthCap verifies a repo buried below the scan-depth
// cap is not discovered, and the truncation is reported in skipped (no silent
// coverage gap — CLAUDE.md honesty about what was not covered).
func TestFindGitRepos_RespectsDepthCap(t *testing.T) {
	root := t.TempDir()
	deep := root
	for i := 0; i < maxWizardScanDepth+2; i++ {
		deep = filepath.Join(deep, "d")
	}
	mkGitRepo(t, deep)

	repos, skipped := findGitRepos(root)
	for _, r := range repos {
		if r == deep {
			t.Fatalf("repo below depth cap should not be found: %s", deep)
		}
	}
	reported := false
	for _, s := range skipped {
		if strings.Contains(s, "scan depth") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("expected the depth-capped directory to be reported in skipped, got %v", skipped)
	}
}

// TestFindGitRepos_EmptyRootReturnsNothing keeps the no-repos path quiet and
// non-erroring.
func TestFindGitRepos_EmptyRootReturnsNothing(t *testing.T) {
	root := t.TempDir()
	repos, _ := findGitRepos(root)
	if len(repos) != 0 {
		t.Errorf("expected no repos under an empty root, got %v", repos)
	}
}

func TestExpandHome(t *testing.T) {
	home := "/Users/example"
	cases := map[string]string{
		"~":            home,
		"~/code":       filepath.Join(home, "code"),
		"/abs/path":    "/abs/path",
		"relative/dir": "relative/dir",
	}
	for in, want := range cases {
		if got := expandHome(in, home); got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}
