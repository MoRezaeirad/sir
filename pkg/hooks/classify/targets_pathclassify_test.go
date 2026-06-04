package classify

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// TestMatchPath_WindowsBackslashPaths confirms that credential and sensitive
// paths expressed with Windows backslash separators are correctly detected.
// This guards against a security regression where normalizePath produces
// backslash paths (via filepath.Clean on Windows) that the '/' based pattern
// matching in matchPath would silently miss.
func TestMatchPath_WindowsBackslashPaths(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		pattern string
		want    bool
	}{
		{
			name:    "backslash aws credentials",
			path:    `C:\Users\alice\.aws\credentials`,
			pattern: "**/.aws/credentials",
			want:    true,
		},
		{
			name:    "backslash dot env",
			path:    `C:\projects\myapp\.env`,
			pattern: "**/.env",
			want:    true,
		},
		{
			name:    "backslash nested ssh key",
			path:    `C:\Users\alice\.ssh\id_rsa`,
			pattern: "**/.ssh/id_rsa",
			want:    true,
		},
		{
			name:    "forward slash windows path",
			path:    `C:/Users/alice/.aws/credentials`,
			pattern: "**/.aws/credentials",
			want:    true,
		},
		{
			name:    "non-sensitive path not matched",
			path:    `C:\Users\alice\Documents\notes.txt`,
			pattern: "**/.env",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchPath(tt.path, tt.pattern)
			if got != tt.want {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestIsSensitivePath_WindowsCredentialPaths verifies that credential files
// on Windows-style paths are identified as sensitive by the full pipeline
// (normalizePath → matchPath).
func TestIsSensitivePath_WindowsCredentialPaths(t *testing.T) {
	l := &lease.Lease{
		SensitivePaths: []string{
			"**/.aws/credentials",
			"**/.env",
			"**/.ssh/id_rsa",
		},
	}

	sensitive := []string{
		`C:\Users\alice\.aws\credentials`,
		`C:/Users/alice/.aws/credentials`,
		filepath.Join("C:", "Users", "alice", ".env"),
	}
	for _, p := range sensitive {
		// Normalize as the production code does: lowercase and clean.
		clean := strings.ToLower(filepath.Clean(p))
		if !IsSensitivePath(clean, l) {
			t.Errorf("IsSensitivePath(%q) = false, want true (Windows credential path missed)", clean)
		}
	}
}

// TestMatchPath_RelativeDirGlobPrefix guards the fix for project-relative
// directory-glob exclusions (e.g. "testdata/**") matching a canonicalized
// ABSOLUTE path. Before the fix matchPath required the "testdata/" prefix at
// the path root, so an absolute path like "/abs/proj/testdata/foo.pem" never
// matched and the exclusion was silently bypassed.
func TestMatchPath_RelativeDirGlobPrefix(t *testing.T) {
	cases := []struct {
		path, pattern string
		want          bool
	}{
		{"/abs/proj/testdata/foo.pem", "testdata/**", true},
		{"/abs/proj/fixtures/key.pem", "fixtures/**", true},
		{"/abs/proj/sub/testdata/x", "testdata/**", true}, // any boundary
		{"/abs/proj/mytestdata/foo.pem", "testdata/**", false}, // segment-anchored
		{"/abs/proj/src/main.go", "testdata/**", false},
		{"/etc/log/app.log", "/etc/**", true},  // absolute prefix preserved
		{"/etclog/app.log", "/etc/**", false},  // absolute prefix anchored
	}
	for _, tc := range cases {
		if got := matchPath(tc.path, tc.pattern); got != tc.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tc.path, tc.pattern, got, tc.want)
		}
	}
}

// TestIsSensitivePath_DirGlobExclusionBeatsBroadPattern confirms a directory
// exclusion overrides a broad SensitivePaths match (*.pem) for an absolute path.
func TestIsSensitivePath_DirGlobExclusionBeatsBroadPattern(t *testing.T) {
	l := &lease.Lease{
		SensitivePaths:          []string{"*.pem"},
		SensitivePathExclusions: []string{"testdata/**"},
	}
	if IsSensitivePath("/abs/proj/testdata/foo.pem", l) {
		t.Error("testdata/foo.pem should be excluded despite matching *.pem")
	}
	if !IsSensitivePath("/abs/proj/secrets/foo.pem", l) {
		t.Error("secrets/foo.pem should remain sensitive (*.pem, not excluded)")
	}
}
