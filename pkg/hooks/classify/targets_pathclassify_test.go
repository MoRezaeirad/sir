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
