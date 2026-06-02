package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCodexConfig writes a config.toml to a temp dir and returns its path.
func writeCodexConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestCodexHooksFlagStatus(t *testing.T) {
	cases := []struct {
		name string
		body string
		want codexFlagStatus
	}{
		{
			name: "canonical enabled",
			body: "[features]\nhooks = true\n",
			want: codexFlagAlreadyEnabled,
		},
		{
			name: "legacy only -> migration offered",
			body: "[features]\ncodex_hooks = true\n",
			want: codexFlagLegacyEnabled,
		},
		{
			name: "canonical wins over stale legacy",
			body: "[features]\ncodex_hooks = true\nhooks = true\n",
			want: codexFlagAlreadyEnabled,
		},
		{
			name: "features section without hooks key",
			body: "[features]\napps = true\n",
			want: codexFlagNeedsEnable,
		},
		{
			name: "no features section",
			body: "model = \"o3\"\n",
			want: codexFlagNeedsEnable,
		},
		{
			name: "legacy disabled is not enabled",
			body: "[features]\ncodex_hooks = false\n",
			want: codexFlagNeedsEnable,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCodexConfig(t, tc.body)
			got, _, err := codexHooksFlagStatus(path)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCodexHooksFlagStatus_MissingFile(t *testing.T) {
	got, _, err := codexHooksFlagStatus(filepath.Join(t.TempDir(), "absent.toml"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != codexFlagMissingFile {
		t.Fatalf("status = %d, want codexFlagMissingFile", got)
	}
}

func TestEnsureCodexFeatureFlag_AutoMigratesLegacyOnSkipPrompt(t *testing.T) {
	path := writeCodexConfig(t, "model = \"o3\"\n\n[features]\ncodex_hooks = true\n")
	// skipPrompt=true mirrors a non-interactive `--yes` install: migration runs
	// automatically without a confirmation prompt.
	ensureCodexFeatureFlag(path, true)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got := string(data)
	if strings.Contains(got, "codex_hooks") {
		t.Fatalf("legacy key not migrated:\n%s", got)
	}
	if !strings.Contains(got, "hooks = true") {
		t.Fatalf("canonical key missing after migration:\n%s", got)
	}
	if !strings.Contains(got, "model = \"o3\"") {
		t.Fatalf("unrelated content lost:\n%s", got)
	}
}

func TestEnsureCodexFeatureFlag_CanonicalIsNoOp(t *testing.T) {
	body := "[features]\nhooks = true\n"
	path := writeCodexConfig(t, body)
	ensureCodexFeatureFlag(path, true)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != body {
		t.Fatalf("canonical config mutated:\nwant %q\n got %q", body, string(data))
	}
}

func TestMigrateCodexLegacyHooksFlag(t *testing.T) {
	t.Run("rewrites legacy to canonical preserving order", func(t *testing.T) {
		in := []string{"model = \"o3\"", "", "[features]", "codex_hooks = true", "apps = true"}
		out := migrateCodexLegacyHooksFlag(in)
		joined := strings.Join(out, "\n")
		if strings.Contains(joined, "codex_hooks") {
			t.Fatalf("legacy key still present:\n%s", joined)
		}
		if !strings.Contains(joined, "hooks = true") {
			t.Fatalf("canonical key missing:\n%s", joined)
		}
		if !strings.Contains(joined, "apps = true") || !strings.Contains(joined, "model = \"o3\"") {
			t.Fatalf("unrelated content dropped:\n%s", joined)
		}
	})

	t.Run("preserves indentation", func(t *testing.T) {
		in := []string{"[features]", "  codex_hooks = true"}
		out := migrateCodexLegacyHooksFlag(in)
		if out[1] != "  hooks = true" {
			t.Fatalf("indentation not preserved: %q", out[1])
		}
	})

	t.Run("drops legacy when canonical already present", func(t *testing.T) {
		in := []string{"[features]", "codex_hooks = true", "hooks = true"}
		out := migrateCodexLegacyHooksFlag(in)
		joined := strings.Join(out, "\n")
		if strings.Contains(joined, "codex_hooks") {
			t.Fatalf("legacy key not dropped:\n%s", joined)
		}
		if strings.Count(joined, "hooks = true") != 1 {
			t.Fatalf("expected exactly one canonical hooks line:\n%s", joined)
		}
	})

	t.Run("no features section is a no-op", func(t *testing.T) {
		in := []string{"model = \"o3\""}
		out := migrateCodexLegacyHooksFlag(in)
		if strings.Join(out, "\n") != "model = \"o3\"" {
			t.Fatalf("unexpected mutation: %v", out)
		}
	})
}

// TestMigrateCodexLegacyHooksFlag_DisabledCanonicalIsEnabled covers the P2 bug:
// when both `codex_hooks = true` and `hooks = false` exist, migration must NOT
// silently disable hooks by dropping the legacy line and leaving hooks=false —
// it must end with hooks=true.
func TestMigrateCodexLegacyHooksFlag_DisabledCanonicalIsEnabled(t *testing.T) {
	in := []string{"[features]", "codex_hooks = true", "hooks = false"}
	out := migrateCodexLegacyHooksFlag(in)
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "codex_hooks") {
		t.Fatalf("legacy key should be dropped:\n%s", joined)
	}
	if strings.Contains(joined, "hooks = false") {
		t.Fatalf("hooks must NOT be left disabled:\n%s", joined)
	}
	if !strings.Contains(joined, "hooks = true") {
		t.Fatalf("hooks must be enabled after migration:\n%s", joined)
	}
	if strings.Count(joined, "hooks = true") != 1 {
		t.Fatalf("expected exactly one hooks=true line:\n%s", joined)
	}
}

// TestReadCodexHookTrust_HeaderWithoutHashIsUntrusted covers the P2 bug: a
// [hooks.state] header with no trusted_hash (or an empty one) must read as NOT
// trusted, so the diagnostic does not falsely report trust.
func TestReadCodexHookTrust_HeaderWithoutHashIsUntrusted(t *testing.T) {
	dir := t.TempDir()
	hp := "/h/.codex/hooks.json"
	cfg := writeCodexConfig(t, `[hooks.state]

[hooks.state."`+hp+`:pre_tool_use:0:0"]
# no trusted_hash here

[hooks.state."`+hp+`:stop:0:0"]
trusted_hash = ""

[hooks.state."`+hp+`:session_start:0:0"]
trusted_hash = "sha256:real"
`)
	_ = dir
	trust, err := readCodexHookTrust(cfg, hp)
	if err != nil {
		t.Fatal(err)
	}
	if !trust.hasFeaturesGate {
		t.Fatal("expected hasFeaturesGate (headers present)")
	}
	if trust.trustedEvents["pre_tool_use"] {
		t.Error("pre_tool_use has no trusted_hash → must be untrusted")
	}
	if trust.trustedEvents["stop"] {
		t.Error("stop has empty trusted_hash → must be untrusted")
	}
	if !trust.trustedEvents["session_start"] {
		t.Error("session_start has a real trusted_hash → must be trusted")
	}
}
