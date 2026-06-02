package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestReadCodexHookTrust(t *testing.T) {
	dir := t.TempDir()
	hooksPath := "/home/u/.codex/hooks.json"

	t.Run("all events trusted", func(t *testing.T) {
		cfg := writeFile(t, dir, "all.toml", `[features]
hooks = true

[hooks.state]

[hooks.state."`+hooksPath+`:pre_tool_use:0:0"]
trusted_hash = "sha256:a"

[hooks.state."`+hooksPath+`:permission_request:0:0"]
trusted_hash = "sha256:b"

[hooks.state."`+hooksPath+`:post_tool_use:0:0"]
trusted_hash = "sha256:c"

[hooks.state."`+hooksPath+`:session_start:0:0"]
trusted_hash = "sha256:d"

[hooks.state."`+hooksPath+`:user_prompt_submit:0:0"]
trusted_hash = "sha256:e"

[hooks.state."`+hooksPath+`:stop:0:0"]
trusted_hash = "sha256:f"
`)
		trust, err := readCodexHookTrust(cfg, hooksPath)
		if err != nil {
			t.Fatal(err)
		}
		if !trust.configReadable || !trust.hasFeaturesGate {
			t.Fatalf("expected readable+gate, got %+v", trust)
		}
		for _, ev := range []string{"pre_tool_use", "permission_request", "post_tool_use", "session_start", "user_prompt_submit", "stop"} {
			if !trust.trustedEvents[ev] {
				t.Errorf("event %s not trusted", ev)
			}
		}
	})

	t.Run("no trust entries", func(t *testing.T) {
		cfg := writeFile(t, dir, "none.toml", "[features]\nhooks = true\n")
		trust, err := readCodexHookTrust(cfg, hooksPath)
		if err != nil {
			t.Fatal(err)
		}
		if trust.hasFeaturesGate {
			t.Errorf("expected no gate, got %+v", trust)
		}
		if len(trust.trustedEvents) != 0 {
			t.Errorf("expected zero trusted events, got %v", trust.trustedEvents)
		}
	})

	t.Run("partial trust", func(t *testing.T) {
		cfg := writeFile(t, dir, "partial.toml", `[hooks.state."`+hooksPath+`:pre_tool_use:0:0"]
trusted_hash = "sha256:a"
`)
		trust, err := readCodexHookTrust(cfg, hooksPath)
		if err != nil {
			t.Fatal(err)
		}
		if !trust.hasFeaturesGate {
			t.Fatal("expected gate present")
		}
		if !trust.trustedEvents["pre_tool_use"] {
			t.Error("pre_tool_use should be trusted")
		}
		if trust.trustedEvents["stop"] {
			t.Error("stop should NOT be trusted")
		}
	})

	t.Run("ignores entries for a different hooks.json path", func(t *testing.T) {
		cfg := writeFile(t, dir, "other.toml", `[hooks.state."/some/other/path/hooks.json:pre_tool_use:0:0"]
trusted_hash = "sha256:a"
`)
		trust, err := readCodexHookTrust(cfg, hooksPath)
		if err != nil {
			t.Fatal(err)
		}
		if trust.hasFeaturesGate {
			t.Errorf("entries for a different path must not count, got %+v", trust)
		}
	})

	t.Run("unreadable config", func(t *testing.T) {
		trust, err := readCodexHookTrust(filepath.Join(dir, "absent.toml"), hooksPath)
		if err == nil {
			t.Fatal("expected error for missing file")
		}
		if trust.configReadable {
			t.Error("configReadable should be false")
		}
	})
}
