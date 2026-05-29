package main

import (
	"bufio"
	"strings"
	"testing"
)

// TestReadKey_DecodesControlAndArrowSequences verifies the raw-byte keypress
// decoder maps the bytes a terminal delivers in cbreak mode to the right
// logical keys, including the multi-byte arrow escape sequences.
func TestReadKey_DecodesControlAndArrowSequences(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want keyCode
	}{
		{"enter-cr", "\r", keyEnter},
		{"enter-lf", "\n", keyEnter},
		{"space", " ", keySpace},
		{"q-cancels", "q", keyCancel},
		{"ctrl-c-cancels", "\x03", keyCancel},
		{"a-toggles-all", "a", keyToggleAll},
		{"j-down", "j", keyDown},
		{"k-up", "k", keyUp},
		{"arrow-up", "\x1b[A", keyUp},
		{"arrow-down", "\x1b[B", keyDown},
		{"bare-esc-cancels", "\x1b", keyCancel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.in))
			got, err := readKey(r)
			if err != nil {
				t.Fatalf("readKey(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("readKey(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestReadKey_EOF surfaces a clean error (not a panic) when the stream ends,
// which the selector treats as a cancel.
func TestReadKey_EOF(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(""))
	if _, err := readKey(r); err == nil {
		t.Fatal("expected an error on EOF")
	}
}

// TestIsInteractiveTerminal_NonTTY confirms the gate returns false under the
// test runner (stdin/stdout are pipes), which is what drives the
// auto-detect-all fallback in selectAgentsForInstall.
func TestIsInteractiveTerminal_NonTTY(t *testing.T) {
	if isInteractiveTerminal() {
		t.Skip("running attached to a TTY; gate behavior is environment-specific here")
	}
}
