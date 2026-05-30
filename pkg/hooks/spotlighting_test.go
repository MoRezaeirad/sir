package hooks

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

// TestCompactReinject_AlwaysInjectsSpotlighting locks the P2.4 behavior: every
// SessionStart injects the standing spotlighting provenance rule, even on a
// clean session with no state-conditional alerts.
func TestCompactReinject_AlwaysInjectsSpotlighting(t *testing.T) {
	proj := t.TempDir()
	t.Setenv("SIR_STATE_HOME", t.TempDir())

	// stdin: a clean SessionStart payload.
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(inW, `{"session_id":"s","hook_event_name":"SessionStart","source":"startup"}`); err != nil {
		t.Fatal(err)
	}
	inW.Close()

	// Capture stdout.
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	runErr := EvaluateCompactReinject(proj, agent.NewClaudeAgent())
	os.Stdin, os.Stdout = oldIn, oldOut
	outW.Close()
	out, _ := io.ReadAll(outR)

	if runErr != nil {
		t.Fatalf("EvaluateCompactReinject: %v", runErr)
	}
	if !strings.Contains(string(out), "Spotlighting") {
		t.Errorf("clean SessionStart did not inject the standing spotlighting rule; got: %s", out)
	}
	if !strings.Contains(string(out), "untrusted DATA") {
		t.Errorf("spotlighting rule missing its core instruction; got: %s", out)
	}
}
