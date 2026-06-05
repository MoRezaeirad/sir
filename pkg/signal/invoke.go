package signal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/sdk"
)

const signalProviderTimeout = 300 * time.Millisecond

// invokeSignalProvider spawns the provider entrypoint, sends the raw event
// JSON on stdin, and reads one or more sir.signal.v0 objects from stdout.
// Times out after 300ms — signal providers must be fast (they are on the
// hot path before every evaluation). Errors degrade enforceability but never
// block evaluation.
func invokeSignalProvider(entrypoint string, eventJSON []byte) ([]sdk.Signal, error) {
	ctx, cancel := context.WithTimeout(context.Background(), signalProviderTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, entrypoint)
	cmd.Stdin = strings.NewReader(string(eventJSON) + "\n")
	cmd.Env = append(os.Environ(), sdkPythonPath(entrypoint))

	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("timed out after %s", signalProviderTimeout)
		}
		return nil, fmt.Errorf("exit: %w", err)
	}

	return parseSignalOutput(out)
}

// parseSignalOutput accepts either a single sir.signal.v0 object or an array.
func parseSignalOutput(out []byte) ([]sdk.Signal, error) {
	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil, nil
	}
	if strings.HasPrefix(line, "[") {
		var signals []sdk.Signal
		if err := json.Unmarshal([]byte(line), &signals); err != nil {
			return nil, fmt.Errorf("parse signal array: %w", err)
		}
		return signals, nil
	}
	var sig sdk.Signal
	if err := json.Unmarshal([]byte(line), &sig); err != nil {
		return nil, fmt.Errorf("parse signal: %w", err)
	}
	if sig.SchemaVersion != sdk.SchemaSignalV0 {
		return nil, fmt.Errorf("wrong schema_version: %s", sig.SchemaVersion)
	}
	return []sdk.Signal{sig}, nil
}

// sdkPythonPath delegates to the shared resolver so signal providers get the
// same absolute, vendored-beside-entrypoint PYTHONPATH as policy providers. See
// sdk.SDKPythonPath.
func sdkPythonPath(entrypoint string) string {
	return sdk.SDKPythonPath(entrypoint)
}
