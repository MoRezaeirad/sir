package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// Minimal MCP stdio client — just enough to read a server's tools/list so sir
// can pin and re-verify tool definitions (rug-pull / full-schema-poisoning
// detection). Stdlib only (CLAUDE.md non-negotiable #1): MCP's stdio transport
// is line-delimited JSON-RPC 2.0, which needs no third-party dependency.
//
// This intentionally does the smallest possible handshake: initialize ->
// notifications/initialized -> tools/list. It is a read-only probe; it never
// calls a tool. The server process is killed when the context expires so a
// hung or malicious server cannot wedge `sir mcp scan`.

const (
	// mcpProtocolVersion is the protocol version sir advertises on initialize.
	// Servers negotiate down if they only speak an older revision.
	mcpProtocolVersion = "2025-06-18"
	// defaultClientTimeout bounds the whole handshake. A server that cannot list
	// its tools within this window yields an error, never a hang.
	defaultClientTimeout = 8 * time.Second
)

// QueryToolsList spawns the MCP server described by command+args, performs the
// initialize handshake, and returns the raw JSON bytes of the tools/list
// result (the object containing the "tools" array). The returned bytes are
// suitable to pass straight to CanonicalToolsDigest.
//
// It is read-only and bounded by timeout (defaultClientTimeout if zero). The
// caller is responsible for deciding whether spawning the server is acceptable
// in the current posture — this function just performs the probe.
func QueryToolsList(ctx context.Context, command string, args []string, timeout time.Duration) ([]byte, error) {
	if command == "" {
		return nil, fmt.Errorf("empty MCP server command")
	}
	if timeout <= 0 {
		timeout = defaultClientTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command, args...) // #nosec G204 -- command comes from the user's own approved MCP config
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start MCP server %q: %w", command, err)
	}
	// Best-effort reap; ctx cancel already kills the process on timeout.
	defer func() { _ = cmd.Wait() }()

	raw, err := handshakeAndListTools(stdin, stdout)
	_ = stdin.Close()
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// jsonrpcMessage is the subset of a JSON-RPC 2.0 message we read. We keep
// Result and Error as raw so we never lose fidelity before hashing.
type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// handshakeAndListTools runs the protocol over an arbitrary writer/reader pair
// so it can be unit-tested against in-memory pipes without spawning a process.
func handshakeAndListTools(w io.Writer, r io.Reader) ([]byte, error) {
	br := bufio.NewReaderSize(r, 1<<20)

	// 1. initialize (id=1)
	if err := writeMessage(w, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "sir", "version": "pinning-probe"},
		},
	}); err != nil {
		return nil, err
	}
	if _, err := readResultForID(br, "1"); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	// 2. notifications/initialized (no id, no response expected)
	if err := writeMessage(w, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}); err != nil {
		return nil, err
	}

	// 3. tools/list (id=2)
	if err := writeMessage(w, map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}); err != nil {
		return nil, err
	}
	result, err := readResultForID(br, "2")
	if err != nil {
		return nil, fmt.Errorf("tools/list: %w", err)
	}
	return result, nil
}

func writeMessage(w io.Writer, msg map[string]interface{}) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("write JSON-RPC: %w", err)
	}
	return nil
}

// readResultForID reads line-delimited JSON-RPC messages until it finds a
// response whose id matches wantID, returning its raw result bytes. Server
// notifications and unrelated responses are skipped. A JSON-RPC error for the
// matching id is surfaced as an error.
func readResultForID(br *bufio.Reader, wantID string) ([]byte, error) {
	for {
		line, err := br.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			return nil, fmt.Errorf("connection closed before id=%s response: %w", wantID, err)
		}
		trimmed := trimSpace(line)
		if len(trimmed) == 0 {
			if err != nil {
				return nil, fmt.Errorf("connection closed before id=%s response", wantID)
			}
			continue
		}
		var m jsonrpcMessage
		if jErr := json.Unmarshal(trimmed, &m); jErr != nil {
			// A non-JSON line (server logging to stdout) is skipped, not fatal.
			if err != nil {
				return nil, fmt.Errorf("connection closed before id=%s response", wantID)
			}
			continue
		}
		if idString(m.ID) == wantID {
			if len(m.Error) > 0 {
				return nil, fmt.Errorf("server returned error: %s", string(m.Error))
			}
			return m.Result, nil
		}
		if err != nil {
			return nil, fmt.Errorf("connection closed before id=%s response", wantID)
		}
	}
}

// idString normalizes a JSON-RPC id (which may be a number or string) to its
// textual form for comparison. "1" and 1 both render as "1".
func idString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	s := string(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\r' || b[start] == '\n') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r' || b[end-1] == '\n') {
		end--
	}
	return b[start:end]
}
