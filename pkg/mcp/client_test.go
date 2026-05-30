package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// fakeServer drives handshakeAndListTools over in-memory pipes, playing the
// role of an MCP stdio server: it reads the client's requests and replies with
// scripted responses. This lets us test the protocol without spawning a binary.
func runFakeServer(t *testing.T, respond func(method, id string) (string, bool)) ([]byte, error) {
	t.Helper()
	cliIn, srvOut := io.Pipe() // server writes -> client reads
	srvIn, cliOut := io.Pipe() // client writes -> server reads

	go func() {
		br := bufio.NewReader(srvIn)
		for {
			line, err := br.ReadBytes('\n')
			if len(line) > 0 {
				var m struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
				}
				_ = json.Unmarshal(line, &m)
				if m.Method != "" {
					reply, ok := respond(m.Method, idString(m.ID))
					switch {
					case ok:
						_, _ = io.WriteString(srvOut, reply+"\n")
					case len(m.ID) > 0:
						// A request (has an id) the script declines to answer:
						// simulate the server disconnecting. Notifications (no
						// id) just continue without a reply.
						_ = srvOut.Close()
						return
					}
				}
			}
			if err != nil {
				_ = srvOut.Close()
				return
			}
		}
	}()

	raw, err := handshakeAndListTools(cliOut, cliIn)
	_ = cliOut.Close()
	return raw, err
}

func TestHandshakeAndListTools_HappyPath(t *testing.T) {
	toolsResult := `{"tools":[{"name":"echo","description":"echoes"}]}`
	raw, err := runFakeServer(t, func(method, id string) (string, bool) {
		switch method {
		case "initialize":
			return `{"jsonrpc":"2.0","id":` + id + `,"result":{"protocolVersion":"2025-06-18"}}`, true
		case "notifications/initialized":
			return "", false // notification: no reply
		case "tools/list":
			return `{"jsonrpc":"2.0","id":` + id + `,"result":` + toolsResult + `}`, true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// The returned result must be exactly the tools/list result and must digest.
	digest, names, err := CanonicalToolsDigest(raw)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if digest == "" || len(names) != 1 || names[0] != "echo" {
		t.Errorf("unexpected digest/names: %q %v", digest, names)
	}
}

func TestHandshakeAndListTools_SkipsInterleavedNotifications(t *testing.T) {
	// Server emits a log notification (no id) before the tools/list response.
	raw, err := runFakeServer(t, func(method, id string) (string, bool) {
		switch method {
		case "initialize":
			return `{"jsonrpc":"2.0","id":` + id + `,"result":{}}`, true
		case "tools/list":
			// First a notification (no id), then a non-JSON log line, then the real result.
			return `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info"}}` + "\n" +
				`server log: listing tools` + "\n" +
				`{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":[{"name":"t"}]}}`, true
		}
		return "", false
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, names, _ := CanonicalToolsDigest(raw); len(names) != 1 || names[0] != "t" {
		t.Errorf("expected tool t after skipping noise, got %v", names)
	}
}

func TestHandshakeAndListTools_ServerErrorSurfaced(t *testing.T) {
	_, err := runFakeServer(t, func(method, id string) (string, bool) {
		switch method {
		case "initialize":
			return `{"jsonrpc":"2.0","id":` + id + `,"result":{}}`, true
		case "tools/list":
			return `{"jsonrpc":"2.0","id":` + id + `,"error":{"code":-32601,"message":"no tools"}}`, true
		}
		return "", false
	})
	if err == nil || !strings.Contains(err.Error(), "server returned error") {
		t.Errorf("expected surfaced server error, got %v", err)
	}
}

func TestHandshakeAndListTools_ClosedBeforeResponse(t *testing.T) {
	// Server closes after initialize without answering tools/list.
	_, err := runFakeServer(t, func(method, id string) (string, bool) {
		if method == "initialize" {
			return `{"jsonrpc":"2.0","id":` + id + `,"result":{}}`, true
		}
		return "", false // never answers tools/list; pipe closes at EOF
	})
	if err == nil || !strings.Contains(err.Error(), "tools/list") {
		t.Errorf("expected tools/list closed-connection error, got %v", err)
	}
}
