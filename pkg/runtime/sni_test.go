package runtime

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// TestTunnelWithSNI_ServerFirstNotStalled is the regression guard for the review
// finding: a server-speaks-first protocol (SSH, SMTP, ...) must NOT be stalled by
// the SNI peek. The upstream->client banner must reach the client even though the
// client sends nothing, well before the peek deadline.
func TestTunnelWithSNI_ServerFirstNotStalled(t *testing.T) {
	p := &LocalProxy{allowlist: buildRuntimeAllowlist([]string{"example.com:22"})}
	clientEnd, proxyClient := net.Pipe()
	proxyUp, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer upstreamEnd.Close()
	go p.tunnelWithSNI(proxyClient, proxyUp, "example.com", "22")

	go func() { _, _ = upstreamEnd.Write([]byte("BANNER")) }() // server speaks first

	_ = clientEnd.SetReadDeadline(time.Now().Add(2 * time.Second)) // << the 8s peek deadline
	buf := make([]byte, 6)
	if _, err := io.ReadFull(clientEnd, buf); err != nil {
		t.Fatalf("server-first banner not delivered (stalled by SNI peek?): %v", err)
	}
	if string(buf) != "BANNER" {
		t.Errorf("got %q, want BANNER", buf)
	}
}

func TestTunnelWithSNI_ForwardsAllowedClientHello(t *testing.T) {
	p := &LocalProxy{allowlist: buildRuntimeAllowlist([]string{"github.com:443"})}
	clientEnd, proxyClient := net.Pipe()
	proxyUp, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer upstreamEnd.Close()
	go p.tunnelWithSNI(proxyClient, proxyUp, "github.com", "443")

	rec := realClientHello(t, "github.com")
	go func() { _, _ = clientEnd.Write(rec) }()

	_ = upstreamEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(rec))
	if _, err := io.ReadFull(upstreamEnd, got); err != nil {
		t.Fatalf("allowed ClientHello not forwarded to upstream: %v", err)
	}
	if !bytes.Equal(got, rec) {
		t.Error("forwarded ClientHello differs from the original bytes")
	}
}

func TestTunnelWithSNI_BlocksDisallowedSNI(t *testing.T) {
	p := &LocalProxy{allowlist: buildRuntimeAllowlist([]string{"github.com:443"})}
	clientEnd, proxyClient := net.Pipe()
	proxyUp, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer upstreamEnd.Close()
	go p.tunnelWithSNI(proxyClient, proxyUp, "github.com", "443")

	// SNI = evil.example on an approved CONNECT host (github.com) -> blocked.
	rec := realClientHello(t, "evil.example")
	go func() { _, _ = clientEnd.Write(rec) }()

	_ = upstreamEnd.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := upstreamEnd.Read(make([]byte, 1)); err == nil {
		t.Error("expected upstream torn down on disallowed SNI; bytes got through")
	}
}

// realClientHello produces a genuine TLS ClientHello (full record, header + body)
// for the given server name, using crypto/tls over an in-memory pipe.
func realClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	go func() {
		// The handshake never completes (no server on the other end); we only
		// need the ClientHello it writes first, which carries the SNI. No
		// InsecureSkipVerify needed — verification is never reached.
		_ = tls.Client(c1, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}).Handshake()
	}()
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8192)
	n, err := c2.Read(buf)
	if err != nil || n == 0 {
		t.Fatalf("capture ClientHello: n=%d err=%v", n, err)
	}
	_ = c1.Close()
	_ = c2.Close()
	return buf[:n]
}

func TestReadClientHello_ExtractsSNI(t *testing.T) {
	for _, name := range []string{"github.com", "api.anthropic.com", "sub.example.co.uk"} {
		rec := realClientHello(t, name)
		// readClientHello reads from a conn; feed the record through a pipe.
		srv, cli := net.Pipe()
		go func() { _, _ = cli.Write(rec); _ = cli.Close() }()
		raw, sni := readClientHello(srv)
		if sni != name {
			t.Errorf("SNI = %q, want %q", sni, name)
		}
		if len(raw) == 0 {
			t.Error("expected raw bytes to be returned for forwarding")
		}
	}
}

func TestReadClientHello_NonTLSFailsOpen(t *testing.T) {
	srv, cli := net.Pipe()
	go func() { _, _ = cli.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); _ = cli.Close() }()
	raw, sni := readClientHello(srv)
	if sni != "" {
		t.Errorf("non-TLS should yield empty SNI, got %q", sni)
	}
	if len(raw) == 0 {
		t.Error("expected the consumed bytes back for forwarding")
	}
}

func TestExtractSNI_MalformedNeverPanics(t *testing.T) {
	for _, b := range [][]byte{nil, {0x01}, {0x01, 0, 0, 0}, {0x16, 0x03}, make([]byte, 50)} {
		if got := extractSNI(b); got != "" {
			t.Errorf("extractSNI(%v) = %q, want empty", b, got)
		}
	}
}

func TestSNIAllowed(t *testing.T) {
	p := &LocalProxy{allowlist: buildRuntimeAllowlist([]string{"github.com:443", "api.anthropic.com:443"})}
	// SNI matches the CONNECT host.
	if !p.sniAllowed("github.com", "github.com", "443") {
		t.Error("SNI matching CONNECT host should be allowed")
	}
	// CONNECT by IP, SNI is an allowlisted host.
	if !p.sniAllowed("api.anthropic.com", "10.0.0.1", "443") {
		t.Error("allowlisted SNI should be allowed even when CONNECT host is an IP")
	}
	// SNI differs from CONNECT host and is not allowlisted -> blocked.
	if p.sniAllowed("evil.example", "github.com", "443") {
		t.Error("unapproved SNI on an approved CONNECT host must be blocked")
	}
	// Empty SNI passes (no name to check).
	if !p.sniAllowed("", "github.com", "443") {
		t.Error("empty SNI should pass through")
	}
}
