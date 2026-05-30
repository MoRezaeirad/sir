package runtime

import (
	"io"
	"net"
	"strings"
	"time"
)

// TLS SNI consistency gate for the `sir run` proxy.
//
// The proxy makes its allow decision on the CONNECT host string and dials that
// host. This adds a second, defense-in-depth check on the *actual* TLS name the
// client negotiates: it peeks the leading ClientHello, extracts the SNI, and
// blocks when the SNI is neither the allow-checked CONNECT host nor an
// allowlisted host. That catches a client that CONNECTs to an approved host but
// then negotiates TLS for a different, unapproved name.
//
// Honest boundary: this is NOT a complete domain-fronting defense. Classic
// fronting uses an *approved* SNI with a hidden inner HTTP Host header, which is
// invisible without terminating TLS (sir deliberately does not MITM). Non-TLS
// traffic, ClientHellos with no SNI, and ClientHellos sir cannot parse all pass
// through (fail open) so legitimate connections are never broken.

const (
	sniPeekTimeout    = 8 * time.Second
	maxTLSRecordBytes = 16384 // a TLS record is at most 2^14 bytes
)

// enforceSNI peeks the client's leading TLS ClientHello and verifies the SNI is
// consistent with the allow-checked CONNECT host. It returns the bytes it
// consumed (which the caller MUST forward to upstream before piping) and whether
// the connection may proceed. ok=false means the SNI was parsed and disallowed.
func (p *LocalProxy) enforceSNI(client net.Conn, connectHost, port string) (consumed []byte, ok bool) {
	_ = client.SetReadDeadline(time.Now().Add(sniPeekTimeout))
	raw, sni := readClientHello(client)
	_ = client.SetReadDeadline(time.Time{})

	if sni == "" {
		return raw, true // non-TLS, no SNI, or unparseable -> pass through
	}
	if p.sniAllowed(sni, connectHost, port) {
		return raw, true
	}
	p.recordBlockedEgress(net.JoinHostPort(sni, port))
	return raw, false
}

// sniAllowed reports whether the negotiated SNI is consistent with the
// authorized destination: it matches the CONNECT host, or it is itself an
// allowlisted host (so CONNECT-by-IP with an allowlisted SNI still works).
func (p *LocalProxy) sniAllowed(sni, connectHost, port string) bool {
	sni = NormalizeProxyHost(sni)
	if sni == "" {
		return true
	}
	if sni == NormalizeProxyHost(connectHost) {
		return true
	}
	return p.isAllowed(sni, port)
}

// readClientHello reads the leading TLS record from conn and, if it is a
// handshake record carrying a ClientHello, returns the SNI. It always returns
// the raw bytes it consumed so the caller can forward them. Any deviation from a
// clean, single-record ClientHello yields ("", ...) — fail open.
//
// It reads ONE byte first: a non-TLS protocol (its first byte is not the TLS
// handshake type 0x16) returns immediately with that single byte, so a
// server-speaks-first protocol whose client eventually sends a non-0x16 banner
// is never stalled waiting for a full 5-byte header.
func readClientHello(conn net.Conn) (raw []byte, sni string) {
	first := make([]byte, 1)
	if n, _ := io.ReadFull(conn, first); n < 1 {
		return nil, ""
	}
	if first[0] != 0x16 { // 0x16 = TLS handshake content type
		return first, "" // not TLS — forward the byte, fail open
	}
	rest := make([]byte, 4)
	m, _ := io.ReadFull(conn, rest)
	raw = append(first, rest[:m]...)
	if m < 4 {
		return raw, ""
	}
	recLen := int(raw[3])<<8 | int(raw[4])
	if recLen == 0 || recLen > maxTLSRecordBytes {
		return raw, ""
	}
	body := make([]byte, recLen)
	k, _ := io.ReadFull(conn, body)
	raw = append(raw, body[:k]...)
	if k < recLen {
		return raw, "" // partial record (ClientHello fragmented) -> fail open
	}
	return raw, extractSNI(body)
}

// tunnelWithSNI bridges client<->upstream while inspecting the client's leading
// ClientHello for SNI consistency. The upstream->client direction starts
// IMMEDIATELY so server-speaks-first protocols (SSH, SMTP, ...) are never
// stalled by the peek; only the client->upstream direction waits for the (fast,
// localhost) ClientHello. A disallowed SNI tears both sides down. This call
// blocks until the tunnel closes; callers already run per-connection goroutines.
func (p *LocalProxy) tunnelWithSNI(client, upstream net.Conn, host, port string) {
	go tunnelRunProxyConnections(client, upstream) // upstream -> client, immediate

	hello, ok := p.enforceSNI(client, host, port)
	if !ok {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	if len(hello) > 0 {
		if _, err := upstream.Write(hello); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
	}
	tunnelRunProxyConnections(upstream, client) // client -> upstream
}

// extractSNI parses a TLS handshake message (a ClientHello) and returns the
// server_name (SNI) host, or "" if absent/unparseable. All indexing is bounds-
// checked so a malformed ClientHello can never panic.
func extractSNI(hs []byte) string {
	r := byteReader{b: hs}
	if r.u8() != 0x01 { // handshake type 0x01 = ClientHello
		return ""
	}
	r.skip(3)           // handshake length
	r.skip(2)           // client_version
	r.skip(32)          // random
	r.skip(int(r.u8())) // session_id
	r.skip(r.u16())     // cipher_suites
	r.skip(int(r.u8())) // compression_methods
	extTotal := r.u16() // extensions length
	extEnd := r.pos + extTotal
	if r.err || extEnd > len(hs) {
		return ""
	}
	for r.pos+4 <= extEnd {
		extType := r.u16()
		extLen := r.u16()
		if r.err || r.pos+extLen > len(hs) {
			return ""
		}
		if extType != 0x0000 { // 0x0000 = server_name
			r.skip(extLen)
			continue
		}
		// server_name extension body: list_len(2), then entries of
		// {name_type(1), name_len(2), name}. We want name_type 0 (host_name).
		sub := byteReader{b: hs[r.pos : r.pos+extLen]}
		sub.skip(2) // server_name_list length
		for sub.pos+3 <= len(sub.b) {
			nameType := sub.u8()
			nameLen := sub.u16()
			if sub.err || sub.pos+nameLen > len(sub.b) {
				return ""
			}
			if nameType == 0 {
				return strings.ToLower(string(sub.b[sub.pos : sub.pos+nameLen]))
			}
			sub.skip(nameLen)
		}
		return ""
	}
	return ""
}

// byteReader is a tiny bounds-checked big-endian reader. Once any read runs past
// the end, err latches and subsequent reads are no-ops returning 0.
type byteReader struct {
	b   []byte
	pos int
	err bool
}

func (r *byteReader) u8() int {
	if r.err || r.pos+1 > len(r.b) {
		r.err = true
		return 0
	}
	v := int(r.b[r.pos])
	r.pos++
	return v
}

func (r *byteReader) u16() int {
	if r.err || r.pos+2 > len(r.b) {
		r.err = true
		return 0
	}
	v := int(r.b[r.pos])<<8 | int(r.b[r.pos+1])
	r.pos += 2
	return v
}

func (r *byteReader) skip(n int) {
	if r.err || n < 0 || r.pos+n > len(r.b) {
		r.err = true
		return
	}
	r.pos += n
}
