package secretscan

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Verbatim secret fingerprinting (context-laundering backstop).
//
// When a secret VALUE enters the model context (an approved raw read, an env
// read, or detected credentials in tool output), sir records a salted one-way
// fingerprint of it — never the raw value. If that exact value later re-appears
// in an outbound payload (a curl body, a file write, ...), sir can recognize it
// even though the bytes are "agent-authored". This catches verbatim copy-paste
// exfiltration of a secret laundered through context; it does NOT catch a
// paraphrased or transformed secret (the documented residual).

const minFingerprintLen = 12 // shorter values are too common -> false positives

// SecretFingerprint is a one-way digest of a secret value plus its byte length.
type SecretFingerprint struct {
	Hash string
	Len  int
}

// FingerprintValue returns the salted digest of value, or ok=false when value is
// too short to fingerprint safely.
func FingerprintValue(value string, salt []byte) (SecretFingerprint, bool) {
	if len(value) < minFingerprintLen {
		return SecretFingerprint{}, false
	}
	return SecretFingerprint{Hash: digest(value, salt), Len: len(value)}, true
}

// FingerprintSecrets extracts secret-bearing VALUES from text — pattern-matched
// credentials and high-entropy / secret-keyed env assignment values — and
// returns their salted one-way fingerprints. Raw values never leave this
// function.
func FingerprintSecrets(text string, salt []byte) []SecretFingerprint {
	if text == "" {
		return nil
	}
	seen := make(map[string]struct{})
	var out []SecretFingerprint
	add := func(value string) {
		fp, ok := FingerprintValue(value, salt)
		if !ok {
			return
		}
		if _, dup := seen[fp.Hash]; dup {
			return
		}
		seen[fp.Hash] = struct{}{}
		out = append(out, fp)
	}

	// 1. Pattern-matched credential values (sk-, ghp_, AKIA, JWT, private keys…).
	for _, p := range outputPatterns {
		for _, m := range p.RE.FindAllString(text, -1) {
			if p.Validator == nil || p.Validator(m) {
				add(m)
			}
		}
	}
	// 2. env-style assignment values that look like secrets (high entropy, or a
	//    secret-suggesting key) — catches non-patterned passwords/tokens.
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := splitAssignmentLine(line)
		if !ok {
			continue
		}
		if IsHighEntropyString(value) || keyLooksSecret(key) {
			add(value)
		}
	}
	return out
}

// PayloadLeaksSecret reports whether payload contains the value behind any
// fingerprint — verbatim, or laundered through a single cheap *mechanical*
// transform an agent can apply with a shell tool. It checks:
//
//   - delimiter-separated tokens, each also tested base64/hex/percent-decoded
//     (the `… | base64`, `xxd`, URL-encode exfil shapes);
//   - a sliding window over the raw payload, a reversed copy (the `… | rev`
//     case), and a whitespace-stripped copy (chunked `AKIA 1234 …`).
//
// All transforms are inverted on the PAYLOAD side, so the stored fingerprint
// stays a single one-way digest of the raw value. Semantic transforms
// (paraphrase, encryption, re-keying) are out of reach and remain the
// documented residual. Returns the matched length for the reason string.
func PayloadLeaksSecret(payload string, fps []SecretFingerprint, salt []byte) (int, bool) {
	if payload == "" || len(fps) == 0 {
		return 0, false
	}
	// Key the lookup by the raw 32-byte digest so the hot window scan never
	// allocates a hex string. The stored fingerprint Hash is hex; decode once.
	byHash := make(map[[sha256.Size]byte]int, len(fps))
	lengths := make(map[int]struct{})
	for _, fp := range fps {
		raw, err := hex.DecodeString(fp.Hash)
		if err != nil || len(raw) != sha256.Size {
			continue
		}
		var k [sha256.Size]byte
		copy(k[:], raw)
		byHash[k] = fp.Len
		lengths[fp.Len] = struct{}{}
	}
	if len(byHash) == 0 {
		return 0, false
	}

	// Single reused hasher + scratch buffer: the window scan below is allocation
	// free in steady state (no per-candidate sha256.New / []byte / hex).
	h := sha256.New()
	var buf []byte
	var sum [sha256.Size]byte
	match := func(s string) (int, bool) {
		if len(s) < minFingerprintLen {
			return 0, false
		}
		h.Reset()
		h.Write(salt)
		buf = append(buf[:0], s...)
		h.Write(buf)
		h.Sum(sum[:0])
		if n, ok := byHash[sum]; ok {
			return n, true
		}
		return 0, false
	}

	// A search space is scanned two ways: exact token match (the secret is a
	// discrete token) and a bounded sliding window (the secret is embedded
	// without delimiters). Window scanning is the expensive part, so the raw
	// payload keeps the original 64KB reach while derived spaces are capped.
	const rawWindowCap = 64 * 1024
	const derivedWindowCap = 16 * 1024
	windowScan := func(s string, limit int) (int, bool) {
		if len(s) == 0 || len(s) > limit {
			return 0, false
		}
		for L := range lengths {
			if L < minFingerprintLen || L > len(s) {
				continue
			}
			for i := 0; i+L <= len(s); i++ {
				if n, ok := match(s[i : i+L]); ok {
					return n, true
				}
			}
		}
		return 0, false
	}
	search := func(s string, limit int) (int, bool) {
		for _, tok := range tokenizePayload(s) {
			if n, ok := match(tok); ok {
				return n, true
			}
		}
		return windowScan(s, limit)
	}

	// 1. The raw payload (verbatim secret, as a token or embedded).
	if n, ok := search(payload, rawWindowCap); ok {
		return n, true
	}
	// 2. Cheap whole-payload inversions: reversed (`… | rev`) and
	//    whitespace-stripped (chunked `AKIA 1234 5678`). Capped for perf.
	if len(payload) <= derivedWindowCap {
		if r := reverseString(payload); r != payload {
			if n, ok := search(r, derivedWindowCap); ok {
				return n, true
			}
		}
		if s := stripWhitespace(payload); s != payload {
			if n, ok := search(s, derivedWindowCap); ok {
				return n, true
			}
		}
	}
	// 3. Decoded forms of each encoded run. Runs join across internal
	//    whitespace first, so line-wrapped output (`xxd -p` wraps hex at 60
	//    cols, `base64` at 76) is reassembled before decoding rather than
	//    decoded line-by-line. Each decoded blob is then searched in full.
	for _, dec := range decodeEncodedRuns(payload) {
		if n, ok := search(dec, derivedWindowCap); ok {
			return n, true
		}
	}
	return 0, false
}

// decodeEncodedRuns returns the decoded forms of encoded content in the payload,
// two ways: each delimiter-separated token (an inline single-token value like a
// base64 JSON field or a percent-encoded URL parameter), and reassembled
// line-wrapped blocks (so `xxd -p`/`base64`/`openssl` output split across lines
// is decoded as one value). Bounded in count to stay cheap on dense payloads.
func decodeEncodedRuns(payload string) []string {
	const maxCandidates = 512
	var out []string
	for _, tok := range tokenizePayload(payload) {
		if d := decodeTransforms(tok); len(d) > 0 {
			out = append(out, d...)
			if len(out) >= maxCandidates {
				return out
			}
		}
	}
	return append(out, decodeWrappedLineBlocks(payload)...)
}

// decodeWrappedLineBlocks reassembles line-wrapped encoded output before
// decoding. A "block" is a maximal run of consecutive lines that are entirely
// encode-charset bytes and share one wrap width (equal length), optionally ended
// by a shorter terminal line. For each block it emits the decode of the lines
// joined WITH and WITHOUT the last line, so it is correct whether that last line
// is the secret's terminal chunk or an unrelated short token (e.g. a heredoc
// `EOF`). Single-line values are left to the per-token path.
func decodeWrappedLineBlocks(payload string) []string {
	if strings.IndexByte(payload, '\n') < 0 {
		return nil
	}
	var out []string
	var block []string
	width := 0
	emit := func() {
		if len(block) >= 2 {
			if all := strings.Join(block, ""); len(all) >= minFingerprintLen {
				out = append(out, decodeTransforms(all)...)
			}
			if butLast := strings.Join(block[:len(block)-1], ""); len(butLast) >= minFingerprintLen {
				out = append(out, decodeTransforms(butLast)...)
			}
		}
		block = block[:0]
		width = 0
	}
	for _, line := range strings.Split(payload, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || !isAllRunBytes(line) {
			emit()
			continue
		}
		switch L := len(line); {
		case len(block) == 0:
			block = append(block, line)
			width = L
		case L == width:
			block = append(block, line)
		case L < width: // a shorter terminal line ends the wrap block
			block = append(block, line)
			emit()
		default: // a longer line starts a new block
			emit()
			block = append(block, line)
			width = L
		}
		if len(out) >= 512 {
			break
		}
	}
	emit()
	return out
}

// isAllRunBytes reports whether every byte of s is a base64/hex/percent symbol.
func isAllRunBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isRunByte(s[i]) {
			return false
		}
	}
	return len(s) > 0
}

// isRunByte reports whether c can appear in a base64/hex/percent-encoded blob.
func isRunByte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '+', c == '/', c == '-', c == '_', c == '=', c == '%':
		return true
	}
	return false
}

// decodeTransforms returns the plausible decoded forms of a token: base64 (std,
// raw, and URL alphabets), hex, and percent-encoding. Only printable decodes
// long enough to be a secret are returned, which keeps the false-positive rate
// and the work down. The token itself is matched by the caller separately.
func decodeTransforms(tok string) []string {
	if len(tok) < minFingerprintLen {
		return nil
	}
	var out []string
	addPrintable := func(b []byte, err error) {
		if err != nil || len(b) < minFingerprintLen || !mostlyPrintable(b) {
			return
		}
		out = append(out, string(b))
	}
	if isBase64ish(tok) {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding,
			base64.URLEncoding, base64.RawURLEncoding,
		} {
			if b, err := enc.DecodeString(tok); err == nil {
				addPrintable(b, nil)
			}
		}
	}
	if len(tok)%2 == 0 && isHexish(tok) {
		b, err := hex.DecodeString(tok)
		addPrintable(b, err)
	}
	if strings.IndexByte(tok, '%') >= 0 {
		if d, ok := percentDecode(tok); ok {
			addPrintable([]byte(d), nil)
		}
	}
	return out
}

func digest(value string, salt []byte) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(value))
	return hex.EncodeToString(h.Sum(nil))
}

// tokenizePayload splits a payload into candidate value tokens on the delimiters
// that surround secrets in shells, JSON, URLs, and code.
func tokenizePayload(payload string) []string {
	return strings.FieldsFunc(payload, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '"', '\'', '=', ':', '&', '?', ',', ';',
			'(', ')', '[', ']', '{', '}', '<', '>', '|', '`', '\\':
			return true
		}
		return false
	})
}

func splitAssignmentLine(line string) (key, value string, ok bool) {
	t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
	i := strings.Index(t, "=")
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(t[:i])
	value = strings.TrimSpace(t[i+1:])
	value = strings.TrimSuffix(strings.TrimPrefix(value, `"`), `"`)
	value = strings.TrimSuffix(strings.TrimPrefix(value, `'`), `'`)
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

// reverseString returns s with its runes in reverse order.
func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// stripWhitespace removes all Unicode whitespace, so a secret chunked across
// spaces/newlines (`AKIA 1234 5678`) is rejoined before the window scan.
func stripWhitespace(s string) string {
	if strings.IndexFunc(s, unicode.IsSpace) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isBase64ish reports whether every byte is a base64 (std or URL) symbol or
// padding — a cheap gate before attempting a decode.
func isBase64ish(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '-' || c == '_' || c == '=':
		default:
			return false
		}
	}
	return true
}

// isHexish reports whether every byte is a hex digit.
func isHexish(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// percentDecode decodes %XX escapes; ok is false on a malformed escape.
func percentDecode(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		hi, ok1 := unhex(s[i+1])
		lo, ok2 := unhex(s[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), true
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// mostlyPrintable reports whether decoded bytes look like text (valid UTF-8 and
// predominantly printable) — used to discard binary base64/hex decodes that
// cannot be a re-emitted secret string.
func mostlyPrintable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) {
			printable++
		}
	}
	return total > 0 && printable*10 >= total*9 // >=90% printable
}

func keyLooksSecret(key string) bool {
	k := strings.ToLower(key)
	for _, hint := range []string{"key", "token", "secret", "password", "passwd", "pwd", "credential", "api", "auth", "private", "access"} {
		if strings.Contains(k, hint) {
			return true
		}
	}
	return false
}
