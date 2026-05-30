package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
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

// PayloadLeaksSecret reports whether payload contains the verbatim value behind
// any fingerprint. It checks delimiter-separated tokens (the common case — a
// secret pasted into a curl body or JSON), and for each distinct fingerprinted
// length a sliding window over small payloads (catches values embedded without
// delimiters). Returns the matched length for the reason string.
func PayloadLeaksSecret(payload string, fps []SecretFingerprint, salt []byte) (int, bool) {
	if payload == "" || len(fps) == 0 {
		return 0, false
	}
	hashes := make(map[string]int, len(fps)) // hash -> len
	lengths := make(map[int]struct{})
	for _, fp := range fps {
		hashes[fp.Hash] = fp.Len
		lengths[fp.Len] = struct{}{}
	}
	match := func(s string) (int, bool) {
		if len(s) < minFingerprintLen {
			return 0, false
		}
		if n, ok := hashes[digest(s, salt)]; ok {
			return n, true
		}
		return 0, false
	}

	for _, tok := range tokenizePayload(payload) {
		if n, ok := match(tok); ok {
			return n, true
		}
	}
	// Sliding window for values embedded without delimiters; bounded for perf.
	if len(payload) <= 64*1024 {
		for L := range lengths {
			if L < minFingerprintLen || L > len(payload) {
				continue
			}
			for i := 0; i+L <= len(payload); i++ {
				if n, ok := match(payload[i : i+L]); ok {
					return n, true
				}
			}
		}
	}
	return 0, false
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

func keyLooksSecret(key string) bool {
	k := strings.ToLower(key)
	for _, hint := range []string{"key", "token", "secret", "password", "passwd", "pwd", "credential", "api", "auth", "private", "access"} {
		if strings.Contains(k, hint) {
			return true
		}
	}
	return false
}
