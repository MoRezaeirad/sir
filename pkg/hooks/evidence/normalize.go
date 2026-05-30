package evidence

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Encoding/obfuscation normalization for the injection scanner.
//
// The ~50-pattern scanner matches literal text, so an attacker can evade it by
// splitting words with zero-width characters ("ig​nore previous
// instructions") or by encoding the payload (base64/hex/percent). These helpers
// produce normalized VARIANTS of the MCP output that the same patterns are run
// over, so the literal scanner also catches the common encoded/hidden forms.
// Stdlib only — no Unicode-confusables (homoglyph) folding, so paraphrase and
// homoglyph substitution remain the honest residual backstopped by the
// integrity-flow egress wall.

const maxDecodedVariantBytes = 100_000

var (
	base64Run = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)
	hexRun    = regexp.MustCompile(`(?:[0-9a-fA-F]{2}){8,}`)
)

// injectionScanVariants returns additional strings to run the injection patterns
// over: the output with invisible (zero-width/bidi) format characters removed,
// and the concatenation of any base64/hex/percent-decoded blobs it contains.
// Empty/duplicate variants are omitted.
func injectionScanVariants(output string) []string {
	var variants []string
	if stripped := stripFormatRunes(output); stripped != output && stripped != "" {
		variants = append(variants, stripped)
	}
	if decoded := decodeEmbeddedBlobs(output); decoded != "" {
		variants = append(variants, decoded)
	}
	return variants
}

// stripFormatRunes removes Unicode "format" runes (category Cf: zero-width
// joiners, zero-width space, BOM, bidi controls, …) so words split by invisible
// characters re-form into the literal the patterns look for.
func stripFormatRunes(s string) string {
	hasFormat := false
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) {
			hasFormat = true
			break
		}
	}
	if !hasFormat {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// decodeEmbeddedBlobs finds base64/hex runs and percent-encoding in output,
// decodes them, and returns the printable decoded text joined by spaces (bounded
// in size). Non-printable decode results are dropped so binary blobs that happen
// to look like base64 do not pollute the scan.
func decodeEmbeddedBlobs(output string) string {
	var b strings.Builder

	appendIfPrintable := func(dec []byte) {
		if len(dec) == 0 || b.Len() >= maxDecodedVariantBytes || !mostlyPrintable(dec) {
			return
		}
		b.Write(dec)
		b.WriteByte('\n')
	}

	for _, m := range base64Run.FindAllString(output, -1) {
		appendIfPrintable(tryBase64(m))
	}
	for _, m := range hexRun.FindAllString(output, -1) {
		if dec, err := hex.DecodeString(m); err == nil {
			appendIfPrintable(dec)
		}
	}
	if strings.IndexByte(output, '%') >= 0 {
		if dec, err := url.QueryUnescape(output); err == nil && dec != output {
			appendIfPrintable([]byte(dec))
		}
	}
	return b.String()
}

// tryBase64 attempts the common base64 alphabets/paddings and returns the first
// successful decode (or nil). Embedded base64 is often unpadded.
func tryBase64(s string) []byte {
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if dec, err := enc.DecodeString(trimmed); err == nil && len(dec) > 0 {
			return dec
		}
	}
	return nil
}

func mostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) >= 0.8
}
