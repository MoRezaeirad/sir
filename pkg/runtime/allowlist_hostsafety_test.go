package runtime

import "testing"

// TestProxyAllowlistRejectsSmuggledHosts is the regression guard against the
// SOCKS5 host-smuggling bypass class (e.g. Claude Code's
// `attacker.com\x00.allowed.com`). An allowed host must match only as itself;
// any NUL byte, control char, whitespace, or non-ASCII rune fails closed even
// when the allowed name appears as a substring.
func TestProxyAllowlistRejectsSmuggledHosts(t *testing.T) {
	a := buildRuntimeAllowlist([]string{"api.anthropic.com:443", "github.com:443"})

	// Sanity: the clean allowed hosts pass.
	if !a.Allows("api.anthropic.com", "443") {
		t.Fatal("expected api.anthropic.com:443 to be allowed")
	}
	if !a.Allows("github.com", "443") {
		t.Fatal("expected github.com:443 to be allowed")
	}

	smuggled := []string{
		"attacker.com\x00.github.com",    // NUL truncation
		"api.anthropic.com\x00",          // trailing NUL on an allowed name
		"api.anthropic.com\x00.evil.com", // allowed name as a prefix
		"github.com\n",                   // newline
		"gitхub.com",                     // Cyrillic homoglyph 'х'
		"github.com ",                    // trailing space
		"evil\tgithub.com",               // tab
	}
	for _, h := range smuggled {
		if a.Allows(h, "443") {
			t.Errorf("smuggled host %q was allowed — host-safety bypass", h)
		}
	}
}

func TestSafeProxyHost(t *testing.T) {
	ok := []string{"github.com", "api.anthropic.com", "10.0.0.1", "::1", "fe80::1%eth0", "a-b.example.com"}
	for _, h := range ok {
		if !safeProxyHost(h) {
			t.Errorf("safeProxyHost(%q) = false, want true", h)
		}
	}
	bad := []string{"evil\x00.com", "gitхub.com", "a b.com", "x\ty.com", "host\n", "ünïcode.com"}
	for _, h := range bad {
		if safeProxyHost(h) {
			t.Errorf("safeProxyHost(%q) = true, want false", h)
		}
	}
}
