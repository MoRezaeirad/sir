package secretscan

import (
	"strings"
	"testing"
)

// TestURICredentialDetection (SCAN-1) locks the connection-string / URI-with-
// credentials detector that closes the scanner's headline blind spot: a secret
// embedded in a URI userinfo (postgres://user:pass@host) that the high-entropy
// heuristic deliberately skips because it contains "://". This is the exact
// scanner-blind exfil shape the red-team used to reject the egress downgrade,
// so detecting + redacting it is a precondition for NET-1.
func TestURICredentialDetection(t *testing.T) {
	leaks := []struct {
		name string
		text string
	}{
		{"postgres with @ in password", "DATABASE_URL=postgres://svc:S3cr3tP@ss@db.internal/prod"},
		{"redis empty user", "redis://:s0meP4ssw0rd@cache.prod:6379/0"},
		{"mongodb", "mongodb://admin:hunter2@mongo.internal:27017/app"},
		{"amqp", "amqp://guest:guestpw@rabbit.svc.cluster.local:5672"},
		{"https basic auth", "https://deploy:gh_tok3n_value@artifacts.corp.net/repo"},
	}
	for _, tc := range leaks {
		t.Run("detects/"+tc.name, func(t *testing.T) {
			matches := ScanOutputForCredentials(tc.text)
			if !hasPattern(matches, "uri_with_credentials") {
				t.Errorf("expected uri_with_credentials match for %q, got %+v", tc.text, matches)
			}
			red := RedactStructuredText(tc.text)
			if strings.Contains(red, "@") && !strings.Contains(red, "[REDACTED:uri_credentials]") {
				t.Errorf("expected redaction of %q, got %q", tc.text, red)
			}
		})
	}

	// No false positives on URLs that carry no embedded credential.
	clean := []string{
		"https://github.com/somoore/sir",
		"see https://api.example.com/v1/users?token=abc for docs", // query-string token is a different (non-userinfo) case
		"git clone https://example.com/repo.git",
		"http://localhost:3000/health",
		"reach out at user@example.com for support",
	}
	for _, text := range clean {
		t.Run("no_false_positive", func(t *testing.T) {
			if hasPattern(ScanOutputForCredentials(text), "uri_with_credentials") {
				t.Errorf("false positive uri_with_credentials on %q", text)
			}
		})
	}
}
