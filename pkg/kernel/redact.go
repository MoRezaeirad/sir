package kernel

import "regexp"

// Redact applies passive redaction to evidence before ledgering.
// Non-negotiable #7: the ledger never stores raw secrets.
// Only obviously tokenized values are redacted; ambiguous strings are kept.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                    // AWS access key
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),                 // GitHub PAT
	regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`),                 // GitHub Actions secret
	regexp.MustCompile(`sk-[A-Za-z0-9]{32,}`),                 // OpenAI-style key
	regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{8,}`),        // Slack token
	regexp.MustCompile(`Bearer\s+[A-Za-z0-9+/=._-]{20,}`),     // Bearer token
	regexp.MustCompile(`(?i)password\s*=\s*\S{8,}`),           // password=... in shell
	regexp.MustCompile(`(?i)api[_-]?key\s*=\s*\S{8,}`),        // api_key=...
}

// RedactString replaces known secret patterns with "[REDACTED]".
func RedactString(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// RedactExplanation redacts the explanation string before it enters the ledger.
func RedactExplanation(explanation string) string {
	return RedactString(explanation)
}
