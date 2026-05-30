package classify

import (
	"math"
	"strings"
)

// IsNetworkCommand reports whether cmd starts with a network egress tool.
func IsNetworkCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	prefixes := []string{
		"curl ", "curl\t", "wget ", "wget\t",
		"ssh ", "ssh\t", "scp ", "scp\t", "sftp ", "sftp\t",
		"rsync ", "rsync\t",
		"ftp ", "ftp\t", "ftps ", "lftp ", "ncftp ",
		"nc ", "nc\t", "ncat ", "netcat ", "netcat\t",
		"socat ", "socat\t",
		"telnet ", "telnet\t",
		"openssl s_client",
		"aws s3 cp", "aws s3 sync", "aws s3 mv",
		"gsutil cp", "gsutil rsync", "gsutil mv",
		"az storage blob upload",
		"rclone copy", "rclone sync", "rclone move",
		"s3cmd put", "s3cmd sync",
		"smbclient ",
		"tftp ",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// ExtractNetworkDest extracts the first destination token from curl/wget-like commands.
func ExtractNetworkDest(cmd string) string {
	parts := strings.Fields(cmd)
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if strings.HasPrefix(p, "-") {
			if FlagTakesValue(p) && i+1 < len(parts) {
				i++
			}
			continue
		}
		return p
	}
	return ""
}

// IsDNSTunnelHost reports whether host looks like a DNS-tunneling / DNS-exfil
// destination — a subdomain label that is both long and high-entropy, the shape
// of base32/hex-encoded data smuggled into a hostname
// (e.g. "mz2wg4tbojuw4zlon...deadbeef.tunnel.evil.com"). It is deliberately
// conservative to stay quiet on normal hostnames: a label must be long (>= 32
// chars), almost entirely alphanumeric (dictionary/hyphenated CDN names are
// kept), AND high Shannon entropy. Returns (true, reason) on a match.
func IsDNSTunnelHost(host string) (bool, string) {
	host = hostnameForTunnelCheck(host)
	if host == "" {
		return false, ""
	}
	for _, label := range strings.Split(host, ".") {
		if isHighEntropyLabel(label) {
			return true, "destination contains a long high-entropy DNS label (possible DNS tunneling / exfiltration)"
		}
	}
	return false, ""
}

// hostnameForTunnelCheck strips scheme, path, and port from a raw destination,
// leaving the bare hostname for label analysis.
func hostnameForTunnelCheck(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.LastIndex(raw, "@"); i >= 0 { // strip user:pass@
		raw = raw[i+1:]
	}
	if i := strings.LastIndex(raw, ":"); i >= 0 && !strings.Contains(raw, "]") {
		raw = raw[:i] // strip :port (not IPv6)
	}
	return strings.Trim(raw, ".")
}

func isHighEntropyLabel(label string) bool {
	n := len(label)
	if n < 32 {
		return false
	}
	alnum := 0
	for i := 0; i < n; i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			alnum++
		}
	}
	if float64(alnum)/float64(n) < 0.9 {
		return false // hyphens/underscores -> human-readable, not encoded data
	}
	// Very long pure-alphanumeric labels are encoded data even at the moderate
	// entropy of hex; shorter (32-44) labels need the higher entropy of base32/64
	// to avoid flagging the rare long-but-readable label. No legitimate hostname
	// label is 45+ chars of alphanumeric.
	e := shannonEntropy(label)
	if n >= 45 {
		return e >= 3.0
	}
	return e >= 3.5
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	e := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// IsDNSCommand detects DNS exfiltration prefixes.
func IsDNSCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	for _, p := range []string{"nslookup ", "dig ", "host ", "drill ", "whois "} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return strings.HasPrefix(lower, "hping ") || strings.HasPrefix(lower, "hping3 ")
}

// IsPingCommand reports whether cmd is ping or ping6.
func IsPingCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	return strings.HasPrefix(lower, "ping ") || strings.HasPrefix(lower, "ping6 ")
}

// IsInterpreterNetworkCommand returns true for one-liner interpreter network usage.
func IsInterpreterNetworkCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	interpreterPrefixes := []string{
		"python ", "python3 ", "python2 ",
		"node ", "nodejs ",
		"ruby ",
		"perl ",
		"php ",
		"bun ",
		"deno ",
		"go run ",
		"rscript ",
	}

	matchedInterpreter := false
	for _, p := range interpreterPrefixes {
		if strings.HasPrefix(lower, p) {
			matchedInterpreter = true
			break
		}
	}
	if !matchedInterpreter {
		return false
	}

	hasOneLinerFlag := false
	parts := strings.Fields(cmd)
	for _, part := range parts[1:] {
		if part == "-c" || part == "-e" || part == "-r" || part == "--eval" {
			hasOneLinerFlag = true
			break
		}
		if strings.HasPrefix(part, "-") && !strings.HasPrefix(part, "--") && len(part) > 2 {
			if strings.HasSuffix(part, "c") || strings.HasSuffix(part, "e") || strings.HasSuffix(part, "r") {
				hasOneLinerFlag = true
				break
			}
		}
	}
	if !hasOneLinerFlag {
		return false
	}

	networkPatterns := []string{
		"requests.", "urllib", "http.client", "httpx", "aiohttp",
		"socket.connect", "socket.create_connection", "ssl.", "urlopen", "urllib2",
		"fetch(", "http.get", "https.get",
		"require('http", `require("http`, "require('https", `require("https`,
		"axios", "got(", "superagent", "needle",
		"net::http", "open-uri", "uri.open", "faraday", "httparty", "restclient", "tcpsocket",
		"lwp::", "http::", "www::mechanize", "io::socket", "net::http",
		"curl_init", "file_get_contents", "fsockopen", "stream_socket_client",
		".connect(", "socket(", ".send(",
	}

	lowerCmd := strings.ToLower(cmd)
	for _, pattern := range networkPatterns {
		if strings.Contains(lowerCmd, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// IsTestCommand reports whether cmd is a test runner invocation.
func IsTestCommand(cmd string) bool {
	testPrefixes := []string{
		"go test", "npm test", "npm run test", "yarn test",
		"pytest", "python -m pytest", "python3 -m pytest",
		"cargo test", "make test", "bundle exec rspec",
		"jest", "vitest", "mocha",
	}
	lower := strings.ToLower(strings.TrimSpace(cmd))
	for _, p := range testPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}
