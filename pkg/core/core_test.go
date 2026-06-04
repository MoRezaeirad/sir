package core

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

// decodeMSTR1Payload decodes a MSTR/1 binary buffer and returns the JSON payload bytes.
func decodeMSTR1Payload(t *testing.T, buf []byte) map[string]interface{} {
	t.Helper()
	if len(buf) < 9 {
		t.Fatalf("buffer too short: %d bytes", len(buf))
	}
	if string(buf[0:4]) != "MSTR" {
		t.Fatalf("bad magic: %q", string(buf[0:4]))
	}
	if buf[4] != 0x01 {
		t.Fatalf("bad version: %d", buf[4])
	}
	length := binary.BigEndian.Uint32(buf[5:9])
	if int(length) > len(buf)-9 {
		t.Fatalf("length mismatch: declared %d, available %d", length, len(buf)-9)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(buf[9:9+length], &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return out
}

func TestEncodeMSTR1_IncludesLabels(t *testing.T) {
	req := &Request{
		ToolName: "Read",
		Intent: Intent{
			Verb:        "read_ref",
			Target:      ".env",
			IsSensitive: true,
			Labels: []Label{
				{Sensitivity: "secret", Trust: "trusted", Provenance: "user"},
			},
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)

	requestObj, ok := payload["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing or malformed 'request' key in payload")
	}

	labelsRaw, ok := requestObj["labels"]
	if !ok {
		t.Fatal("'labels' key missing from request payload")
	}

	labelsArr, ok := labelsRaw.([]interface{})
	if !ok {
		t.Fatalf("'labels' is not an array: %T", labelsRaw)
	}
	if len(labelsArr) == 0 {
		t.Fatal("expected at least one label")
	}

	lbl, ok := labelsArr[0].(map[string]interface{})
	if !ok {
		t.Fatalf("label[0] is not an object: %T", labelsArr[0])
	}

	if lbl["sensitivity"] != "secret" {
		t.Errorf("label sensitivity = %q, want %q", lbl["sensitivity"], "secret")
	}
	if lbl["trust"] != "trusted" {
		t.Errorf("label trust = %q, want %q", lbl["trust"], "trusted")
	}
	if lbl["provenance"] != "user" {
		t.Errorf("label provenance = %q, want %q", lbl["provenance"], "user")
	}
}

func TestEncodeMSTR1_IncludesDelegation(t *testing.T) {
	req := &Request{
		ToolName: "Agent",
		Intent: Intent{
			Verb:         "delegate",
			Target:       "build the feature",
			IsDelegation: true,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj, ok := payload["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing 'request' in payload")
	}

	val, ok := requestObj["is_delegation"]
	if !ok {
		t.Fatal("'is_delegation' key missing from request payload")
	}
	if val != true {
		t.Errorf("is_delegation = %v, want true", val)
	}
}

func TestEncodeMSTR1_IncludesTripwire(t *testing.T) {
	req := &Request{
		ToolName: "Read",
		Intent: Intent{
			Verb:       "read_ref",
			Target:     ".canary",
			IsTripwire: true,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj, ok := payload["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing 'request' in payload")
	}

	val, ok := requestObj["is_tripwire"]
	if !ok {
		t.Fatal("'is_tripwire' key missing from request payload")
	}
	if val != true {
		t.Errorf("is_tripwire = %v, want true", val)
	}
}

func TestEncodeMSTR1_IncludesToolName(t *testing.T) {
	req := &Request{
		ToolName: "WebFetch",
		Intent: Intent{
			Verb:   "net_external",
			Target: "https://example.com",
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj, ok := payload["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing 'request' in payload")
	}

	toolName, ok := requestObj["tool_name"]
	if !ok {
		t.Fatal("'tool_name' key missing from request payload")
	}
	if toolName != "WebFetch" {
		t.Errorf("tool_name = %q, want %q", toolName, "WebFetch")
	}
}

func TestEncodeMSTR1_MagicAndVersion(t *testing.T) {
	req := &Request{
		Intent: Intent{Verb: "read_ref", Target: "src/main.go"},
	}
	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}
	if len(buf) < 9 {
		t.Fatalf("output too short: %d bytes", len(buf))
	}
	if string(buf[0:4]) != "MSTR" {
		t.Errorf("bad magic: %q", string(buf[0:4]))
	}
	if buf[4] != 0x01 {
		t.Errorf("bad version: %d", buf[4])
	}
}

func TestEncodeMSTR1_SessionFields(t *testing.T) {
	req := &Request{
		Intent: Intent{Verb: "net_external", Target: "evil.com"},
		Session: SessionInfo{
			SecretSession: true,
			DenyAll:       false,
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	sessionObj, ok := payload["session"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing 'session' in payload")
	}
	if sessionObj["secret_session"] != true {
		t.Errorf("session.secret_session = %v, want true", sessionObj["secret_session"])
	}
	if sessionObj["deny_all"] != false {
		t.Errorf("session.deny_all = %v, want false", sessionObj["deny_all"])
	}
}

func TestEncodeMSTR1_EmptyLabels(t *testing.T) {
	req := &Request{
		Intent: Intent{
			Verb:   "read_ref",
			Target: "src/main.go",
			Labels: []Label{},
		},
	}

	buf, err := encodeMSTR1(req)
	if err != nil {
		t.Fatalf("encodeMSTR1: %v", err)
	}

	payload := decodeMSTR1Payload(t, buf)
	requestObj, ok := payload["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing 'request' in payload")
	}

	labelsRaw, ok := requestObj["labels"]
	if !ok {
		t.Fatal("'labels' key missing from request payload")
	}
	labelsArr, ok := labelsRaw.([]interface{})
	if !ok {
		t.Fatalf("'labels' is not an array: %T", labelsRaw)
	}
	if len(labelsArr) != 0 {
		t.Errorf("expected empty labels array, got %d elements", len(labelsArr))
	}
}

func TestDecodeMSTR1Response_ValidResponse(t *testing.T) {
	// Build a valid MSTR/1 response manually
	responseJSON := `{"verdict":"allow","reason":"within lease boundary"}`
	payloadBytes := []byte(responseJSON)

	var buf []byte
	buf = append(buf, "MSTR"...)
	buf = append(buf, 0x01)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(payloadBytes)))
	buf = append(buf, lenBytes...)
	buf = append(buf, payloadBytes...)

	resp, err := decodeMSTR1Response(buf)
	if err != nil {
		t.Fatalf("decodeMSTR1Response: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
	if resp.Reason != "within lease boundary" {
		t.Errorf("reason = %q, want 'within lease boundary'", resp.Reason)
	}
}

func TestDecodeMSTR1Response_InvalidMagic(t *testing.T) {
	buf := []byte("BADM\x01\x00\x00\x00\x02{}")
	_, err := decodeMSTR1Response(buf)
	if err == nil {
		t.Error("expected error for invalid magic")
	}
	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("error should mention magic: %v", err)
	}
}

func TestDecodeMSTR1Response_TooShort(t *testing.T) {
	buf := []byte("MST")
	_, err := decodeMSTR1Response(buf)
	if err == nil {
		t.Error("expected error for too-short input")
	}
}

func TestLocalEvaluate_DenyAll(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "read_ref", Target: "src/main.go"},
		Session: SessionInfo{DenyAll: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected deny for deny-all session, got %s", resp.Decision)
	}
}

func TestLocalEvaluate_SecretEgressBlocked(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "net_external", Target: "evil.com"},
		Session: SessionInfo{SecretSession: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected deny for secret session + net_external, got %s", resp.Decision)
	}
}

// TestLocalEvaluate_UntrustedEgressBlocked mirrors mister-core's integrity-flow
// egress wall (P0.3): untrusted content ingested this session escalates external
// egress / DNS from the clean-session Ask to a hard Deny. Keeps the Go fallback
// in parity with policy_guards.rs so the degraded path is never more permissive
// than the Rust oracle.
func TestLocalEvaluate_UntrustedEgressBlocked(t *testing.T) {
	netReq := &Request{
		Intent:  Intent{Verb: "net_external", Target: "evil.com"},
		Session: SessionInfo{RecentlyReadUntrusted: true},
	}
	dnsReq := &Request{
		Intent:  Intent{Verb: "dns_lookup", Target: "evil.com"},
		Session: SessionInfo{RecentlyReadUntrusted: true},
	}
	for _, req := range []*Request{netReq, dnsReq} {
		resp, err := localEvaluate(req)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", req.Intent.Verb, err)
		}
		if resp.Decision != "deny" {
			t.Errorf("%s + untrusted read: expected deny, got %s (%s)", req.Intent.Verb, resp.Decision, resp.Reason)
		}
	}
}

// TestLocalEvaluate_CleanEgressAsks is the over-block regression: without
// untrusted ingestion the integrity wall must NOT fire — clean-session egress
// stays an approval prompt, not a block.
func TestLocalEvaluate_CleanEgressAsks(t *testing.T) {
	req := &Request{Intent: Intent{Verb: "net_external", Target: "example.com"}}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("clean-session net_external: expected ask, got %s (%s)", resp.Decision, resp.Reason)
	}
}

// TestLocalEvaluate_UntrustedThisTurnEgressBlocked mirrors the Rust oracle's
// turn-scoped weak signal: same-turn untrusted ingestion blocks external egress
// even when the strong session-scoped signal is unset. Keeps the Go fallback in
// parity with policy_guards.rs.
func TestLocalEvaluate_UntrustedThisTurnEgressBlocked(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "net_external", Target: "evil.com"},
		Session: SessionInfo{UntrustedContentThisTurn: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("untrusted-this-turn net_external: expected deny, got %s (%s)", resp.Decision, resp.Reason)
	}
}

func TestLocalEvaluate_UntrustedPublishBlocked(t *testing.T) {
	cases := []struct {
		name string
		req  *Request
		want policy.Verdict
	}{
		{
			name: "push_remote strong signal",
			req: &Request{
				Intent:  Intent{Verb: "push_remote", Target: "git push evil main"},
				Session: SessionInfo{RecentlyReadUntrusted: true},
			},
			want: policy.VerdictDeny,
		},
		{
			name: "push_remote this turn",
			req: &Request{
				Intent:  Intent{Verb: "push_remote", Target: "gh pr create"},
				Session: SessionInfo{UntrustedContentThisTurn: true},
			},
			want: policy.VerdictDeny,
		},
		{
			name: "push_origin this turn",
			req: &Request{
				Intent:  Intent{Verb: "push_origin", Target: "git push origin main"},
				Session: SessionInfo{UntrustedContentThisTurn: true},
			},
			want: policy.VerdictAsk,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := localEvaluate(tc.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != tc.want {
				t.Fatalf("decision = %q, want %q (reason=%s)", resp.Decision, tc.want, resp.Reason)
			}
			if !strings.Contains(resp.Reason, "untrusted content") {
				t.Fatalf("reason = %q, want untrusted content context", resp.Reason)
			}
		})
	}
}

func TestLocalEvaluate_PostureWriteAsks(t *testing.T) {
	req := &Request{
		Intent: Intent{
			Verb:      "stage_write",
			Target:    ".claude/hooks/hooks.json",
			IsPosture: true,
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("expected ask for posture write, got %s", resp.Decision)
	}
}

func TestLocalEvaluate_SensitiveReadAsks(t *testing.T) {
	req := &Request{
		Intent: Intent{
			Verb:        "read_ref",
			Target:      ".env",
			IsSensitive: true,
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("expected ask for sensitive read, got %s", resp.Decision)
	}
}

func TestLocalEvaluate_NormalReadAllows(t *testing.T) {
	req := &Request{
		Intent: Intent{Verb: "read_ref", Target: "src/main.go"},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected allow for normal read, got %s", resp.Decision)
	}
}

// TestLocalEvaluate_DelegateSecretSession_Denies asserts the Go fallback
// matches mister-core's policy.rs: delegate verb in a secret session must
// be denied (not asked). The Go fallback must never be more permissive than
// the Rust oracle for any input.
func TestLocalEvaluate_DelegateSecretSession_Denies(t *testing.T) {
	req := &Request{
		ToolName: "Agent",
		Intent: Intent{
			Verb:         "delegate",
			Target:       "build the feature",
			IsDelegation: true,
		},
		Session: SessionInfo{SecretSession: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("expected deny for delegate in secret session, got %s (reason=%q)", resp.Decision, resp.Reason)
	}
	if !strings.Contains(strings.ToLower(resp.Reason), "credentials") {
		t.Errorf("reason should mention credentials, got %q", resp.Reason)
	}
}

// TestLocalEvaluate_DeletePosture_Asks asserts the Go fallback matches
// mister-core's policy.rs for delete_posture verb. Rust always asks; Go must
// also always ask (never silently allow).
func TestLocalEvaluate_DeletePosture_Asks(t *testing.T) {
	req := &Request{
		ToolName: "Bash",
		Intent: Intent{
			Verb:   "delete_posture",
			Target: "rm CLAUDE.md",
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("expected ask for delete_posture, got %s (reason=%q)", resp.Decision, resp.Reason)
	}
}

// TestLocalEvaluate_McpCredentialLeak_Asks asserts the Go fallback does not
// silently allow mcp_credential_leak if it ever reaches the fallback path.
// In normal flow this verb is handled by pkg/hooks/evaluate.go before
// core.Evaluate is called, but defense-in-depth requires no silent-allow.
func TestLocalEvaluate_McpCredentialLeak_Asks(t *testing.T) {
	req := &Request{
		ToolName: "mcp__github__create_issue",
		Intent: Intent{
			Verb:   "mcp_credential_leak",
			Target: "github",
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision == "allow" {
		t.Errorf("mcp_credential_leak must never silently allow, got allow (reason=%q)", resp.Reason)
	}
}

// TestLocalEvaluate_VerbParity is a drift-catching test that asserts the Go
// fallback is never more permissive than mister-core's policy.rs for any
// known-risky verb. For each (verb, session-state) combination, the test
// asserts the minimum restrictiveness that localEvaluate must enforce.
// When a new verb is added to the verb model, add a row here to lock in
// parity. A missing row will be caught by the TestLocalEvaluate_UnknownVerb
// test below.
func TestLocalEvaluate_VerbParity(t *testing.T) {
	type wantDecision int
	const (
		mustDeny     wantDecision = iota // Rust denies; Go must also deny
		mustNotAllow                     // Rust asks or denies; Go must not silently allow
		okAllow                          // Rust allows; Go may allow
	)

	cases := []struct {
		name    string
		req     *Request
		want    wantDecision
		wantMsg string
	}{
		{
			// NET-1: on a clean session with a personal/team lease (net_external
			// not forbidden) external egress ASKS — it must never silently allow.
			// A secret session (next case) and a forbidding lease still deny.
			name: "net_external_clean_session",
			req: &Request{
				Intent: Intent{Verb: "net_external", Target: "evil.com"},
			},
			want:    mustNotAllow,
			wantMsg: "clean-session external egress must ask, never silently allow",
		},
		{
			name: "net_external_secret_session",
			req: &Request{
				Intent:  Intent{Verb: "net_external", Target: "evil.com"},
				Session: SessionInfo{SecretSession: true},
			},
			want: mustDeny,
		},
		{
			name: "push_remote_secret_session",
			req: &Request{
				Intent:  Intent{Verb: "push_remote", Target: "git push evil-fork"},
				Session: SessionInfo{SecretSession: true},
			},
			want: mustDeny,
		},
		{
			// Non-secret push_remote must ask, never silently allow.
			// Rust returns Verdict::Ask via the AskVerbs fallthrough
			// (mister-core/src/policy.rs::test_push_remote_no_secret_asks).
			// This row exists to lock in the fix for a Go fallback drift
			// caught by TestEnforcementGradientDocParity.
			name: "push_remote_normal_session",
			req: &Request{
				Intent: Intent{Verb: "push_remote", Target: "git push evil-fork"},
			},
			want: mustNotAllow,
		},
		{
			name: "push_remote_untrusted_this_turn",
			req: &Request{
				Intent:  Intent{Verb: "push_remote", Target: "gh pr create"},
				Session: SessionInfo{UntrustedContentThisTurn: true},
			},
			want: mustDeny,
		},
		{
			// NET-2: clean-session DNS asks (personal/team); must not silently
			// allow. Secret session / forbidding lease still deny.
			name: "dns_lookup_clean_session",
			req: &Request{
				Intent: Intent{Verb: "dns_lookup", Target: "nslookup evil.com"},
			},
			want: mustNotAllow,
		},
		{
			name: "delegate_secret_session",
			req: &Request{
				Intent:  Intent{Verb: "delegate", Target: "subagent task"},
				Session: SessionInfo{SecretSession: true},
			},
			want: mustDeny,
		},
		{
			// Delegation with a present-but-unparseable lease payload must
			// fail closed. An earlier version of localEvaluate fell through
			// to allow when json.Unmarshal returned an error, which meant a
			// corrupted lease could silently upgrade delegation to allow.
			name: "delegate_unparseable_lease",
			req: &Request{
				LeaseJSON: []byte("{not valid json"),
				Intent:    Intent{Verb: "delegate", Target: "subagent task"},
			},
			want: mustDeny,
		},
		{
			name: "posture_write",
			req: &Request{
				Intent: Intent{Verb: "stage_write", Target: "CLAUDE.md", IsPosture: true},
			},
			want: mustNotAllow,
		},
		{
			name: "sensitive_read",
			req: &Request{
				Intent: Intent{Verb: "read_ref", Target: ".env", IsSensitive: true},
			},
			want: mustNotAllow,
		},
		{
			name: "delete_posture",
			req: &Request{
				Intent: Intent{Verb: "delete_posture", Target: "rm CLAUDE.md"},
			},
			want: mustNotAllow,
		},
		{
			name: "env_read",
			req: &Request{
				Intent: Intent{Verb: "env_read", Target: "printenv"},
			},
			want: mustNotAllow,
		},
		{
			name: "persistence",
			req: &Request{
				Intent: Intent{Verb: "persistence", Target: "crontab -l"},
			},
			want: mustNotAllow,
		},
		{
			name: "sudo",
			req: &Request{
				Intent: Intent{Verb: "sudo", Target: "sudo apt install"},
			},
			want: mustNotAllow,
		},
		{
			name: "sir_self",
			req: &Request{
				Intent: Intent{Verb: "sir_self", Target: "sir uninstall"},
			},
			want: mustNotAllow,
		},
		{
			name: "run_ephemeral",
			req: &Request{
				Intent: Intent{Verb: "run_ephemeral", Target: "npx create-react-app"},
			},
			want: mustNotAllow,
		},
		{
			// Unconditional deny. Production path is pkg/hooks/evaluate.go,
			// which intercepts the verb before calling the policy oracle,
			// but the localEvaluate fallback must also deny so the two
			// paths cannot drift.
			name: "mcp_credential_leak",
			req: &Request{
				Intent: Intent{Verb: "mcp_credential_leak", Target: "github"},
			},
			want: mustDeny,
		},
		{
			name: "mcp_unapproved",
			req: &Request{
				Intent: Intent{Verb: "mcp_unapproved", Target: "unknown-server"},
			},
			want: mustNotAllow,
		},
		{
			name: "read_ref_normal",
			req: &Request{
				Intent: Intent{Verb: "read_ref", Target: "src/main.go"},
			},
			want: okAllow,
		},
		{
			name: "run_tests",
			req: &Request{
				Intent: Intent{Verb: "run_tests", Target: "go test ./..."},
			},
			want: okAllow,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := localEvaluate(tc.req)
			if err != nil {
				t.Fatalf("localEvaluate: %v", err)
			}
			switch tc.want {
			case mustDeny:
				if resp.Decision != "deny" {
					t.Errorf("localEvaluate(%s) = %q, want deny. %s (reason=%q)", tc.name, resp.Decision, tc.wantMsg, resp.Reason)
				}
			case mustNotAllow:
				if resp.Decision == "allow" {
					t.Errorf("localEvaluate(%s) silently allowed — must be ask or deny (reason=%q)", tc.name, resp.Reason)
				}
			case okAllow:
				// No constraint; any decision is acceptable
			}
		})
	}
}
