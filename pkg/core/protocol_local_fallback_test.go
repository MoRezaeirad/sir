package core

import (
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

func TestLocalEvaluate_EnvRead_Ask(t *testing.T) {
	// env_read must be "ask", never silently allowed.
	req := &Request{
		Intent: Intent{Verb: "env_read", Target: "env"},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("env_read: decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_Persistence_Ask(t *testing.T) {
	// persistence must be "ask", never silently allowed.
	req := &Request{
		Intent: Intent{Verb: "persistence", Target: "crontab -e"},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("persistence: decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_Sudo_Ask(t *testing.T) {
	// sudo must be "ask", never silently allowed.
	req := &Request{
		Intent: Intent{Verb: "sudo", Target: "sudo rm -rf /"},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("sudo: decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_DNSLookup_Gradient(t *testing.T) {
	// NET-2 gradient: clean + not forbidden (personal/team) -> ask; forbidden
	// (strict/managed) -> deny; secret session -> deny.
	clean := &Request{Intent: Intent{Verb: "dns_lookup", Target: "nslookup evil.com"}}
	if resp, _ := localEvaluate(clean); resp.Decision != "ask" {
		t.Errorf("dns_lookup clean: decision = %q, want ask", resp.Decision)
	}
	forbidden := &Request{
		Intent:    Intent{Verb: "dns_lookup", Target: "nslookup evil.com"},
		LeaseJSON: []byte(`{"forbidden_verbs":["dns_lookup"]}`),
	}
	if resp, _ := localEvaluate(forbidden); resp.Decision != "deny" {
		t.Errorf("dns_lookup forbidden: decision = %q, want deny", resp.Decision)
	}
	secret := &Request{
		Intent:  Intent{Verb: "dns_lookup", Target: "nslookup evil.com"},
		Session: SessionInfo{SecretSession: true},
	}
	if resp, _ := localEvaluate(secret); resp.Decision != "deny" {
		t.Errorf("dns_lookup secret: decision = %q, want deny", resp.Decision)
	}
}

func TestLocalEvaluate_MCPUnapproved_Ask(t *testing.T) {
	req := &Request{
		Intent: Intent{Verb: "mcp_unapproved", Target: "mcp__evil_server__do_thing"},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("mcp_unapproved: decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_SirSelf_Ask(t *testing.T) {
	req := &Request{
		Intent: Intent{Verb: "sir_self", Target: "sir uninstall"},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("sir_self: decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_RunEphemeral_Ask(t *testing.T) {
	req := &Request{
		Intent: Intent{Verb: "run_ephemeral", Target: "npx create-react-app"},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("run_ephemeral: decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_NetAllowlisted_Ask(t *testing.T) {
	req := &Request{
		Intent: Intent{Verb: "net_allowlisted", Target: "api.example.com"},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("net_allowlisted: decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_NetExternal_NoSecret_Asks(t *testing.T) {
	// NET-1: on a clean session with a personal/team lease (net_external NOT
	// forbidden) external egress is an approval prompt, not a hard block — there
	// is no secret to exfiltrate. A forbidding lease (strict/managed) still
	// denies.
	clean := &Request{
		Intent:  Intent{Verb: "net_external", Target: "example.com"},
		Session: SessionInfo{SecretSession: false},
	}
	if resp, _ := localEvaluate(clean); resp.Decision != "ask" {
		t.Errorf("net_external (clean, not forbidden): decision = %q, want ask", resp.Decision)
	}
	forbidden := &Request{
		Intent:    Intent{Verb: "net_external", Target: "example.com"},
		LeaseJSON: []byte(`{"forbidden_verbs":["net_external"]}`),
	}
	if resp, _ := localEvaluate(forbidden); resp.Decision != "deny" {
		t.Errorf("net_external (forbidden): decision = %q, want deny", resp.Decision)
	}
}

func TestLocalEvaluate_NetExternal_FailsClosedOnMalformedLease(t *testing.T) {
	// A lease whose forbidden_verbs cannot be parsed structurally must DENY
	// net_external (fail closed) — a corrupted/tampered lease must never silently
	// downgrade the hard egress deny to an ask on the degraded fallback path.
	for _, bad := range [][]byte{
		[]byte(`{"forbidden_verbs": [ not json`),
		[]byte(`{"forbidden_verbs": "net_external"}`), // wrong type
		[]byte(`}{`),
	} {
		req := &Request{
			Intent:    Intent{Verb: "net_external", Target: "example.com"},
			LeaseJSON: bad,
		}
		if resp, _ := localEvaluate(req); resp.Decision != "deny" {
			t.Errorf("malformed lease %q: net_external must fail closed to deny, got %q", bad, resp.Decision)
		}
	}
}

func TestLocalEvaluate_NetExternal_ForbiddenKeyIsStructural(t *testing.T) {
	// "forbidden_verbs" text inside another field's VALUE must not be mistaken
	// for the forbidden set; the real (empty) forbidden_verbs key governs -> ask.
	req := &Request{
		Intent:    Intent{Verb: "net_external", Target: "example.com"},
		LeaseJSON: []byte(`{"mission":"\"forbidden_verbs\":[\"net_external\"]","forbidden_verbs":[]}`),
	}
	if resp, _ := localEvaluate(req); resp.Decision != "ask" {
		t.Errorf("structural key match: empty real forbidden_verbs should ask, got %q", resp.Decision)
	}
}

func TestLocalEvaluate_NetExternal_WithSecret_Deny(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "net_external", Target: "evil.com"},
		Session: SessionInfo{SecretSession: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("net_external (secret): decision = %q, want deny", resp.Decision)
	}
}

func TestLocalEvaluate_PushRemote_WithSecret_Deny(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "push_remote", Target: "evil-remote"},
		Session: SessionInfo{SecretSession: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("push_remote (secret): decision = %q, want deny", resp.Decision)
	}
}

func TestLocalEvaluate_PushOrigin_WithSecret_Ask(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "push_origin", Target: "origin"},
		Session: SessionInfo{SecretSession: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("push_origin (secret): decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_PushOrigin_NoSecret_Allow(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "push_origin", Target: "origin"},
		Session: SessionInfo{SecretSession: false},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("push_origin (no secret): decision = %q, want allow", resp.Decision)
	}
}

func TestLocalEvaluate_PolicyVerdictEscalatesCleanPush(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "push_origin", Target: "origin"},
		Session: SessionInfo{SecretSession: false},
		PolicyVerdicts: []policy.PolicyVerdict{
			{Provider: "opa-bridge", Verdict: "deny", RulesMatched: []string{"deny-all-push"}, IsAdvisory: true},
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("provider deny on clean push should escalate allow to ask, got %q", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "policy:opa-bridge") {
		t.Errorf("provider attribution missing from reason: %q", resp.Reason)
	}
}

func TestLocalEvaluate_PolicyVerdictCannotOverrideCleanCommitFloor(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "commit", Target: "git commit -m test"},
		Session: SessionInfo{SecretSession: false},
		PolicyVerdicts: []policy.PolicyVerdict{
			{Provider: "opa-bridge", Verdict: "deny", RulesMatched: []string{"deny-all-commit"}, IsAdvisory: true},
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("clean commit floor should suppress provider deny, got %q", resp.Decision)
	}
}

func TestLocalEvaluate_PolicyVerdictCannotLowerNativeDeny(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "net_external", Target: "https://example.com"},
		Session: SessionInfo{SecretSession: true},
		PolicyVerdicts: []policy.PolicyVerdict{
			{Provider: "opa-bridge", Verdict: "allow", RulesMatched: []string{"allow-all"}, IsAdvisory: true},
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("provider allow must not lower native deny, got %q", resp.Decision)
	}
}

// TestLocalEvaluate_PushOrigin_WasSecret_Ask locks in the monotonic high-water
// mark in the Go fallback: the turn-scoped secret flag has cleared
// (SecretSession=false) but the session held a secret earlier this session
// (WasSecret=true). A truly clean session would silently allow push_origin; the
// high-water mark must downgrade that to an approval prompt, mirroring the
// oracle (see mister-core/src/policy.rs test_push_origin_was_secret_asks).
func TestLocalEvaluate_PushOrigin_WasSecret_Ask(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "push_origin", Target: "origin"},
		Session: SessionInfo{SecretSession: false, WasSecret: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("push_origin (was-secret): decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_PushAfterUntrusted(t *testing.T) {
	remote := &Request{
		Intent:  Intent{Verb: "push_remote", Target: "gh pr create"},
		Session: SessionInfo{UntrustedContentThisTurn: true},
	}
	if resp, _ := localEvaluate(remote); resp.Decision != "deny" {
		t.Fatalf("push_remote after untrusted content = %q, want deny (reason=%s)", resp.Decision, resp.Reason)
	}

	origin := &Request{
		Intent:  Intent{Verb: "push_origin", Target: "git push origin main"},
		Session: SessionInfo{UntrustedContentThisTurn: true},
	}
	if resp, _ := localEvaluate(origin); resp.Decision != "ask" {
		t.Fatalf("push_origin after untrusted content = %q, want ask (reason=%s)", resp.Decision, resp.Reason)
	}
}

// TestEncodeMSTR1_CarriesWasSecret confirms the high-water mark is serialized
// onto the wire as session_was_secret so the oracle can act on it.
func TestEncodeMSTR1_CarriesWasSecret(t *testing.T) {
	req := &Request{
		ToolName: "Bash",
		Intent:   Intent{Verb: "push_origin", Target: "origin"},
		Session:  SessionInfo{WasSecret: true},
	}
	wire := buildWireEvalRequest(req)
	if !wire.SessionWasSecret {
		t.Error("buildWireEvalRequest must carry WasSecret as session_was_secret")
	}
}

func TestLocalEvaluate_Delegate_WithSecret_Deny(t *testing.T) {
	// Secret session: deny (parity with mister-core policy.rs).
	// The Go fallback must never be more permissive than Rust.
	req := &Request{
		Intent:  Intent{Verb: "delegate", Target: "sub-agent task"},
		Session: SessionInfo{SecretSession: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("delegate (secret): decision = %q, want deny", resp.Decision)
	}
}

func TestLocalEvaluate_Delegate_AfterUntrusted_Ask(t *testing.T) {
	req := &Request{
		Intent:  Intent{Verb: "delegate", Target: "sub-agent task"},
		Session: SessionInfo{RecentlyReadUntrusted: true},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("delegate (untrusted read): decision = %q, want ask", resp.Decision)
	}
}

func TestLocalEvaluate_Delegate_Clean_Allow(t *testing.T) {
	// Delegation with AllowDelegation=true (default): allow in clean session
	leaseJSON := []byte(`{"allow_delegation": true}`)
	req := &Request{
		Intent:    Intent{Verb: "delegate", Target: "sub-agent task"},
		LeaseJSON: leaseJSON,
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("delegate (clean, AllowDelegation=true): decision = %q, want allow", resp.Decision)
	}
}

func TestLocalEvaluate_Delegate_LeaseDisabled_Deny(t *testing.T) {
	// Delegation explicitly disabled by lease
	leaseJSON := []byte(`{"allow_delegation": false}`)
	req := &Request{
		Intent:    Intent{Verb: "delegate", Target: "sub-agent task"},
		LeaseJSON: leaseJSON,
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("delegate (AllowDelegation=false): decision = %q, want deny", resp.Decision)
	}
}

// Silent-allow verbs: standard dev operations that should pass through
func TestLocalEvaluate_SilentAllowVerbs(t *testing.T) {
	silentVerbs := []struct {
		verb   policy.Verb
		target string
	}{
		{policy.VerbExecuteDryRun, "ls -la"},
		{policy.VerbRunTests, "go test ./..."},
		{policy.VerbCommit, "git commit -m 'test'"},
		{policy.VerbListFiles, "*.go"},
		{policy.VerbSearchCode, "func main"},
		{policy.VerbReadRef, "src/main.go"},
		{policy.VerbStageWrite, "src/output.go"},
		{policy.VerbNetLocal, "http://localhost"},
	}

	for _, tc := range silentVerbs {
		t.Run(string(tc.verb), func(t *testing.T) {
			req := &Request{
				Intent: Intent{Verb: tc.verb, Target: tc.target},
			}
			resp, err := localEvaluate(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != policy.VerdictAllow {
				t.Errorf("%s: decision = %q, want allow", tc.verb, resp.Decision)
			}
		})
	}
}

// DenyAll overrides everything
func TestLocalEvaluate_DenyAll_OverridesEverything(t *testing.T) {
	verbs := []policy.Verb{
		policy.VerbReadRef,
		policy.VerbStageWrite,
		policy.VerbExecuteDryRun,
		policy.VerbNetLocal,
		policy.VerbEnvRead,
		policy.VerbPersistence,
		policy.VerbSudo,
		policy.VerbRunEphemeral,
	}

	for _, verb := range verbs {
		t.Run(string(verb), func(t *testing.T) {
			req := &Request{
				Intent:  Intent{Verb: verb, Target: "anything"},
				Session: SessionInfo{DenyAll: true},
			}
			resp, err := localEvaluate(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Decision != policy.VerdictDeny {
				t.Errorf("deny_all + %s: decision = %q, want deny", verb, resp.Decision)
			}
		})
	}
}

// A git-hook write classified as posture must ask in the production fallback
// engine — proving the floor fires through core.Evaluate, not only the harness
// kernel. (IsPosture is set upstream by classify.IsPostureFile; see
// pkg/hooks.TestIsPostureFile for the classification link.)
func TestLocalEvaluate_GitHookWrite_Asks(t *testing.T) {
	req := &Request{
		Intent: Intent{
			Verb:      "stage_write",
			Target:    ".git/hooks/pre-commit",
			IsPosture: true,
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("git-hook write: decision = %q, want ask", resp.Decision)
	}
}

// Posture write + non-write verb = should NOT ask
func TestLocalEvaluate_PostureFile_ReadVerb_Allow(t *testing.T) {
	req := &Request{
		Intent: Intent{
			Verb:      "read_ref",
			Target:    ".claude/hooks/hooks.json",
			IsPosture: true,
		},
	}
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("posture read: decision = %q, want allow", resp.Decision)
	}
}

// ---------------------------------------------------------------------------
// Error Handling: Binary Not Found
// ---------------------------------------------------------------------------

func TestEvaluate_BinaryNotFound_FallsBackToLocal(t *testing.T) {
	// Set binary path to something that doesn't exist
	oldPath := CoreBinaryPath
	CoreBinaryPath = "/nonexistent/mister-core-does-not-exist"
	defer func() { CoreBinaryPath = oldPath }()

	req := &Request{
		ToolName: "Read",
		Intent: Intent{
			Verb:        "read_ref",
			Target:      ".env",
			IsSensitive: true,
		},
	}

	resp, err := Evaluate(req)
	if err != nil {
		t.Fatalf("Evaluate should not error (should fallback): %v", err)
	}
	// Fallback should produce "ask" for sensitive read
	if resp.Decision != "ask" {
		t.Errorf("fallback for sensitive read: decision = %q, want ask", resp.Decision)
	}
}

func TestEvaluate_BinaryNotFound_DenyAllStillWorks(t *testing.T) {
	oldPath := CoreBinaryPath
	CoreBinaryPath = "/nonexistent/mister-core-does-not-exist"
	defer func() { CoreBinaryPath = oldPath }()

	req := &Request{
		Intent:  Intent{Verb: "read_ref", Target: "anything"},
		Session: SessionInfo{DenyAll: true},
	}

	resp, err := Evaluate(req)
	if err != nil {
		t.Fatalf("Evaluate should not error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("fallback deny_all: decision = %q, want deny", resp.Decision)
	}
}

func TestEvaluate_BinaryNotFound_SecretEgressBlocked(t *testing.T) {
	oldPath := CoreBinaryPath
	CoreBinaryPath = "/nonexistent/mister-core-does-not-exist"
	defer func() { CoreBinaryPath = oldPath }()

	req := &Request{
		Intent:  Intent{Verb: "net_external", Target: "evil.com"},
		Session: SessionInfo{SecretSession: true},
	}

	resp, err := Evaluate(req)
	if err != nil {
		t.Fatalf("Evaluate should not error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("fallback secret + egress: decision = %q, want deny", resp.Decision)
	}
}

// ---------------------------------------------------------------------------
// Error Handling: Malformed Responses
// ---------------------------------------------------------------------------

func TestDecodeMSTR1Response_EmptyBuffer(t *testing.T) {
	_, err := decodeMSTR1Response([]byte{})
	if err == nil {
		t.Fatal("expected error for empty buffer")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("error should mention 'too short': %v", err)
	}
}

func TestDecodeMSTR1Response_OnlyMagic(t *testing.T) {
	_, err := decodeMSTR1Response([]byte("MSTR"))
	if err == nil {
		t.Fatal("expected error for only-magic buffer")
	}
}

func TestDecodeMSTR1Response_MissingPayload(t *testing.T) {
	// Header says 100 bytes but there are 0 payload bytes
	buf := []byte("MSTR\x01\x00\x00\x00\x64") // length = 100
	_, err := decodeMSTR1Response(buf)
	if err == nil {
		t.Fatal("expected error for missing payload")
	}
}

func TestDecodeMSTR1Response_UnknownFields(t *testing.T) {
	// Response with extra unknown fields should still decode
	payload := `{"verdict":"allow","reason":"ok","unknown_field":"should_be_ignored","extra":123}`
	buf := buildMSTR1Response(t, payload)
	resp, err := decodeMSTR1Response(buf)
	if err != nil {
		t.Fatalf("should decode despite extra fields: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("decision = %q, want allow", resp.Decision)
	}
}

func TestDecodeMSTR1Response_NullValues(t *testing.T) {
	payload := `{"verdict":null,"reason":null}`
	buf := buildMSTR1Response(t, payload)
	resp, err := decodeMSTR1Response(buf)
	if err != nil {
		t.Fatalf("should decode null values: %v", err)
	}
	// Null JSON values decode to Go zero values
	if resp.Decision != "" {
		t.Errorf("decision = %q, want empty", resp.Decision)
	}
}

func TestDecodeMSTR1Response_EmptyJSON(t *testing.T) {
	payload := `{}`
	buf := buildMSTR1Response(t, payload)
	resp, err := decodeMSTR1Response(buf)
	if err != nil {
		t.Fatalf("should decode empty object: %v", err)
	}
	if resp.Decision != "" {
		t.Errorf("decision = %q, want empty", resp.Decision)
	}
}
