package provider

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

// These tests pin the policy-request WIRE CONTRACT as actually sent by
// InvokePolicy (not a handwritten literal). Two guarantees:
//
//  1. BACKWARD COMPATIBILITY: the schema_version string stays
//     "sir.policy_request.v0". The PDP work adds new session/integrity fields,
//     but they are ADDITIVE and omitempty — bumping the version string would
//     break strict v0 providers (the bundled packs advertise
//     schema_version_supported: sir.policy_request.v0), whose verdicts would then
//     vanish and silently stop advisory escalation. This is the regression guard
//     for that exact break.
//  2. The new session/integrity signals are carried when set and omitted when
//     false, so v1-aware providers detect them by presence and v0 providers see
//     no new keys on a clean session.

func captureProviderRequest(t *testing.T, req policy.PolicyRequest) map[string]any {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	capPath := filepath.Join(t.TempDir(), "request.json")
	t.Setenv("SIR_PROVIDER_TEST_HELPER", "1")
	t.Setenv("SIR_PROVIDER_TEST_CAPTURE", capPath)
	t.Setenv("SIR_PROVIDER_TEST_STDOUT", "") // empty stdout => quiet/no verdict, fine here
	t.Setenv("SIR_PROVIDER_TEST_STDERR", "")
	entry := Entry{Name: "capture-provider", Entrypoint: exe}

	if _, err := InvokePolicy(entry, req); err != nil {
		t.Fatalf("InvokePolicy: %v", err)
	}
	data, err := os.ReadFile(capPath)
	if err != nil {
		t.Fatalf("read captured request: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal captured request: %v\nraw: %s", err, data)
	}
	return got
}

func TestInvokePolicy_SchemaVersionStaysV0(t *testing.T) {
	got := captureProviderRequest(t, policy.PolicyRequest{Action: "commit"})
	if sv, _ := got["schema_version"].(string); sv != "sir.policy_request.v0" {
		t.Fatalf("schema_version = %q, want %q (bumping it breaks strict v0 providers)",
			sv, "sir.policy_request.v0")
	}
}

func TestInvokePolicy_CleanSessionOmitsNewSignals(t *testing.T) {
	got := captureProviderRequest(t, policy.PolicyRequest{Action: "commit"})
	for _, key := range []string{
		"session_secret", "session_was_secret",
		"session_untrusted_read", "session_untrusted_this_turn",
	} {
		if _, present := got[key]; present {
			t.Errorf("clean-session request should omit %q (omitempty); a v0 provider must see no new keys", key)
		}
	}
}

func TestInvokePolicy_CarriesSessionSignalsWhenSet(t *testing.T) {
	got := captureProviderRequest(t, policy.PolicyRequest{
		Action:                   "net_external",
		SessionSecret:            true,
		SessionWasSecret:         true,
		SessionUntrustedRead:     true,
		SessionUntrustedThisTurn: true,
	})
	for _, key := range []string{
		"session_secret", "session_was_secret",
		"session_untrusted_read", "session_untrusted_this_turn",
	} {
		v, present := got[key]
		if !present {
			t.Errorf("request missing %q when set", key)
			continue
		}
		if b, _ := v.(bool); !b {
			t.Errorf("request %q = %v, want true", key, v)
		}
	}
}
