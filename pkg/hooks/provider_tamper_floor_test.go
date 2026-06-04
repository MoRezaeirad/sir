package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	providerreg "github.com/somoore/sir/pkg/provider"
)

// O3 regression: an injected agent must NOT be able to self-amplify by promoting
// a provider to authoritative (or otherwise mutating the provider registry)
// through the sir binary. `sir provider authoritative` is a NON-DELEGABLE floor:
// it short-circuits before evaluatePolicy, so it holds even when an active
// authoritative provider would otherwise grant everything. This is the boundary
// that keeps "delegated PDP" from becoming "seized PDP".

func TestProviderMutation_IsNonDelegableFloor_UnderPermissiveAuthoritative(t *testing.T) {
	// Active authoritative provider that GRANTS everything (allow).
	withProviderRegistry(t, authReg())
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return []policy.PolicyVerdict{{Provider: "auth-opa", Verdict: "allow"}}, nil
	})

	projectRoot := t.TempDir()
	state := newTestSession(t, projectRoot)
	l := lease.DefaultLease()

	// Agent tries to promote a (hypothetical attacker-controlled) provider.
	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "sir provider authoritative evil --yes"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision == policy.VerdictAllow {
		t.Fatalf("O3 VIOLATION: agent self-promotion of a provider was ALLOWED under an authoritative provider — registry mutation must be a non-delegable floor (%+v)", resp)
	}
	// Assert it is specifically the sir-self floor (ask), not some unrelated deny —
	// so this can't silently pass via a different gate.
	if resp.Decision != policy.VerdictAsk {
		t.Fatalf("expected the sir-self floor (ask), got %q (%s)", resp.Decision, resp.Reason)
	}
}

// The same floor must hold with NO provider configured (it is not a
// provider-specific behavior — sir self-modification is always gated).
func TestProviderMutation_GatedWithNoProvider(t *testing.T) {
	projectRoot := t.TempDir()
	state := newTestSession(t, projectRoot)
	l := lease.DefaultLease()

	for _, cmd := range []string{
		"sir provider authoritative evil --yes",
		"sir provider use evil",
		"sir provider swap good evil",
		"sir provider enable evil",
	} {
		resp, err := evaluatePayload(&HookPayload{
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{"command": cmd},
			CWD:       projectRoot,
		}, l, state, projectRoot)
		if err != nil {
			t.Fatalf("evaluatePayload(%q): %v", cmd, err)
		}
		if resp.Decision == policy.VerdictAllow {
			t.Fatalf("provider-mutation command %q must be gated (ask/deny), got allow", cmd)
		}
	}
}

// Read-only provider subcommands are NOT gated — they don't change posture.
func TestProviderReadOnly_NotGated(t *testing.T) {
	projectRoot := t.TempDir()
	state := newTestSession(t, projectRoot)
	l := lease.DefaultLease()

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "sir provider list"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != policy.VerdictAllow {
		t.Fatalf("read-only `sir provider list` should not be gated, got %q", resp.Decision)
	}
}
