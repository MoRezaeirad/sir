package hooks

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	providerreg "github.com/somoore/sir/pkg/provider"
	"github.com/somoore/sir/pkg/session"
)

// Regression tests for two fail-open holes a reviewer (Codex P1) caught in the
// authoritative override, plus an observe-mode one found during the fix:
//   P1#1 — an authoritative/fail-closed ASK was silently downgraded to ALLOW by
//          later native convenience rules (SilentApprovedHosts etc.) and by
//          observe mode. Sealed via coreResp.AuthoritativeActive.
//   P1#2 — a CORRUPT provider registry was treated like "no provider" → native
//          governs → fail-open. Now fails closed (vs. a MISSING file, which is
//          a nil error and proceeds to native).

// resetRegistryCache clears the sync.Once-cached registry between tests.
func resetRegistryCache() {
	providerRegistryOnce = sync.Once{}
	providerRegistryVal = nil
	providerRegistryErr = nil
}

// --- P1#1: authoritative ASK must survive the native convenience downgrades ---

func TestAuthoritativeAsk_NotDowngradedBySilentApprovedHosts(t *testing.T) {
	withProviderRegistry(t, authReg())
	// Authoritative provider returns ASK on an allowlisted host.
	stubPolicyProviderInvocation(t, func(providerreg.Entry, policy.PolicyRequest) ([]policy.PolicyVerdict, error) {
		return []policy.PolicyVerdict{{Provider: "auth-opa", Verdict: "ask"}}, nil
	})

	projectRoot := t.TempDir()
	st := session.NewState(projectRoot)
	// Clean context + SilentApprovedHosts on: exactly the conditions under which
	// net_allowlisted ask→allow would normally fire.
	l := lease.DefaultLease()
	l.SilentApprovedHosts = true

	resp, err := evaluatePayload(
		&HookPayload{ToolName: "Bash"},
		l, st, projectRoot,
	)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	// Map to net_allowlisted by target would require classification; instead we
	// assert the sealed verdict directly: an authoritative ask must never be allow.
	if resp.Decision == policy.VerdictAllow {
		t.Fatalf("FAIL-OPEN: authoritative ask was downgraded to allow (%+v)", resp)
	}
}

// Direct, classification-independent proof of the seal: applyCoreEvaluationResult
// marks an authoritative verdict as Floor so observe mode cannot downgrade it.
func TestAuthoritativeVerdict_MarkedFloor_ObserveCannotDowngrade(t *testing.T) {
	st := session.NewState(t.TempDir())
	coreResp := &core.Response{
		Decision:              policy.VerdictDeny,
		AuthoritativeActive:   true,
		AuthoritativeProvider: "auth-opa",
	}
	hookResp := applyCoreEvaluationResult(coreResp, Intent{Verb: policy.VerbNetExternal}, core.Label{}, st, nil)
	if !hookResp.Floor {
		t.Fatal("authoritative verdict must be marked Floor so observe mode cannot downgrade it")
	}
	// Prove observe-mode downgrade is now a no-op on it.
	applyObserveMode(hookResp)
	if hookResp.Decision != policy.VerdictDeny {
		t.Fatalf("observe mode downgraded an authoritative deny to %q — fail-open", hookResp.Decision)
	}
}

// --- P1#2: corrupt registry fails closed; missing registry proceeds to native ---

func TestCorruptRegistry_FailsClosed(t *testing.T) {
	resetRegistryCache()
	t.Cleanup(resetRegistryCache)
	home := t.TempDir()
	t.Setenv("HOME", home)
	sirDir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(sirDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Corrupt (unparseable) providers.json.
	if err := os.WriteFile(filepath.Join(sirDir, "providers.json"), []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadProviderRegistryChecked()
	if err == nil {
		t.Fatal("corrupt registry must return a non-nil load error (so the PDP path can fail closed)")
	}
}

func TestMissingRegistry_NoError_ProceedsToNative(t *testing.T) {
	resetRegistryCache()
	t.Cleanup(resetRegistryCache)
	home := t.TempDir() // no .sir/providers.json at all
	t.Setenv("HOME", home)

	reg, err := loadProviderRegistryChecked()
	if err != nil {
		t.Fatalf("a MISSING registry file must be a nil error (proceeds to native), got %v", err)
	}
	if reg == nil {
		t.Fatal("missing registry should yield an empty (non-nil) registry")
	}
	if _, ok := activeAuthoritativePolicyProvider(reg); ok {
		t.Fatal("missing registry has no authoritative provider")
	}
}
