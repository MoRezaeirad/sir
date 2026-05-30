package hooks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// seedLeaseBaseline writes lease.json and records its hash as the session
// baseline, so VerifyLeaseIntegrity is meaningful in the test.
func seedLeaseBaseline(t *testing.T, projectRoot string, l *lease.Lease, state *session.State) {
	t.Helper()
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	if err := os.MkdirAll(filepath.Dir(leasePath), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := l.Save(leasePath); err != nil {
		t.Fatalf("save lease: %v", err)
	}
	h, err := HashLease(projectRoot)
	if err != nil {
		t.Fatalf("hash lease: %v", err)
	}
	state.LeaseHash = h
	if err := state.Save(); err != nil {
		t.Fatalf("save state: %v", err)
	}
}

func bashCurl(url string) *PostHookPayload {
	return &PostHookPayload{ToolName: "Bash", ToolInput: map[string]interface{}{"command": "curl " + url}}
}

func TestAutoLease_MarkThenMintOnApproval(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease() // AutoLeaseApprovedHosts is true by default
	state := newTestSession(t, projectRoot)
	seedLeaseBaseline(t, projectRoot, l, state)

	intent := MapToolToIntent("Bash", map[string]interface{}{"command": "curl https://api.example.com/x"}, l)

	// Simulate the PreToolUse ask marking the host pending.
	maybeMarkAutoLeasePending(l, state, intent, policy.VerdictAsk)
	if _, ok := state.PendingAutoLeaseHosts["api.example.com"]; !ok {
		t.Fatalf("expected pending auto-lease marker, got %v", state.PendingAutoLeaseHosts)
	}

	// PostToolUse: the same egress executed, meaning the developer approved it.
	if !applyAutoLeaseOnApproval(bashCurl("https://api.example.com/x"), l, state, projectRoot, nil) {
		t.Fatal("expected auto-lease to mint after observed approval")
	}
	if !l.IsApprovedHost("api.example.com") {
		t.Errorf("host not added to lease: %+v", l.ApprovedHosts)
	}
	if _, ok := l.ApprovedHostExpires["api.example.com"]; !ok {
		t.Errorf("expected a TTL on the auto-lease, got %v", l.ApprovedHostExpires)
	}
	// The crucial invariant: the session lease-integrity baseline was refreshed,
	// so the next call does not fail closed.
	if !VerifyLeaseIntegrity(projectRoot, state) {
		t.Error("lease integrity broken after auto-lease — next call would deny-all")
	}
	// Marker consumed.
	if _, ok := state.PendingAutoLeaseHosts["api.example.com"]; ok {
		t.Error("pending marker should be consumed after minting")
	}
}

func TestAutoLease_NoMintWithoutPendingMarker(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)
	seedLeaseBaseline(t, projectRoot, l, state)

	// No prior ask/marker: an executed egress must not mint a lease.
	if applyAutoLeaseOnApproval(bashCurl("https://api.example.com/x"), l, state, projectRoot, nil) {
		t.Fatal("must not auto-lease without an observed approval marker")
	}
	if l.IsApprovedHost("api.example.com") {
		t.Error("host should not be leased without a marker")
	}
}

func TestAutoLease_DisabledByLease(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.AutoLeaseApprovedHosts = false
	state := newTestSession(t, projectRoot)
	seedLeaseBaseline(t, projectRoot, l, state)

	intent := MapToolToIntent("Bash", map[string]interface{}{"command": "curl https://api.example.com/x"}, l)
	maybeMarkAutoLeasePending(l, state, intent, policy.VerdictAsk)
	if len(state.PendingAutoLeaseHosts) != 0 {
		t.Fatal("disabled lease must not mark pending hosts")
	}
	if applyAutoLeaseOnApproval(bashCurl("https://api.example.com/x"), l, state, projectRoot, nil) {
		t.Fatal("disabled lease must not auto-lease")
	}
}

func TestAutoLease_NeverUnderSecretSession(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)
	seedLeaseBaseline(t, projectRoot, l, state)
	state.MarkSecretSession()

	intent := MapToolToIntent("Bash", map[string]interface{}{"command": "curl https://api.example.com/x"}, l)
	maybeMarkAutoLeasePending(l, state, intent, policy.VerdictAsk)
	if len(state.PendingAutoLeaseHosts) != 0 {
		t.Fatal("secret session must not mark pending hosts")
	}
	// Even if a marker somehow existed, minting must refuse under secret session.
	state.MarkPendingAutoLease("api.example.com")
	if applyAutoLeaseOnApproval(bashCurl("https://api.example.com/x"), l, state, projectRoot, nil) {
		t.Fatal("must not auto-lease while the session carries secret context")
	}
}

// TestAutoLeaseSafeContext_FalseUnderUntrustedContent locks the P1 review fix:
// untrusted content in the turn/session is not a safe context, so the
// NETALLOW-1 / REMOTE-1 / NPX-1 / ENV-1 reuse paths cannot silently downgrade an
// approval to allow — closing the same-turn untrusted-content-to-approved-host
// exfiltration path that the integrity-flow wall (net_external/dns only) misses.
func TestAutoLeaseSafeContext_FalseUnderUntrustedContent(t *testing.T) {
	clean := session.NewState(t.TempDir())
	if !autoLeaseSafeContext(clean) {
		t.Fatal("a clean session should be a safe context")
	}

	turn := session.NewState(t.TempDir())
	turn.MarkUntrustedContentThisTurn()
	if autoLeaseSafeContext(turn) {
		t.Error("turn-scoped untrusted content must NOT be a safe context")
	}

	sessionScoped := session.NewState(t.TempDir())
	sessionScoped.MarkUntrustedRead()
	if autoLeaseSafeContext(sessionScoped) {
		t.Error("session-scoped untrusted read must NOT be a safe context")
	}
}

// TestAutoLease_PostEvaluateWiring proves the PostToolUse handler actually
// invokes the auto-lease path: with a pending marker set, a clean executed
// egress mints the lease through the real postEvaluatePayload.
func TestAutoLease_PostEvaluateWiring(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)
	seedLeaseBaseline(t, projectRoot, l, state)
	state.MarkPendingAutoLease("api.demo.example")
	if err := state.Save(); err != nil { // persist marker + refresh integrity hash, as PreToolUse does
		t.Fatalf("save state: %v", err)
	}

	// WebFetch (not Bash) so the test does not exercise the Bash hook-integrity
	// drift path, which has no baseline in a bare temp project.
	post := &PostHookPayload{ToolName: "WebFetch", ToolInput: map[string]interface{}{"url": "https://api.demo.example/x"}, CWD: projectRoot}
	if _, err := postEvaluatePayload(post, l, state, projectRoot); err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}
	if !l.IsApprovedHost("api.demo.example") {
		t.Errorf("PostToolUse did not auto-lease the approved host: %+v", l.ApprovedHosts)
	}
	if !VerifyLeaseIntegrity(projectRoot, state) {
		t.Error("lease integrity broken after PostToolUse auto-lease")
	}
}

func TestAutoLease_StaleMarkerNotConsumed(t *testing.T) {
	state := session.NewState(t.TempDir())
	state.MarkPendingAutoLease("h.example")
	// Backdate the marker beyond the window.
	state.PendingAutoLeaseHosts["h.example"] = state.PendingAutoLeaseHosts["h.example"].Add(-time.Hour)
	if state.ConsumePendingAutoLease("h.example") {
		t.Error("stale marker should not be consumable")
	}
	if state.ConsumePendingAutoLease("never.marked") {
		t.Error("unmarked host should not be consumable")
	}
}
