package hooks

import (
	"testing"
	"time"

	"github.com/somoore/sir/pkg/lease"
)

// MCPQUIET-1 tests. On a clean session, the two MCP asks the code documents as
// "friction, not containment" (mcp_onboarding and mcp_network_unapproved) are
// silenced when QuietMCPFriction is on — but ONLY on a clean, untainted session,
// and never the real gates (mcp_unapproved, mcp_binary_drift). These pin the
// safe-subset reduction and, crucially, its safety boundaries.

// scopedServer makes a server NON-heightened by giving it a capability scope,
// so the plain (friction-only) onboarding path is exercised rather than the
// heightened first-call-exfil checkpoint.
func scopeFor(l *lease.Lease, server string) {
	l.MCPCapabilityScopes = append(l.MCPCapabilityScopes, lease.MCPCapabilityScope{Server: server})
}

func TestMCPQuiet1_OnboardingSilencedOnCleanSession(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	writeOnboardingConfig(t, home, 24, 20)
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-1*time.Hour))
	scopeFor(l, "fresh") // scoped → not heightened → plain onboarding friction
	// DefaultLease (via seedApprovedLease) has QuietMCPFriction=true.
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("plain onboarding ask should be silenced on a clean scoped session (QuietMCPFriction), got %q (reason=%s)",
			resp.Decision, resp.Reason)
	}
}

// The HEIGHTENED onboarding floor (no capability scope = unfamiliar server) is a
// real first-call checkpoint, NOT pure friction — MCPQUIET-1 must preserve it.
func TestMCPQuiet1_HeightenedOnboardingStillAsks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	writeOnboardingConfig(t, home, 24, 20)
	l := seedApprovedLease(t, projectRoot, "noscope", time.Now().Add(-1*time.Hour))
	// No capability scope → heightened → must still ask even with QuietMCPFriction.
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__noscope__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("heightened onboarding (no scope) is the first-call checkpoint and must still ask, got %q", resp.Decision)
	}
}

func TestMCPQuiet1_OnboardingStillAsksWhenDisabled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	writeOnboardingConfig(t, home, 24, 20)
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-1*time.Hour))
	scopeFor(l, "fresh")       // scoped → not heightened, so the flag is what's under test
	l.QuietMCPFriction = false // strict/managed posture
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("with QuietMCPFriction off the onboarding gate must still ask, got %q", resp.Decision)
	}
}

func TestMCPQuiet1_OnboardingStillAsksUnderSecretSession(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	writeOnboardingConfig(t, home, 24, 20)
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-1*time.Hour))
	scopeFor(l, "fresh") // even scoped, a secret session is heightened → must not be silenced
	state := newTestSession(t, projectRoot)
	state.MarkSecretSession() // tainted context — the safety guard must hold

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	// Must NOT be silenced to allow under a secret session (heightened). Whether
	// it asks or denies, the point is the friction reduction did not fire.
	if resp.Decision == "allow" {
		t.Fatalf("MCPQUIET-1 must NOT silence to allow under a secret session, got allow")
	}
}

// The reduction must never silence mcp_unapproved — the real gate between an
// approved and an UNKNOWN server. An unapproved server is not in
// ApprovedMCPServers, so it maps to VerbMcpUnapproved, which is not in the
// QuietMCPFriction set.
func TestMCPQuiet1_DoesNotSilenceUnapprovedServer(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	writeOnboardingConfig(t, home, 24, 20)
	l := lease.DefaultLease() // no approved servers → unknown server asks
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__unknown__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("mcp_unapproved (unknown server) is a real gate and must still ask, got %q", resp.Decision)
	}
}

// Finding B regression: a scoped server is not "heightened", but an untrusted
// ingestion this session is still an exfil-sink context. autoLeaseSafeContext
// (required by the gate) must keep onboarding asking there, even though
// `heightened` alone would not.
func TestMCPQuiet1_OnboardingStillAsksAfterUntrustedRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	writeOnboardingConfig(t, home, 24, 20)
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-1*time.Hour))
	scopeFor(l, "fresh") // scoped → not heightened by capability scope...
	state := newTestSession(t, projectRoot)
	state.MarkUntrustedRead() // ...but untrusted content was ingested → unsafe context

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision == "allow" {
		t.Fatalf("MCPQUIET-1 onboarding must NOT silence after an untrusted read (exfil-sink context), got allow")
	}
}

// --- mcp_network_unapproved silence (the other half — Finding A) ---

// netScopeFor makes a server NON-heightened (has a capability scope) AND lets a
// URL argument through to the mcp_network_unapproved classification (rather than
// the harder allow_network=false scope-violation gate).
func netScopeFor(l *lease.Lease, server string) {
	l.MCPCapabilityScopes = append(l.MCPCapabilityScopes,
		lease.MCPCapabilityScope{Server: server, AllowNetwork: true})
}

func TestMCPQuiet1_NetworkUnapprovedSilencedOnCleanSession(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-48*time.Hour)) // past onboarding window
	netScopeFor(l, "fresh")                                                        // scoped (not heightened) + allow_network
	state := newTestSession(t, projectRoot)

	// Approved, scoped server + a tool-arg URL to an UNAPPROVED external host → mcp_network_unapproved.
	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__fetch",
		ToolInput: map[string]interface{}{"url": "https://unapproved.example.com/data"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("mcp_network_unapproved should be silenced on a clean session (QuietMCPFriction), got %q (reason=%s)",
			resp.Decision, resp.Reason)
	}
}

func TestMCPQuiet1_NetworkUnapprovedStillAsksWhenDisabled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-48*time.Hour))
	netScopeFor(l, "fresh")
	l.QuietMCPFriction = false
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__fetch",
		ToolInput: map[string]interface{}{"url": "https://unapproved.example.com/data"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("with QuietMCPFriction off, mcp_network_unapproved must still ask, got %q", resp.Decision)
	}
}

// Codex P1 regression: a FRESH, NO-SCOPE server whose FIRST call carries a URL
// arg is classified mcp_network_unapproved (not onboarding), so it never hit the
// onboarding heightened checkpoint. The network downgrade must itself exclude the
// heightened case, or that first-call-exfil checkpoint is bypassed via the
// network path. No scope → heightened → must still ask.
func TestMCPQuiet1_NetworkUnapproved_FreshNoScope_StillAsks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	// Fresh approval (within onboarding window) AND no capability scope → heightened.
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-1*time.Minute))
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__fetch",
		ToolInput: map[string]interface{}{"url": "https://unapproved.example.com/data"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision == "allow" {
		t.Fatalf("a fresh no-scope server's first network call must NOT be silenced (heightened checkpoint), got allow")
	}
}

func TestMCPQuiet1_ProfileGradient(t *testing.T) {
	if !lease.DefaultLease().QuietMCPFriction {
		t.Fatal("personal/default profile should have QuietMCPFriction on")
	}
}
