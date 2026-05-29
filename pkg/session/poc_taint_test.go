package session

import (
	"testing"
	"time"

	"github.com/somoore/sir/pkg/policy"
)

// poc_taint_test.go is the authoritative session-layer regression for the
// monotonic secret high-water mark (SessionEverSecret).
//
// Background (F1/F2 of the 2026-05-29 security review): the turn-scoped
// SecretSession flag clears on a turn boundary — instantly on the next user
// message via AdvanceTurnByHook, or after a 30s gap via MaybeAdvanceTurn. Before
// the high-water mark, that turn boundary dropped the secret taint entirely, so
// a secret laundered through model context could be re-emitted as agent-authored
// bytes a turn later with no friction (e.g. a silent push_origin).
//
// The fix: secret taint is monotonic. The turn boundary DOWNGRADES the deny
// floor (SecretSession -> false) but the high-water mark (SessionEverSecret)
// persists, so the oracle/fallback re-prompt on egress/push instead of silently
// allowing. Only `sir unlock` (ClearTransientRestrictions) clears it.
//
// These tests assert the post-fix flag transitions at the session layer. The
// resulting verdict (ask, not allow) is locked in by the oracle tests in
// mister-core/src/policy.rs and the Go fallback test in pkg/core.

// TestHighWaterMark_SurvivesHookTurnAdvance covers the instant reset path:
// one user message (UserPromptSubmit -> AdvanceTurnByHook) clears the turn-scoped
// deny floor but must NOT clear the high-water mark.
func TestHighWaterMark_SurvivesHookTurnAdvance(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession() // turn-scoped by default

	if !s.SecretSession || !s.SessionEverSecret {
		t.Fatalf("precondition: SecretSession=%v SessionEverSecret=%v, want both true", s.SecretSession, s.SessionEverSecret)
	}

	s.AdvanceTurnByHook() // simulate the next user message

	if s.SecretSession {
		t.Error("turn-scoped deny floor should clear on the hook turn advance")
	}
	if !s.SessionEverSecret {
		t.Error("high-water mark must persist across a hook turn advance (monotonic taint)")
	}
}

// TestHighWaterMark_SurvivesTimeGapTurnAdvance covers the 30s gap heuristic path.
func TestHighWaterMark_SurvivesTimeGapTurnAdvance(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession()

	// Seed a last-tool-call timestamp, then advance the clock past the gap.
	now := time.Now()
	s.LastToolCallAt = now
	s.MaybeAdvanceTurn(now.Add(TurnGapThreshold + time.Second))

	if s.SecretSession {
		t.Error("turn-scoped deny floor should clear after a >30s gap")
	}
	if !s.SessionEverSecret {
		t.Error("high-water mark must persist across a time-gap turn advance")
	}
}

// TestHighWaterMark_HeldWithinSameTurn confirms the control: across several tool
// calls in the same turn, the deny floor (SecretSession) stays up.
func TestHighWaterMark_HeldWithinSameTurn(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession()

	now := time.Now()
	s.LastToolCallAt = now
	for i := 0; i < 5; i++ {
		now = now.Add(time.Second) // sub-threshold gaps: still the same turn
		s.MaybeAdvanceTurn(now)
		if !s.SecretSession {
			t.Fatalf("call %d: SecretSession cleared within the same turn", i)
		}
	}
	if !s.SessionEverSecret {
		t.Error("high-water mark should be set throughout a secret turn")
	}
}

// TestHighWaterMark_ClearedOnlyByUnlock confirms `sir unlock`
// (ClearTransientRestrictions) is the explicit way to clear the high-water mark,
// and that the plain turn-scoped clear leaves it set.
func TestHighWaterMark_ClearedOnlyByUnlock(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession()

	// A plain clear (turn boundary equivalent) downgrades but does not clear it.
	s.ClearSecretSession()
	if s.SecretSession {
		t.Fatal("ClearSecretSession should clear the turn-scoped flag")
	}
	if !s.SessionEverSecret {
		t.Fatal("ClearSecretSession must NOT clear the high-water mark")
	}

	// HasTransientRestrictions should still report the recoverable state so the
	// developer is told `sir unlock` can clear it.
	if !s.HasTransientRestrictions() {
		t.Error("a was-secret session should report transient restrictions (unlock hint)")
	}

	// sir unlock clears the high-water mark.
	s.ClearTransientRestrictions()
	if s.SessionEverSecret {
		t.Error("sir unlock (ClearTransientRestrictions) must clear the high-water mark")
	}
}

// TestHighWaterMark_SessionScopedAlsoSetsMark confirms the mark is set
// regardless of approval scope.
func TestHighWaterMark_SessionScopedAlsoSetsMark(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSessionWithScope(policy.ApprovalScopeSession)
	if !s.SessionEverSecret {
		t.Fatal("SessionEverSecret should be set for session-scoped secrets too")
	}
}

// TestHighWaterMark_BackfilledForLegacySessionOnDowngrade covers the upgrade
// path flagged in review: a session.json written before SessionEverSecret
// existed loads with SecretSession=true but SessionEverSecret=false, and
// MarkSecretSession never runs in this process. Without backfill the next turn
// boundary would clear the floor and leave the mark false — reverting to the
// clean baseline and silently allowing push_origin. The downgrade must set the
// high-water mark so the was-secret posture survives.
func TestHighWaterMark_BackfilledForLegacySessionOnDowngrade(t *testing.T) {
	// Simulate a legacy in-memory state straight off disk: turn-scoped secret,
	// mark absent, approval recorded at an earlier turn.
	s := NewState("/p")
	s.SecretSession = true
	s.SessionEverSecret = false
	s.ApprovalScope = policy.ApprovalScopeTurn
	s.SecretApprovalTurn = 0
	s.TurnCounter = 0

	s.AdvanceTurnByHook() // next user message crosses the turn boundary

	if s.SecretSession {
		t.Error("legacy turn-scoped secret should clear on the turn boundary")
	}
	if !s.SessionEverSecret {
		t.Error("downgrade must backfill the high-water mark for a legacy session (else push_origin silently allowed)")
	}

	// Same via the time-gap path.
	s2 := NewState("/p")
	s2.SecretSession = true
	s2.SessionEverSecret = false
	s2.ApprovalScope = policy.ApprovalScopeTurn
	now := time.Now()
	s2.LastToolCallAt = now
	s2.MaybeAdvanceTurn(now.Add(TurnGapThreshold + time.Second))
	if s2.SecretSession || !s2.SessionEverSecret {
		t.Errorf("time-gap downgrade: SecretSession=%v SessionEverSecret=%v, want false/true", s2.SecretSession, s2.SessionEverSecret)
	}
}
