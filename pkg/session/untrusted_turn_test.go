package session

import (
	"testing"
	"time"
)

// TestUntrustedContentThisTurn_ClearsOnTurnBoundary verifies the weak signal is
// set on ingestion and decays at the turn boundary, so cross-turn MCP/web
// workflows stay quiet while same-turn untrusted->egress is gated.
func TestUntrustedContentThisTurn_ClearsOnTurnBoundary(t *testing.T) {
	s := NewState(t.TempDir())
	s.MarkUntrustedContentThisTurn()
	if !s.UntrustedContentThisTurn {
		t.Fatal("expected UntrustedContentThisTurn set after Mark")
	}

	// A hook-driven turn advance (next user message) clears it.
	s.AdvanceTurnByHook()
	if s.UntrustedContentThisTurn {
		t.Error("expected UntrustedContentThisTurn cleared after AdvanceTurnByHook")
	}

	// Also clears via the time-gap heuristic path.
	s2 := NewState(t.TempDir())
	s2.MarkUntrustedContentThisTurn()
	s2.LastToolCallAt = time.Now().Add(-2 * TurnGapThreshold)
	s2.MaybeAdvanceTurn(time.Now())
	if s2.UntrustedContentThisTurn {
		t.Error("expected UntrustedContentThisTurn cleared after time-gap turn advance")
	}
}

// TestUntrustedContentThisTurn_ClearedBySirUnlock verifies `sir unlock`
// (ClearTransientRestrictions) clears the signal, and HasTransientRestrictions
// reports it so unlock knows there is something to clear.
func TestUntrustedContentThisTurn_ClearedBySirUnlock(t *testing.T) {
	s := NewState(t.TempDir())
	s.MarkUntrustedContentThisTurn()
	if !s.HasTransientRestrictions() {
		t.Fatal("expected HasTransientRestrictions true with untrusted-this-turn set")
	}
	s.ClearTransientRestrictions()
	if s.UntrustedContentThisTurn {
		t.Error("expected UntrustedContentThisTurn cleared by ClearTransientRestrictions")
	}
}
