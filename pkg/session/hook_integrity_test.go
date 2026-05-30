package session

import "testing"

func TestDeniedToolUseTracking(t *testing.T) {
	s := NewState(t.TempDir())
	if s.WasToolUseDenied("") || s.WasToolUseDenied("nope") {
		t.Fatal("nothing should be denied initially")
	}
	s.RecordDeniedToolUse("T1")
	if !s.WasToolUseDenied("T1") {
		t.Error("T1 should be recorded as denied")
	}
	s.RecordDeniedToolUse("")   // no-op
	s.RecordDeniedToolUse("T1") // dup no-op
	if len(s.DeniedToolUses) != 1 {
		t.Errorf("empty/dup were added; got %d entries", len(s.DeniedToolUses))
	}
	// Bounded.
	for i := 0; i < maxDeniedToolUses+50; i++ {
		s.RecordDeniedToolUse(string(rune('a'+i%26)) + string(rune('0'+i%10)) + itoa(i))
	}
	if len(s.DeniedToolUses) > maxDeniedToolUses {
		t.Errorf("ring exceeded cap: %d", len(s.DeniedToolUses))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
