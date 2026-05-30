package session

import "testing"

// TestDeclassifyPath verifies granular, per-file declassification: it removes
// exactly one file's derived-secret lineage and leaves others (and other taint)
// intact — the P2.1 primitive that `sir declassify` exposes.
func TestDeclassifyPath(t *testing.T) {
	s := NewState(t.TempDir())
	s.DerivedFileLineage = map[string]DerivedPathRecord{
		"/proj/leak.txt":  {Labels: []LineageLabel{{Sensitivity: "secret"}}},
		"/proj/other.txt": {Labels: []LineageLabel{{Sensitivity: "secret"}}},
	}
	// Also set a live secret session — declassify must NOT touch it.
	s.SecretSession = true

	removed, ok := s.DeclassifyPath("/nope", "/proj/leak.txt")
	if !ok || removed != "/proj/leak.txt" {
		t.Fatalf("DeclassifyPath = %q,%v; want /proj/leak.txt,true", removed, ok)
	}
	if _, still := s.DerivedFileLineage["/proj/leak.txt"]; still {
		t.Error("declassified file still has lineage")
	}
	if _, other := s.DerivedFileLineage["/proj/other.txt"]; !other {
		t.Error("declassify removed an unrelated file's lineage")
	}
	if !s.SecretSession {
		t.Error("declassify cleared the live secret session — it must only touch file lineage")
	}

	// No match -> no removal.
	if _, ok := s.DeclassifyPath("/proj/missing.txt"); ok {
		t.Error("DeclassifyPath reported removal for an untracked path")
	}
}
