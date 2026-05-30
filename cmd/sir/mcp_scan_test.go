package main

import (
	"reflect"
	"testing"
)

func TestClassifyScan(t *testing.T) {
	cases := []struct {
		name         string
		pinned, live string
		want         scanOutcome
	}{
		{"first scan establishes baseline", "", "abc", scanCapture},
		{"unchanged schema is ok", "abc", "abc", scanOK},
		{"changed schema is drift", "abc", "xyz", scanDrift},
		{"pinned server going empty is drift", "abc", "", scanDrift},
		{"never-pinned empty stays capture", "", "", scanCapture},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyScan(c.pinned, c.live); got != c.want {
				t.Errorf("classifyScan(%q,%q) = %v, want %v", c.pinned, c.live, got, c.want)
			}
		})
	}
}

func TestDiffToolNames(t *testing.T) {
	added, removed := diffToolNames([]string{"a", "b"}, []string{"b", "c", "d"})
	if !reflect.DeepEqual(added, []string{"c", "d"}) {
		t.Errorf("added = %v, want [c d]", added)
	}
	if !reflect.DeepEqual(removed, []string{"a"}) {
		t.Errorf("removed = %v, want [a]", removed)
	}

	// Same names -> no add/remove (a definition-only change is reported by the
	// caller via the digest mismatch, not the name diff).
	added, removed = diffToolNames([]string{"a", "b"}, []string{"b", "a"})
	if len(added) != 0 || len(removed) != 0 {
		t.Errorf("identical name sets should diff empty, got added=%v removed=%v", added, removed)
	}
}
