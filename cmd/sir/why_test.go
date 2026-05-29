package main

import (
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/detect"
	"github.com/somoore/sir/pkg/ledger"
)

func TestWhyHelpers_FirstNonEmptyLine(t *testing.T) {
	cases := map[string]string{
		"":                     "",
		"hello":                "hello",
		"\n\n  first \nsecond": "first",
		"   \n\t\nlate":        "late",
	}
	for in, want := range cases {
		if got := firstNonEmptyLine(in); got != want {
			t.Errorf("firstNonEmptyLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWhyHelpers_DataLine(t *testing.T) {
	// Verdict-based defaults.
	if got := whyDataLine(ledger.Entry{Decision: "deny"}); !strings.Contains(got, "nothing left your machine") {
		t.Errorf("deny data line = %q", got)
	}
	if got := whyDataLine(ledger.Entry{Decision: "ask"}); !strings.Contains(got, "Waiting on your approval") {
		t.Errorf("ask data line = %q", got)
	}
	if got := whyDataLine(ledger.Entry{Decision: "allow"}); !strings.Contains(strings.ToLower(got), "allowed") {
		t.Errorf("allow data line = %q", got)
	}
	// Detection metadata wins when present.
	e := ledger.Entry{Decision: "deny", DetectionID: string(detect.SecretToExternalEgress)}
	meta, _ := detect.Lookup(detect.SecretToExternalEgress)
	if got := whyDataLine(e); got != meta.DataLeft {
		t.Errorf("detection data line = %q, want catalog DataLeft %q", got, meta.DataLeft)
	}
}

func TestWhyHelpers_TopRecovery(t *testing.T) {
	// A denied external egress yields the host-allow recovery as the top option.
	if got := topRecovery(ledger.Entry{Decision: "deny", Verb: "net_external", Target: "https://api.example.com/x"}); !strings.Contains(got, "sir allow-host") {
		t.Errorf("net_external deny top recovery = %q, want a sir allow-host hint", got)
	}
	// An allow has no recovery.
	if got := topRecovery(ledger.Entry{Decision: "allow", Verb: "read_ref"}); got != "" {
		t.Errorf("allow top recovery = %q, want empty", got)
	}
	// A verdict with no verb-specific recovery still points at explain.
	if got := topRecovery(ledger.Entry{Decision: "ask", Verb: "some_other_verb"}); !strings.Contains(got, "sir explain") {
		t.Errorf("fallback top recovery = %q, want a sir explain pointer", got)
	}
}
