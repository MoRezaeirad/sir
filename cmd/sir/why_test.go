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

func TestCmdWhySeparatesNativeReasonFromProviderContext(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	env := newTestEnv(t)
	if err := ledger.Append(env.projectRoot, &ledger.Entry{
		ToolName:    "Bash",
		Verb:        "push_origin",
		Target:      "git push origin main",
		Decision:    "ask",
		Reason:      "native floor requires approval\nfull detail follows",
		BaseVerdict: "allow",
		ProviderVerdicts: []ledger.ProviderVerdictRecord{
			{Provider: "opa", Verdict: "ask", RulesMatched: []string{"was-secret-push"}, Used: true},
		},
		ProviderFailures: []ledger.ProviderFailureRecord{
			{Provider: "cedar", Kind: "policy_provider", Status: "unavailable", Behavior: "ignored; native policy used"},
		},
	}); err != nil {
		t.Fatalf("append ledger: %v", err)
	}

	out := captureStdout(t, func() {
		cmdWhy(env.projectRoot)
	})
	for _, want := range []string{
		"  native: native floor requires approval",
		"  Provider verdicts",
		"opa: ask (rules: was-secret-push)",
		"Note: policy provider cedar unavailable",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("cmdWhy output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "  why:") {
		t.Fatalf("cmdWhy should label native rules separately from providers:\n%s", out)
	}
}

func TestProviderVerdictUsage(t *testing.T) {
	cases := []struct {
		name    string
		entry   ledger.Entry
		verdict ledger.ProviderVerdictRecord
		want    string
	}{
		// Escalation: base allow → final ask. An ask/deny advisory is what did it.
		{"escalated-by-ask", ledger.Entry{Decision: "ask", BaseVerdict: "allow"}, ledger.ProviderVerdictRecord{Verdict: "ask"}, "→ used (escalated allow→ask)"},
		{"escalated-by-deny", ledger.Entry{Decision: "ask", BaseVerdict: "allow"}, ledger.ProviderVerdictRecord{Verdict: "deny"}, "→ used (escalated allow→ask)"},
		{"persisted-used", ledger.Entry{Decision: "ask"}, ledger.ProviderVerdictRecord{Verdict: "deny", Used: true}, "→ used (escalated allow→ask)"},
		// An allow advisory never escalates, even alongside one that did.
		{"allow-advisory-no-effect", ledger.Entry{Decision: "ask", BaseVerdict: "allow"}, ledger.ProviderVerdictRecord{Verdict: "allow"}, "→ no effect"},
		// Native ask (base not recorded as allow) — undeterminable, annotate nothing.
		{"native-ask-ambiguous", ledger.Entry{Decision: "ask", BaseVerdict: ""}, ledger.ProviderVerdictRecord{Verdict: "deny"}, ""},
		// Final deny: advisory cannot lower it, regardless of what it recommended.
		{"final-deny", ledger.Entry{Decision: "deny"}, ledger.ProviderVerdictRecord{Verdict: "allow"}, "→ no effect (cannot lower a native deny)"},
		// Final allow: floor or no escalation; advisory had no effect.
		{"final-allow", ledger.Entry{Decision: "allow"}, ledger.ProviderVerdictRecord{Verdict: "deny"}, "→ no effect (cannot change a native allow)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := providerVerdictUsage(tc.entry, tc.verdict); got != tc.want {
				t.Errorf("providerVerdictUsage(%+v, %+v) = %q, want %q", tc.entry, tc.verdict, got, tc.want)
			}
		})
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
