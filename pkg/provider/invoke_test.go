package provider

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

func TestMain(m *testing.M) {
	if os.Getenv("SIR_PROVIDER_TEST_HELPER") == "1" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		if stderr := os.Getenv("SIR_PROVIDER_TEST_STDERR"); stderr != "" {
			_, _ = os.Stderr.WriteString(stderr)
		}
		if stdout := os.Getenv("SIR_PROVIDER_TEST_STDOUT"); stdout != "" {
			_, _ = os.Stdout.WriteString(stdout)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func testProviderEntry(t *testing.T, stdout, stderr string) Entry {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	t.Setenv("SIR_PROVIDER_TEST_HELPER", "1")
	t.Setenv("SIR_PROVIDER_TEST_STDOUT", stdout)
	t.Setenv("SIR_PROVIDER_TEST_STDERR", stderr)
	return Entry{Name: "test-provider", Entrypoint: exe}
}

// TestParsePolicyVerdicts_EmptyFailsOpen pins the parser contract that
// empty/whitespace stdout is the SDK's quiet "evaluate returned None" fail-open
// signal. The invocation layer separately surfaces stderr-only output as a
// provider failure. Regression guard for the "unexpected end of JSON input"
// bug. Tests the pure parser so it is not subject to subprocess-spawn timing.
func TestParsePolicyVerdicts_EmptyFailsOpen(t *testing.T) {
	for _, in := range []string{"", "   ", "\n", "\t\n  "} {
		verdicts, err := parsePolicyVerdicts("silent", []byte(in))
		if err != nil {
			t.Errorf("parsePolicyVerdicts(%q) error = %v, want nil (fail open)", in, err)
		}
		if len(verdicts) != 0 {
			t.Errorf("parsePolicyVerdicts(%q) = %d verdicts, want 0", in, len(verdicts))
		}
	}
}

func TestInvokePolicyEmptyOutputDistinguishesQuietFromStderr(t *testing.T) {
	req := policy.PolicyRequest{Action: "push_origin"}

	t.Run("quiet no verdict", func(t *testing.T) {
		entry := testProviderEntry(t, "", "")

		verdicts, err := InvokePolicy(entry, req)
		if err != nil {
			t.Fatalf("InvokePolicy quiet provider error = %v, want nil", err)
		}
		if len(verdicts) != 0 {
			t.Fatalf("InvokePolicy quiet provider returned %d verdicts, want 0", len(verdicts))
		}
	})

	t.Run("stderr without verdict is surfaced", func(t *testing.T) {
		entry := testProviderEntry(t, "", "opa binary not found")

		verdicts, err := InvokePolicy(entry, req)
		if err == nil {
			t.Fatal("InvokePolicy stderr-only provider error = nil, want failure")
		}
		if len(verdicts) != 0 {
			t.Fatalf("InvokePolicy stderr-only provider returned %d verdicts, want 0", len(verdicts))
		}
		if !strings.Contains(err.Error(), "unavailable dependency not found") {
			t.Fatalf("InvokePolicy error = %q, want unavailable dependency classification", err.Error())
		}
	})
}

func TestInvokeAdvisoryEmptyOutputDistinguishesQuietFromStderr(t *testing.T) {
	req := policy.PolicyRequest{Action: "push_origin"}

	t.Run("quiet no risk", func(t *testing.T) {
		entry := testProviderEntry(t, "", "")

		risk, err := InvokeAdvisory(entry, req)
		if err != nil {
			t.Fatalf("InvokeAdvisory quiet provider error = %v, want nil", err)
		}
		if risk != nil {
			t.Fatalf("InvokeAdvisory quiet provider risk = %+v, want nil", risk)
		}
	})

	t.Run("stderr without risk is surfaced", func(t *testing.T) {
		entry := testProviderEntry(t, "", "risk engine timed out")

		risk, err := InvokeAdvisory(entry, req)
		if err == nil {
			t.Fatal("InvokeAdvisory stderr-only provider error = nil, want failure")
		}
		if risk != nil {
			t.Fatalf("InvokeAdvisory stderr-only provider risk = %+v, want nil", risk)
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("InvokeAdvisory error = %q, want timeout classification", err.Error())
		}
	})
}

func TestEmptyOutputProviderError(t *testing.T) {
	cases := []struct {
		name    string
		stderr  string
		wantErr bool
		want    string
	}{
		{"silent no verdict", "", false, ""},
		{"missing dependency", "[opa-bridge] WARNING: 'opa' binary not found", true, "unavailable dependency not found"},
		{"timeout", "OPA eval timed out", true, "timed out"},
		{"generic error", "policy crashed while evaluating", true, "reported an error without a verdict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := emptyOutputProviderError([]byte(tc.stderr))
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected nil, got %v", err)
			}
			if err != nil && err.Error() != tc.want {
				t.Fatalf("error = %q, want %q", err.Error(), tc.want)
			}
		})
	}
}

// TestParsePolicyVerdicts_SingleAndArray confirms both wire shapes still decode.
func TestParsePolicyVerdicts_SingleAndArray(t *testing.T) {
	single := `{"provider":"opa","verdict":"ask","rules_matched":["r1"]}`
	if v, err := parsePolicyVerdicts("opa", []byte(single)); err != nil || len(v) != 1 || v[0].Verdict != "ask" {
		t.Fatalf("single object: v=%+v err=%v", v, err)
	}
	array := `[{"provider":"opa","verdict":"ask"},{"provider":"opa","verdict":"deny"}]`
	if v, err := parsePolicyVerdicts("opa", []byte(array)); err != nil || len(v) != 2 {
		t.Fatalf("array: v=%+v err=%v", v, err)
	}
	if _, err := parsePolicyVerdicts("opa", []byte("{not json")); err == nil {
		t.Fatal("malformed JSON should still error")
	}
}

func TestNormalizeRiskLevel(t *testing.T) {
	cases := map[string]string{
		"low":      "low",
		"medium":   "medium",
		"high":     "high",
		"critical": "critical",
		"":         "low", // unknown defaults to low (fail-open)
		"bogus":    "low",
		"HIGH":     "low", // case-sensitive; unknown → low
	}
	for in, want := range cases {
		if got := normalizeRiskLevel(in); got != want {
			t.Errorf("normalizeRiskLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHighestAdvisoryRisk(t *testing.T) {
	cases := []struct {
		name  string
		risks []*AdvisoryRisk
		want  string // expected level, "" if nil
	}{
		{"empty", nil, ""},
		{"single low", []*AdvisoryRisk{{Level: "low"}}, "low"},
		{"low and high", []*AdvisoryRisk{{Level: "low"}, {Level: "high"}}, "high"},
		{"high and critical", []*AdvisoryRisk{{Level: "high"}, {Level: "critical"}}, "critical"},
		{"medium and low", []*AdvisoryRisk{{Level: "medium"}, {Level: "low"}}, "medium"},
		{"nils filtered", []*AdvisoryRisk{nil, {Level: "medium"}, nil}, "medium"},
		{"all nil", []*AdvisoryRisk{nil, nil}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := HighestAdvisoryRisk(c.risks)
			if c.want == "" {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil || got.Level != c.want {
				t.Errorf("HighestAdvisoryRisk = %+v, want level %q", got, c.want)
			}
		})
	}
}

func TestToVerdicts_Normalization(t *testing.T) {
	resps := []policyResponse{
		{Verdict: "ask", Provider: "opa", RulesMatched: []string{"r1"}},
		{Verdict: "bogus"}, // dropped — unknown verdict
		{Verdict: "deny"},  // nil RulesMatched → []
		{Verdict: ""},      // dropped — empty verdict
	}
	out := toVerdicts(resps)
	if len(out) != 2 {
		t.Fatalf("expected 2 normalized verdicts, got %d", len(out))
	}
	for _, v := range out {
		if !v.IsAdvisory {
			t.Error("IsAdvisory must be forced to true")
		}
		if v.RulesMatched == nil {
			t.Error("RulesMatched must never be nil after normalization")
		}
	}
}
