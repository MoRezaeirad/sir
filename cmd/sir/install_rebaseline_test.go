package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/hooks"
)

func TestPrintRebaselineSummaryLimitsSkippedDetails(t *testing.T) {
	var summary hooks.RebaselineSummary
	summary.Refreshed = 2
	summary.DenyAllCleared = 1
	for i := 0; i < rebaselineSkipDetailLimit+2; i++ {
		summary.Skipped = append(summary.Skipped, hooks.RebaselineSkip{
			Project: fmt.Sprintf("project-%d", i),
			Reason:  "lease load: invalid character",
		})
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	printRebaselineSummary(&stdout, &stderr, summary)

	if got := stdout.String(); !strings.Contains(got, "Refreshed baselines across 2 project session(s); cleared deny-all on 1.") {
		t.Fatalf("stdout = %q, want refresh summary", got)
	}

	errText := stderr.String()
	if !strings.Contains(errText, "Skipped 7 stale/bad project session(s) during rebaseline.") {
		t.Fatalf("stderr = %q, want skipped count", errText)
	}
	if strings.Count(errText, "lease load: invalid character") != rebaselineSkipDetailLimit {
		t.Fatalf("stderr = %q, want exactly %d skip details", errText, rebaselineSkipDetailLimit)
	}
	if !strings.Contains(errText, "... 2 more skipped; run `sir doctor` in an affected project to inspect.") {
		t.Fatalf("stderr = %q, want truncation hint", errText)
	}
}
