package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/kernel"
)

func TestRedactedKernelExportRecordOmitsProviderReasons(t *testing.T) {
	entry := kernel.LedgerEntry{
		EntryID:  "entry-1",
		PrevHash: "prev",
		Hash:     "hash",
		Decision: kernel.Decision{
			DecisionID: "decision-1",
			ProviderPolicyEvidence: []kernel.ProviderPolicyEvidence{
				{
					Provider:     "opa-bridge",
					Verdict:      kernel.VerdictDeny,
					RulesMatched: []string{"deny-secret-path"},
					Reason:       "provider echoed ~/.aws/credentials",
					Used:         true,
				},
			},
			ProviderEvidence: []kernel.ProviderEvidence{
				{
					Provider: "opa-bridge",
					Kind:     "policy_provider",
					Status:   "unavailable",
					Reason:   "exec failed while evaluating ~/.aws/credentials",
					Behavior: "ignored; native policy used",
				},
			},
		},
	}

	raw, err := json.Marshal(redactedKernelExportRecord(entry))
	if err != nil {
		t.Fatalf("marshal redacted record: %v", err)
	}
	out := string(raw)
	if strings.Contains(out, "~/.aws/credentials") || strings.Contains(out, "provider echoed") || strings.Contains(out, "exec failed") {
		t.Fatalf("redacted export leaked provider reason: %s", out)
	}
	if !strings.Contains(out, "deny-secret-path") || !strings.Contains(out, "unavailable") {
		t.Fatalf("redacted export dropped safe provider metadata: %s", out)
	}
}
