package hooks

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/somoore/sir/pkg/policy"
	providerreg "github.com/somoore/sir/pkg/provider"
	"github.com/somoore/sir/pkg/sdk"
	sirsignal "github.com/somoore/sir/pkg/signal"
)

// EffectSummary carries the outcome of effect dispatch after a policy decision.
type EffectSummary struct {
	BlockApplied  bool
	ContainActive bool
	ExportSent    int // number of export providers that received the decision
	Errors        []string
}

// DispatchEffects invokes registered effect providers after a policy decision.
//
// Routing:
//   - allow  → export effects only (async, non-blocking)
//   - ask    → export effects only (async); prompt is handled by the hook wire format
//   - deny   → block effect from active effect_provider (sync, fail-closed if required),
//     then export effects (async)
//
// Export providers (observability) receive every decision regardless of verdict.
// Signals are forwarded so export providers can include enforceability class and
// attribution confidence in their output (e.g. a SIEM event that says
// "enforceability:enforces, confidence:medium" vs "enforceability:blind").
func DispatchEffects(decision policy.Verdict, intent Intent, signals []sdk.Signal, projectRoot string) EffectSummary {
	var summary EffectSummary

	reg := loadProviderRegistry()

	effectID := newEffectID()
	// Enrich the effect target so a containment provider has something concrete to
	// contain: `command` is the actual shell/action string, `display` mirrors it,
	// `kind` hints the effect type. A devcontainer/sandbox provider runs `command`
	// inside an isolated jail. Without this a containment provider could only
	// probe its own boundary, never contain the specific action.
	target := map[string]any{
		"verb":    string(intent.Verb),
		"target":  intent.Target,
		"command": intent.Target,
		"display": intent.Target,
		"kind":    "process",
		"project": projectRoot,
	}

	// Block effect for deny verdicts — invoke active effect_provider synchronously.
	if decision == policy.VerdictDeny {
		for _, entry := range reg.Active(providerreg.KindEffect) {
			req := sdk.EffectRequest{
				SchemaVersion: sdk.SchemaEffectReqV0,
				EffectID:      effectID,
				Type:          sdk.EffectBlock,
				Required:      true,
				FailClosed:    true,
				Target:        target,
			}
			result, err := providerreg.InvokeEffect(entry, req)
			if err != nil {
				summary.Errors = append(summary.Errors,
					fmt.Sprintf("effect provider %s block: %v", entry.Name, err))
				continue
			}
			if result.Status == sdk.EffectApplied {
				summary.BlockApplied = true
			} else if result.Status == sdk.EffectFailed && req.FailClosed {
				summary.Errors = append(summary.Errors,
					fmt.Sprintf("effect provider %s: block failed: %s", entry.Name, result.Reason))
			}
		}
	}

	// Export effect — send to all active export_providers asynchronously.
	enforceability := sirsignal.EnforceabilityForSignals(signals)
	attribution := sirsignal.AttributionConfidence(signals)

	for _, entry := range reg.Active(providerreg.KindExport) {
		go func(e providerreg.Entry) {
			req := sdk.EffectRequest{
				SchemaVersion: sdk.SchemaEffectReqV0,
				EffectID:      newEffectID(),
				Type:          sdk.EffectExport,
				Required:      false,
				FailClosed:    false,
				Target: map[string]any{
					"verb":           string(intent.Verb),
					"target":         intent.Target,
					"verdict":        string(decision),
					"timestamp":      time.Now().UTC().Format(time.RFC3339),
					"project":        projectRoot,
					"enforceability": enforceability,
					"attribution":    attribution,
					"signal_count":   len(signals),
				},
			}
			if _, err := providerreg.InvokeEffect(e, req); err != nil {
				fmt.Fprintf(os.Stderr, "sir: export provider %s: %v\n", e.Name, err)
			}
		}(entry)
		summary.ExportSent++
	}

	return summary
}

func newEffectID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "eff_" + hex.EncodeToString(b)
}
