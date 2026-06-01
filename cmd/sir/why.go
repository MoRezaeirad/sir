package main

import (
	"fmt"
	"strings"

	"github.com/somoore/sir/pkg/detect"
	"github.com/somoore/sir/pkg/ledger"
)

// cmdWhy (UX-1) prints a tight, instant answer for the most recent decision —
// the "I just got blocked/prompted, tell me in five lines" view: the verdict,
// why, whether any data left the machine, and the single best next step. The
// full causal chain, IFC labels, detection metadata, and hash-chain integrity
// live in `sir explain --last`.
func cmdWhy(projectRoot string) {
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		fatal("read ledger: %v", err)
	}
	if len(entries) == 0 {
		fmt.Println("Nothing to explain yet — sir has recorded no decisions in this project.")
		return
	}
	e := entries[len(entries)-1]

	fmt.Printf("%s  %s\n", ac(decisionColor(e.Decision), strings.ToUpper(e.Decision)), decisionTitle(e))
	if reason := firstNonEmptyLine(e.Reason); reason != "" {
		fmt.Printf("  native: %s\n", reason)
	}
	fmt.Printf("  data:  %s\n", whyDataLine(e))
	if fix := topRecovery(e); fix != "" {
		fmt.Printf("  fix:   %s\n", fix)
	}
	printProviderVerdicts(e)
	fmt.Printf("\n  %s\n", ac(auditDim, "full causal chain, IFC labels & integrity:  sir explain --last"))
}

// printProviderVerdicts renders policy-provider verdicts and fail-open failures
// in a section separate from the native policy rule, so a reader can tell
// managed-policy input (OPA/Cedar/custom packs) apart from sir's own floors.
// Failures are non-blocking notes: a provider that timed out or errored did not
// contribute, and native policy applied (fail-open).
func printProviderVerdicts(e ledger.Entry) {
	if len(e.ProviderVerdicts) > 0 {
		fmt.Println("  Provider verdicts (advisory — recommend only; never lower a native deny):")
		for _, v := range e.ProviderVerdicts {
			line := fmt.Sprintf("    %s: %s", v.Provider, v.Verdict)
			if len(v.RulesMatched) > 0 {
				line += fmt.Sprintf(" (rules: %s)", strings.Join(v.RulesMatched, ", "))
			}
			if usage := providerVerdictUsage(e, v); usage != "" {
				line += " " + ac(auditDim, usage)
			}
			fmt.Println(line)
		}
		fmt.Printf("  %s\n", ac(auditDim, "Run 'sir policy explain' to model how a verdict composes under the native floors."))
	}
	for _, f := range e.ProviderFailures {
		status := f.Status
		if status == "" {
			status = "failed"
			if f.TimedOut {
				status = "timeout"
			}
		}
		behavior := f.Behavior
		if behavior == "" {
			behavior = "native policy applied (fail-open)"
		}
		fmt.Printf("  %s\n", ac(auditDim, fmt.Sprintf("Note: policy provider %s %s — %s", f.Provider, status, behavior)))
	}
}

// providerVerdictUsage returns a short annotation describing whether an advisory
// verdict actually changed this decision, derived only from persisted ledger
// fields (the final Decision and the pre-composition BaseVerdict). It is the
// historical mirror of `sir policy explain`'s live composition trace.
//
//   - final deny/allow: advisory can neither lower a deny nor change an allow, so
//     it had no effect — true regardless of base.
//   - final ask + base allow: an ask/deny advisory escalated allow→ask (used); an
//     allow advisory still had no effect.
//   - final ask + base unrecorded: native ask (or a pre-BaseVerdict entry) —
//     ambiguous, so we annotate nothing and defer to `sir policy explain`.
func providerVerdictUsage(e ledger.Entry, v ledger.ProviderVerdictRecord) string {
	if v.Used {
		return "→ used (escalated allow→ask)"
	}
	switch e.Decision {
	case "deny":
		return "→ no effect (cannot lower a native deny)"
	case "allow":
		return "→ no effect (cannot change a native allow)"
	case "ask":
		if e.BaseVerdict != "allow" {
			return "" // native ask or legacy entry — undeterminable from the ledger
		}
		if v.Verdict == "ask" || v.Verdict == "deny" {
			return "→ used (escalated allow→ask)"
		}
		return "→ no effect"
	}
	return ""
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// whyDataLine answers "did data leave my machine?" — the question a blocked
// developer most wants answered. Prefer the detection's curated statement;
// otherwise a verdict-based default.
func whyDataLine(e ledger.Entry) string {
	if det := ledger.DetectionID(e); det != "" {
		if meta, ok := detect.Lookup(detect.ID(det)); ok && meta.DataLeft != "" {
			return meta.DataLeft
		}
	}
	switch e.Decision {
	case "deny", "would_deny":
		return "Blocked before it ran — nothing left your machine."
	case "ask", "would_ask":
		return "Waiting on your approval — nothing has happened yet."
	default:
		return "Allowed; no egress restriction triggered."
	}
}

// topRecovery returns the single most useful next step for this decision.
func topRecovery(e ledger.Entry) string {
	if opts := recoveryOptions(e); len(opts) > 0 {
		return strings.TrimSpace(opts[0])
	}
	switch e.Decision {
	case "deny", "would_deny", "ask", "would_ask":
		return "sir explain --last   (see the full reason and options)"
	default:
		return ""
	}
}
