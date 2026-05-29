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
		fmt.Printf("  why:   %s\n", reason)
	}
	fmt.Printf("  data:  %s\n", whyDataLine(e))
	if fix := topRecovery(e); fix != "" {
		fmt.Printf("  fix:   %s\n", fix)
	}
	fmt.Printf("\n  %s\n", ac(auditDim, "full causal chain, IFC labels & integrity:  sir explain --last"))
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
