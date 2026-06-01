package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/somoore/sir/pkg/kernel"
)

// cmdExport exports the v2 ledger as redacted JSONL to stdout or a file.
// This is the Phase 8 observability export surface.
// Usage: sir export [--out <path>] [--last N] [--redact]
//
// OTLP export: deferred. A Python export provider at
// examples/providers/otlp-exporter/ would provide this without violating
// the Go stdlib-only non-negotiable.
func cmdExport(args []string) {
	outPath := ""
	lastN := 0
	for i, a := range args {
		switch a {
		case "--out":
			if i+1 < len(args) {
				outPath = args[i+1]
			}
		case "--last":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &lastN)
			}
		}
	}

	ledger, err := kernel.OpenLedger(kernel.DefaultLedgerPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening ledger: %v\n", err)
		os.Exit(1)
	}

	entries, err := ledger.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading ledger: %v\n", err)
		os.Exit(1)
	}

	if lastN > 0 && lastN < len(entries) {
		entries = entries[len(entries)-lastN:]
	}

	var out *os.File
	if outPath != "" {
		out, err = os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating output: %v\n", err)
			os.Exit(1)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}

	for _, e := range entries {
		// Redacted export: omit raw explanation, keep structured fields.
		record := map[string]any{
			"entry_id":       e.EntryID,
			"case_id":        e.CaseID,
			"decision_id":    e.Decision.DecisionID,
			"timestamp":      e.Decision.Timestamp,
			"mode":           e.Decision.Mode,
			"verdict":        e.Decision.Verdict,
			"enforceability": e.Decision.Enforceability,
			"attribution":    e.Decision.Attribution,
			"action_type":    e.Decision.ActionType,
			"sensitivity":    e.Decision.Sensitivity,
			"policy_rules":   e.Decision.PolicyRules,
			"hash":           e.Hash,
			"prev_hash":      e.PrevHash,
		}
		b, _ := json.Marshal(record)
		fmt.Fprintln(out, string(b))
	}

	if outPath != "" {
		fmt.Printf("exported %d entries to %s\n", len(entries), outPath)
	}
}

// cmdLogFollowV2 streams new kernel ledger entries as they are written.
// This is a simple tail-follow; real streaming is a future enhancement.
func cmdLogFollowV2() {
	ledger, err := kernel.OpenLedger(kernel.DefaultLedgerPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	entries, err := ledger.ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("v2 ledger entries (most recent last):")
	fmt.Println(strings.Repeat("-", 80))
	for _, e := range entries {
		d := e.Decision
		fmt.Printf("[%s] %s  %s  %s  %s\n",
			d.Timestamp, d.Verdict, d.Enforceability, d.ActionType, e.CaseID)
	}
	fmt.Printf("\n%d total entries in %s\n", len(entries), kernel.DefaultLedgerPath())
}
