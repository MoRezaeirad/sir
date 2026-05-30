package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// cmdDeclassify lifts the derived-secret lineage label from a single file the
// operator attests is safe to release (e.g. after redacting it). It is the
// granular, audited counterpart to `sir unlock`: where unlock clears all
// developer-recoverable transient restrictions, declassify removes exactly one
// file's persistent derived-secret label and nothing else — so a later push or
// egress of that file is no longer gated, while every other taint (including a
// live secret session) stays in force.
func cmdDeclassify(projectRoot string, args []string) {
	var raw string
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Println("usage: sir declassify <path>\n\nRemoves the derived-secret label from one file the operator attests is safe to release.")
			return
		}
		if len(a) > 0 && a[0] == '-' {
			fatal("unknown flag: %s", a)
		}
		if raw == "" {
			raw = a
		}
	}
	if raw == "" {
		fatal("usage: sir declassify <path>")
	}

	if err := ensureManagedCommandAllowed("declassify"); err != nil {
		fatal("%v", err)
	}

	existing, err := session.Load(projectRoot)
	if err != nil {
		fatal("no active session found: %v", err)
	}

	candidates := declassifyPathCandidates(raw, projectRoot)

	var removed string
	if err := session.Update(projectRoot, func(state *session.State) error {
		if r, ok := state.DeclassifyPath(candidates...); ok {
			removed = r
		}
		return nil
	}); err != nil {
		fatal("declassify: %v", err)
	}

	if removed == "" {
		fmt.Printf("No derived-secret lineage is tracked for %q.\n", raw)
		if tracked := existing.DerivedPaths(); len(tracked) > 0 {
			fmt.Println("\nTracked derived-secret files (declassify one of these exact paths):")
			for _, p := range tracked {
				fmt.Printf("  %s\n", p)
			}
		}
		return
	}

	entry := &ledger.Entry{
		ToolName: "sir-cli",
		Verb:     "lineage_declassified",
		Target:   removed,
		Decision: "allow",
		Reason:   "developer declassified a derived-secret file via sir declassify (operator-attested)",
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not log to ledger: %v\n", err)
	}

	fmt.Printf("Declassified %s\n", removed)
	fmt.Println("Its derived-secret label was removed; a later push or egress of this file is no longer gated.")
	fmt.Println("All other session taint (including any live secret session) remains in force.")
}

// declassifyPathCandidates returns the path forms the lineage map might be keyed
// by: the raw input, its absolute form, and its symlink-resolved absolute form
// (symlinks resolved per the path-sensitivity invariant).
func declassifyPathCandidates(raw, projectRoot string) []string {
	out := []string{raw}
	abs := raw
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(projectRoot, raw)
	}
	out = append(out, abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil && resolved != abs {
		out = append(out, resolved)
	}
	return out
}
