package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	mcppkg "github.com/somoore/sir/pkg/mcp"
)

// scanOutcome is the pure decision for one server's scan: what to do given the
// pinned baseline (if any) and the freshly-probed live digest.
type scanOutcome int

const (
	scanCapture scanOutcome = iota // no baseline yet -> establish the pin
	scanOK                         // baseline matches live -> nothing to do
	scanDrift                      // baseline differs from live -> rug pull / poisoning
)

// classifyScan is the testable core of the drift decision. Kept pure (no I/O)
// so the rug-pull logic can be unit-tested without spawning a server.
//   - empty pinned  -> capture (first scan establishes the baseline)
//   - empty live    -> treated as OK only if pinned is also empty; a server that
//     stops advertising tools after being pinned is drift (its definitions left)
//   - equal         -> ok
//   - differ        -> drift
func classifyScan(pinned, live string) scanOutcome {
	if pinned == "" {
		return scanCapture
	}
	if pinned == live {
		return scanOK
	}
	return scanDrift
}

// diffToolNames returns tools added and removed between the pinned baseline and
// the live set. "same names, changed digest" is reported by the caller when
// both slices are empty but the digests differ (a definition mutated in place).
func diffToolNames(pinned, live []string) (added, removed []string) {
	have := make(map[string]bool, len(pinned))
	for _, n := range pinned {
		have[n] = true
	}
	now := make(map[string]bool, len(live))
	for _, n := range live {
		now[n] = true
	}
	for n := range now {
		if !have[n] {
			added = append(added, n)
		}
	}
	for n := range have {
		if !now[n] {
			removed = append(removed, n)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// probeToolSchema spawns a command-based MCP server read-only, reads its
// tools/list, and returns the canonical full-schema digest plus the covered
// tool names. Best-effort and bounded: any failure (not a command server,
// launch error, unparseable list) returns an error so callers can record
// "nothing pinned" honestly rather than block on it.
func probeToolSchema(server mcpServerInventory) (digest string, names []string, err error) {
	if !server.HasCommand || server.Command == "" {
		return "", nil, fmt.Errorf("not a command-based server")
	}
	raw, err := mcppkg.QueryToolsList(context.Background(), server.Command, server.Args, 0)
	if err != nil {
		return "", nil, err
	}
	return mcppkg.CanonicalToolsDigest(raw)
}

// scanResult carries one server's probe result through to the single lease
// mutation + ledger pass at the end.
type scanResult struct {
	name     string
	outcome  scanOutcome
	digest   string
	names    []string
	pinned   lease.MCPApproval
	probeErr error
}

// cmdMCPScan probes each approved, command-based MCP server's live tools/list,
// pins it on first scan, verifies it on subsequent scans, and on drift revokes
// the approval (so the next agent use hits the unapproved-server ask gate) and
// records it to the ledger. This catches MCP rug pulls (MCPoison) and
// full-schema poisoning, which the binary-drift gate cannot see.
//
// It spawns the configured server command read-only (initialize + tools/list,
// never a tool call), bounded by a timeout. Drift exits non-zero so CI can gate.
func cmdMCPScan(projectRoot string, args []string) {
	var only []string
	quiet := false
	for _, a := range args {
		switch {
		case a == "--quiet" || a == "-q":
			// Cron/scheduler mode: print nothing on success; still print drift
			// warnings and exit non-zero so a timer can alert only on a real
			// finding.
			quiet = true
		case strings.HasPrefix(a, "-"):
			fatal("unknown flag: %s", a)
		default:
			only = append(only, a)
		}
	}

	if err := ensureManagedCommandAllowed("mcp scan"); err != nil {
		fatal("%v", err)
	}

	l, err := loadProjectLease(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}
	if len(l.ApprovedMCPServers) == 0 {
		if !quiet {
			fmt.Println("sir mcp scan")
			fmt.Println()
			fmt.Println("  No approved MCP servers to scan. Approve servers with `sir mcp approve` first.")
		}
		return
	}

	// Live command+args come from the inventory (the approval record only stores
	// the command, not its args). Index by server name.
	report := discoverMCPInventoryForScopes(projectRoot, mcpScopesForAgent(""))
	inv := make(map[string]mcpServerInventory, len(report.Servers))
	for _, s := range report.Servers {
		inv[s.Name] = s
	}

	targets := l.ApprovedMCPServers
	if len(only) > 0 {
		targets = only
	}

	if !quiet {
		fmt.Println("sir mcp scan")
		fmt.Println()
	}

	var results []scanResult
	for _, name := range targets {
		rec := l.MCPApprovals[name]
		server, known := inv[name]
		if !known || !server.HasCommand || server.Command == "" {
			if !quiet {
				fmt.Printf("  - %s  SKIP (not a command-based server, or not found in current config — cannot probe tools/list)\n", name)
			}
			continue
		}
		digest, names, perr := probeToolSchema(server)
		if perr != nil {
			if !quiet {
				fmt.Printf("  - %s  SKIP (could not probe: %v)\n", name, perr)
			}
			results = append(results, scanResult{name: name, probeErr: perr, pinned: rec})
			continue
		}
		out := classifyScan(rec.ToolSchemaHash, digest)
		results = append(results, scanResult{name: name, outcome: out, digest: digest, names: names, pinned: rec})
		switch out {
		case scanCapture:
			if !quiet {
				fmt.Printf("  - %s  PINNED (%d tool(s): %s)\n", name, len(names), strings.Join(names, ", "))
			}
		case scanOK:
			if !quiet {
				fmt.Printf("  - %s  ok (%d tool(s), schema unchanged)\n", name, len(names))
			}
		case scanDrift:
			added, removed := diffToolNames(rec.ToolNames, names)
			fmt.Printf("  - %s  ⚠ DRIFT — tool definitions changed since approval\n", name)
			if len(added) > 0 {
				fmt.Printf("        added:   %s\n", strings.Join(added, ", "))
			}
			if len(removed) > 0 {
				fmt.Printf("        removed: %s\n", strings.Join(removed, ", "))
			}
			if len(added) == 0 && len(removed) == 0 {
				fmt.Printf("        same tool names, but one or more definitions changed in place (description/schema/default).\n")
			}
			fmt.Printf("        action:  approval REVOKED — verify the change, then `sir mcp approve %s` to re-pin.\n", name)
		}
	}

	// Apply pins (capture) and revocations (drift) in a single atomic lease
	// update, then log. Probe failures change nothing — a transient launch
	// error must not silently drop a pin or an approval.
	drift := false
	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		if l.MCPApprovals == nil {
			l.MCPApprovals = make(map[string]lease.MCPApproval)
		}
		now := time.Now().UTC()
		for _, r := range results {
			switch r.outcome {
			case scanCapture:
				rec := l.MCPApprovals[r.name]
				rec.ToolSchemaHash = r.digest
				rec.ToolSchemaCapturedAt = now
				rec.ToolNames = r.names
				l.MCPApprovals[r.name] = rec
			case scanDrift:
				drift = true
				l.RemoveApprovedMCPServer(r.name)
				delete(l.MCPApprovals, r.name)
			}
		}
		return nil
	}); err != nil {
		fatal("update lease: %v", err)
	}

	for _, r := range results {
		switch r.outcome {
		case scanCapture:
			ledger.Append(projectRoot, &ledger.Entry{
				Verb:     "mcp_tool_pin",
				Target:   r.name,
				Decision: "allow",
				Reason:   fmt.Sprintf("pinned MCP tool schema (%d tools)", len(r.names)),
			})
		case scanDrift:
			ledger.Append(projectRoot, &ledger.Entry{
				Verb:     "mcp_tool_drift",
				Target:   r.name,
				Decision: "deny",
				Reason:   "MCP tool schema changed since approval (possible rug pull / tool poisoning); approval revoked",
			})
		}
	}

	if drift {
		// Always loud, even under --quiet: this is the finding a scheduler wants.
		fmt.Println()
		fmt.Println("  Drift detected. Affected servers were reverted to unapproved — the agent")
		fmt.Println("  will be asked before using them again. Re-approve after verifying the change.")
		os.Exit(3)
	}
	if !quiet {
		fmt.Println()
		fmt.Println("  Scan complete.")
	}
}
