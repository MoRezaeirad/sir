package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	mcppkg "github.com/somoore/sir/pkg/mcp"
)

// cmdMCPApprove promotes one (or all, with --all) MCP server(s) from
// DiscoveredMCPServers to ApprovedMCPServers. At approval time we record
// an MCPApproval with timestamp, source config path, command, and the
// sha256 hash of the command binary if resolvable. The hash binds the
// approval to a specific binary so a later install can detect binary
// tampering or supply-chain substitution.
//
// verdict discipline: this command writes trust. We never silently widen —
// every approval is an explicit user action, logged to the ledger.
func cmdMCPApprove(projectRoot string, args []string) {
	approveAll := false
	skipPrompt := false
	names := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--all":
			approveAll = true
		case "--yes":
			skipPrompt = true
		default:
			if strings.HasPrefix(a, "-") {
				fatal("unknown flag: %s", a)
			}
			names = append(names, a)
		}
	}

	if approveAll && len(names) > 0 {
		fatal("sir mcp approve: --all cannot be combined with explicit names")
	}
	if !approveAll && len(names) == 0 {
		fatal("usage: sir mcp approve <name> [<name> ...]\n       sir mcp approve --all")
	}

	if err := ensureManagedCommandAllowed("mcp approve"); err != nil {
		fatal("%v", err)
	}

	l, err := loadProjectLease(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}

	var targets []lease.MCPDiscoveredServer
	if approveAll {
		targets = append(targets, l.DiscoveredMCPServers...)
		if len(targets) == 0 {
			fmt.Println("No discovered MCP servers awaiting approval. Run `sir install` to refresh discovery.")
			return
		}
	} else {
		for _, name := range names {
			d, ok := l.FindDiscoveredMCPServer(name)
			if !ok {
				// If already approved, tell the user and skip rather than error.
				if containsApprovedName(l.ApprovedMCPServers, name) {
					fmt.Printf("MCP server %q is already in approved_mcp_servers.\n", name)
					continue
				}
				fatal("MCP server %q is not in discovered_mcp_servers. Run `sir install` first, or check `sir mcp list`.", name)
			}
			targets = append(targets, d)
		}
		if len(targets) == 0 {
			return
		}
	}

	// Best-effort: pin each server's advertised tool schema at approval time so
	// a later rug pull / tool poisoning (MCPoison, full-schema poisoning) is
	// detectable by `sir mcp scan`. Probing reads tools/list read-only and is
	// non-fatal — a server we cannot probe is approved anyway with an empty pin,
	// exactly as an unresolvable binary yields an empty CommandHash. Args come
	// from the live inventory (the discovered record only carries the command).
	inv := make(map[string]mcpServerInventory)
	for _, s := range discoverMCPInventoryForScopes(projectRoot, mcpScopesForAgent("")).Servers {
		inv[s.Name] = s
	}
	type schemaPin struct {
		hash  string
		names []string
		err   error
	}
	pins := make(map[string]schemaPin, len(targets))
	for _, t := range targets {
		if s, ok := inv[t.Name]; ok {
			h, names, err := probeToolSchema(s)
			pins[t.Name] = schemaPin{hash: h, names: names, err: err}
		}
	}

	// Show a single review screen with provenance so the user can see what
	// they are approving at once. This batches the decision instead of
	// per-server prompts, which habituates users into rubber-stamping.
	fmt.Println()
	fmt.Println("  sir mcp approve — reviewing the following server(s):")
	for _, t := range targets {
		fmt.Println()
		fmt.Printf("    name:    %s\n", t.Name)
		if t.SourcePath != "" {
			fmt.Printf("    source:  %s\n", t.SourcePath)
		}
		if t.Command != "" {
			fmt.Printf("    command: %s\n", t.Command)
		}
		hash, hashErr := mcppkg.HashCommand(t.Command)
		if hashErr != nil {
			fmt.Printf("    hash:    (error: %v)\n", hashErr)
		} else if hash == "" {
			fmt.Printf("    hash:    (not available — command resolved via PATH or npx/uvx)\n")
		} else {
			fmt.Printf("    hash:    %s\n", hash)
		}
		if p, ok := pins[t.Name]; ok {
			switch {
			case p.err != nil:
				fmt.Printf("    tools:   (schema not pinned — could not probe: %v)\n", p.err)
			case p.hash == "":
				fmt.Printf("    tools:   (none advertised)\n")
			default:
				fmt.Printf("    tools:   %d pinned (%s)\n", len(p.names), strings.Join(p.names, ", "))
			}
		}
	}
	fmt.Println()
	fmt.Println("  Approval skips the unknown-server gate for these servers. The verb")
	fmt.Println("  pipeline (credential scan, allow-host, lineage) still applies.")
	if !skipPrompt {
		fmt.Println()
		fmt.Print("Approve? [y/N] ")

		var confirm string
		fmt.Scanln(&confirm)
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm != "y" && confirm != "yes" {
			fmt.Println("Cancelled. No changes made.")
			return
		}
	}

	now := time.Now().UTC()
	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		if l.MCPApprovals == nil {
			l.MCPApprovals = make(map[string]lease.MCPApproval, len(targets))
		}
		for _, t := range targets {
			modTime, hash, _ := mcppkg.StatCommand(t.Command)
			if !containsApprovedName(l.ApprovedMCPServers, t.Name) {
				l.ApprovedMCPServers = append(l.ApprovedMCPServers, t.Name)
			}
			rec := lease.MCPApproval{
				ApprovedAt:     now,
				SourcePath:     t.SourcePath,
				Command:        t.Command,
				CommandHash:    hash,
				CommandModTime: modTime,
			}
			if p, ok := pins[t.Name]; ok && p.err == nil && p.hash != "" {
				rec.ToolSchemaHash = p.hash
				rec.ToolSchemaCapturedAt = now
				rec.ToolNames = p.names
			}
			l.MCPApprovals[t.Name] = rec
			l.RemoveDiscoveredMCPServer(t.Name)
		}
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}

	for _, t := range targets {
		ledger.Append(projectRoot, &ledger.Entry{
			Verb:     "lease_modify",
			Target:   "approved_mcp_servers",
			Decision: "allow",
			Reason:   fmt.Sprintf("approved MCP server: %s (source=%s)", t.Name, t.SourcePath),
		})
	}

	approvedNames := make([]string, 0, len(targets))
	for _, t := range targets {
		approvedNames = append(approvedNames, t.Name)
	}
	fmt.Printf("Approved %d MCP server(s): %s\n", len(approvedNames), strings.Join(approvedNames, ", "))
}

// cmdMCPRevoke removes a server from ApprovedMCPServers and its
// MCPApprovals record. The server is NOT re-added to DiscoveredMCPServers
// automatically; the next `sir install` will surface it again if it still
// exists in agent configs.
func cmdMCPRevoke(projectRoot string, args []string) {
	if len(args) == 0 {
		fatal("usage: sir mcp revoke <name> [<name> ...]")
	}
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			fatal("unknown flag: %s", a)
		}
	}
	if err := ensureManagedCommandAllowed("mcp revoke"); err != nil {
		fatal("%v", err)
	}

	l, err := loadProjectLease(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}

	absent := make([]string, 0)
	present := make([]string, 0, len(args))
	for _, name := range args {
		if containsApprovedName(l.ApprovedMCPServers, name) {
			present = append(present, name)
		} else {
			absent = append(absent, name)
		}
	}
	for _, name := range absent {
		fmt.Printf("MCP server %q is not in approved_mcp_servers (no-op).\n", name)
	}
	if len(present) == 0 {
		return
	}

	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		for _, name := range present {
			l.RemoveApprovedMCPServer(name)
		}
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}

	for _, name := range present {
		ledger.Append(projectRoot, &ledger.Entry{
			Verb:     "lease_modify",
			Target:   "approved_mcp_servers",
			Decision: "allow",
			Reason:   fmt.Sprintf("revoked MCP server: %s", name),
		})
	}
	fmt.Printf("Revoked %d MCP server(s): %s\n", len(present), strings.Join(present, ", "))
}

// cmdMCPList prints the current approved + discovered MCP servers with
// provenance. Shows approval age (how long since the user approved) so
// "recently-approved" servers are visually distinct — consistent with the
// eventual onboarding-window gate.
func cmdMCPList(projectRoot string) {
	l, err := loadProjectLease(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}

	fmt.Println("sir mcp list")
	fmt.Println()
	if len(l.ApprovedMCPServers) == 0 && len(l.DiscoveredMCPServers) == 0 && len(l.TrustedMCPServers) == 0 {
		fmt.Println("  (no MCP servers tracked; run `sir install` to discover)")
		return
	}

	if len(l.ApprovedMCPServers) > 0 {
		approved := append([]string(nil), l.ApprovedMCPServers...)
		sort.Strings(approved)
		fmt.Printf("  approved (%d):\n", len(approved))
		for _, name := range approved {
			rec, ok := l.MCPApprovals[name]
			switch {
			case !ok:
				fmt.Printf("    - %s  (no approval record; from pre-upgrade install or manual lease edit)\n", name)
			case rec.ApprovedAt.IsZero():
				fmt.Printf("    - %s  (source=%s)\n", name, rec.SourcePath)
			default:
				age := time.Since(rec.ApprovedAt).Round(time.Minute)
				fmt.Printf("    - %s  (approved %s ago; source=%s)\n", name, age, rec.SourcePath)
			}
		}
		fmt.Println()
	}

	if len(l.DiscoveredMCPServers) > 0 {
		discovered := append([]lease.MCPDiscoveredServer(nil), l.DiscoveredMCPServers...)
		sort.Slice(discovered, func(i, j int) bool { return discovered[i].Name < discovered[j].Name })
		fmt.Printf("  discovered, awaiting approval (%d):\n", len(discovered))
		for _, d := range discovered {
			fmt.Printf("    - %s  (source=%s; command=%s)\n", d.Name, d.SourcePath, d.Command)
		}
		fmt.Println()
		fmt.Println("  To trust these servers: `sir mcp approve <name>` or `sir mcp approve --all`.")
		fmt.Println()
	}

	if len(l.TrustedMCPServers) > 0 {
		trusted := append([]string(nil), l.TrustedMCPServers...)
		sort.Strings(trusted)
		fmt.Printf("  trusted — exempt from credential scanning (%d):\n", len(trusted))
		for _, name := range trusted {
			fmt.Printf("    - %s\n", name)
		}
	}

	if len(l.MCPCapabilityScopes) > 0 {
		fmt.Println()
		fmt.Printf("  scoped capabilities (%d):\n", len(l.MCPCapabilityScopes))
		scopes := append([]lease.MCPCapabilityScope(nil), l.MCPCapabilityScopes...)
		sort.Slice(scopes, func(i, j int) bool { return scopes[i].Server < scopes[j].Server })
		for _, scope := range scopes {
			fmt.Printf("    - %s  shell=%v network=%v write=%v tools=%v roots=%v\n",
				scope.Server, scope.AllowShell, scope.AllowNetwork, scope.AllowWrite, scope.Tools, scope.Roots)
		}
	}
}

func containsApprovedName(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
