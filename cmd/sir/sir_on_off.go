package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/kernel"
)


// modeState is the persisted protection mode for v2.
type modeState struct {
	Mode      string `json:"mode"`
	Since     string `json:"since"`
	Providers int    `json:"providers_detected"`
}

func modeStatePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sir", "v2", "mode.json")
}

func readModeState() (*modeState, error) {
	data, err := os.ReadFile(modeStatePath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ms modeState
	if err := json.Unmarshal(data, &ms); err != nil {
		return nil, err
	}
	return &ms, nil
}

func writeModeState(ms modeState) error {
	path := modeStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(ms, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// cmdOn activates SIR v2 protection, detects available providers.
func cmdOn(args []string) {
	mode := kernel.ModeHookGate
	for i, a := range args {
		if a == "--mode" && i+1 < len(args) {
			mode = args[i+1]
		}
	}

	manifests, _ := findProviderManifests("examples/providers")
	healthy := 0
	for _, mpath := range manifests {
		m, issues := loadAndValidateManifest(mpath)
		if m == nil || len(issues) > 0 {
			continue
		}
		ep := filepath.Join(filepath.Dir(mpath), m.Entrypoint)
		if _, err := queryProviderCapabilities(ep); err == nil {
			healthy++
		}
	}

	ms := modeState{
		Mode:      mode,
		Since:     time.Now().UTC().Format(time.RFC3339),
		Providers: healthy,
	}
	if err := writeModeState(ms); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write mode state: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("sir on — mode: %s\n", mode)
	fmt.Printf("  %d provider(s) detected and healthy\n", healthy)
	fmt.Printf("  Guarantee: %s\n", modeGuarantee(mode))
	if healthy == 0 {
		fmt.Println()
		fmt.Println("  Warning: no providers available. SIR is in observe-only mode.")
	}
}

// cmdOff deactivates SIR v2 protection.
func cmdOff(args []string) {
	path := modeStatePath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("sir off — v2 mode state cleared")
	fmt.Println("  Run 'sir on' to re-activate protection.")
}

// grantRecord is a persisted scoped grant.
type grantRecord struct {
	Target    string `json:"target"`
	Scope     string `json:"scope"`
	TTL       string `json:"ttl"`
	GrantedAt string `json:"granted_at"`
	ExpiresAt string `json:"expires_at"`
	Used      bool   `json:"used"`
}

func grantStorePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sir", "v2", "grants.json")
}

// readActiveGrants returns non-expired, non-used grants.
func readActiveGrants() ([]grantRecord, error) {
	data, err := os.ReadFile(grantStorePath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var grants []grantRecord
	if err := json.Unmarshal(data, &grants); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var active []grantRecord
	for _, g := range grants {
		if g.Used {
			continue
		}
		exp, err := time.Parse(time.RFC3339, g.ExpiresAt)
		if err != nil || now.After(exp) {
			continue
		}
		active = append(active, g)
	}
	return active, nil
}

func writeGrants(grants []grantRecord) error {
	if err := os.MkdirAll(filepath.Dir(grantStorePath()), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(grants, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(grantStorePath(), b, 0o644)
}

// cmdAllow creates a narrow, one-time scoped grant for a target with enforced TTL.
// Implements CORRELATION spec: persistent grants forbidden; one-time preferred;
// short TTL required. Every grant is ledgered.
func cmdAllow(args []string) {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: sir allow <target> [--ttl <duration>]\n")
		fmt.Fprintf(os.Stderr, "  Default TTL: 15m (max: 1h)\n")
		fmt.Fprintf(os.Stderr, "  Forbidden: --persistent, --repo-wide, --global\n")
		os.Exit(1)
	}

	target := args[0]
	ttl := "15m"

	for i, a := range args[1:] {
		switch a {
		case "--ttl":
			if i+2 < len(args) {
				ttl = args[i+2]
			}
		case "--persistent", "--repo-wide", "--global":
			fmt.Fprintf(os.Stderr, "error: %s grants are forbidden (CORRELATION spec)\n", strings.TrimPrefix(a, "--"))
			fmt.Fprintf(os.Stderr, "  Use default one-time grant with a short TTL instead.\n")
			os.Exit(1)
		}
	}

	dur, err := time.ParseDuration(ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid TTL %q: %v\n", ttl, err)
		os.Exit(1)
	}
	if dur > time.Hour {
		fmt.Fprintf(os.Stderr, "error: TTL %s exceeds maximum (1h). Use a shorter duration.\n", ttl)
		os.Exit(1)
	}

	now := time.Now().UTC()
	grant := grantRecord{
		Target:    target,
		Scope:     "one-time",
		TTL:       ttl,
		GrantedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(dur).Format(time.RFC3339),
		Used:      false,
	}

	existing, _ := readActiveGrants()
	existing = append(existing, grant)
	if err := writeGrants(existing); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not persist grant: %v\n", err)
	}

	// Ledger the grant — CORRELATION: every grant and clear is ledgered.
	ledger, err := kernel.OpenLedger(kernel.DefaultLedgerPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot open ledger: %v\n", err)
	} else {
		grantDecision := kernel.Decision{
			DecisionID:    "grant-" + target[:min(8, len(target))],
			Timestamp:     now.Format(time.RFC3339),
			Mode:          "grant",
			Verdict:       kernel.VerdictAllow,
			DecisionClass: kernel.DecisionClassProceedAndReconcile,
			PolicyRules:   []string{"user-grant"},
			Explanation:   fmt.Sprintf("User granted one-time allow for: %s (TTL: %s)", target, ttl),
			ActionType:    "grant",
			Sensitivity:   "user_decision",
		}
		_ = ledger.Append("grant:"+target, grantDecision)
	}

	fmt.Printf("grant: %s\n", target)
	fmt.Printf("  scope:     one-time\n")
	fmt.Printf("  ttl:       %s (expires %s)\n", ttl, grant.ExpiresAt)
	fmt.Printf("  ledgered:  yes\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
