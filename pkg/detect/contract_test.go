package detect

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// This file holds the two contract tests that keep the detection taxonomy
// honest as a public, stable interface:
//
//   - DETECT-3 (TestCatalogClassifyParity): every catalogued ID is reachable
//     from Classify, and the Detection it yields agrees with the catalog on
//     severity and base route. A new ID added to the catalog without a
//     classification path — or a severity/route that drifts between catalog
//     and classifier — fails here.
//   - DETECT-4 (TestDetectionDocParity): the routing table, the inline
//     enumeration, and the prose count in docs/user/siem-integration.md all
//     match AllIDs() exactly. The detection IDs are documented as a stable
//     SIEM contract, so the doc cannot silently drift from the code (this is
//     the test that would have caught the "ten" vs eleven mismatch).

// canonicalSignals maps every detection ID to a representative Signal that
// must classify to it on the base (non-suspicious) path. The map is exhaustive
// over AllIDs() by assertion below: adding a detection ID without adding a
// fixture here is a test failure, which is the point — it forces the author to
// prove the new ID is actually reachable.
var canonicalSignals = map[ID]Signal{
	SecretToExternalEgress:        {Verb: "net_external", Verdict: "deny", SecretSession: true},
	SecretToPushRemote:            {Verb: "push_remote", Verdict: "deny", SecretSession: true},
	MCPInjectionThenAction:        {Verb: "mcp_unapproved", Verdict: "deny", AlertType: "mcp_injection"},
	NewMCPServerUsed:              {Verb: "mcp_onboarding", Verdict: "ask"},
	MCPBinaryOrConfigDrift:        {Verb: "mcp_binary_drift", Verdict: "deny", AlertType: "mcp_binary_drift"},
	AgentPostureTamper:            {Verb: "stage_write", Verdict: "deny", AlertType: "config_change_posture", TamperRestored: true},
	PackageInstallPostureMutation: {Verb: "persistence", Verdict: "ask", PostureMutation: true},
	RepeatedDeniedIntent:          {Verb: "net_external", Verdict: "deny", RepeatedCount: 3},
	CredentialInToolOutput:        {Verb: "mcp_credential_leak", Verdict: "deny", AlertType: "credential_in_output"},
	ControlPlaneIntegrityFailure:  {Verb: "read_ref", Verdict: "deny", DenyAll: true},
	MCPChangeThenPrivilegedUse:    {Verb: "net_external", Verdict: "allow", RecentMCPChange: true},
}

// TestCatalogClassifyParity (DETECT-3) is the catalog<->classify anti-drift
// lock. For every ID in the catalog there must be a canonical signal that
// classifies to that ID with the catalog's declared severity and base route.
func TestCatalogClassifyParity(t *testing.T) {
	ids := AllIDs()

	// Every catalogued ID has a canonical fixture, and vice versa.
	for _, id := range ids {
		if _, ok := canonicalSignals[id]; !ok {
			t.Errorf("catalog ID %q has no canonical signal fixture in canonicalSignals — add one proving it is reachable from Classify", id)
		}
	}
	for id := range canonicalSignals {
		if !Valid(id) {
			t.Errorf("canonicalSignals references unknown ID %q", id)
		}
	}

	for _, id := range ids {
		sig, ok := canonicalSignals[id]
		if !ok {
			continue
		}
		meta, ok := Lookup(id)
		if !ok {
			t.Errorf("Lookup(%q) failed", id)
			continue
		}
		d, ok := Classify(sig)
		if !ok {
			t.Errorf("canonical signal for %q produced no detection", id)
			continue
		}
		if d.ID != id {
			t.Errorf("canonical signal for %q classified as %q", id, d.ID)
			continue
		}
		if d.Severity != meta.Severity {
			t.Errorf("ID %q: classifier severity %q != catalog severity %q", id, d.Severity, meta.Severity)
		}
		if d.Route != meta.BaseRoute {
			t.Errorf("ID %q: classifier base route %s != catalog base route %s", id, d.Route, meta.BaseRoute)
		}
	}
}

// TestSignals_MultiMatchPrimaryFirst (DETECT-1/DETECT-2) pins that Signals
// returns every firing detection — primary first, deduplicated — and never
// drifts from Classify (the primary is always Signals[0]).
func TestSignals_MultiMatchPrimaryFirst(t *testing.T) {
	// A blocked net_external under MCP taint that ALSO carries secret context:
	// the higher-priority injection detection is primary; secret-egress is a
	// secondary correlation tag.
	sig := Signal{Verb: "net_external", Verdict: "deny", MCPTaint: true, SecretSession: true}
	primary, ok := Classify(sig)
	if !ok {
		t.Fatal("expected a detection")
	}
	sigs := Signals(sig)
	if len(sigs) < 2 {
		t.Fatalf("expected multiple signals, got %v", sigs)
	}
	if sigs[0] != primary.ID {
		t.Errorf("Signals[0] = %q, must equal primary Classify ID %q", sigs[0], primary.ID)
	}
	got := map[ID]bool{}
	for _, id := range sigs {
		got[id] = true
	}
	for _, want := range []ID{MCPInjectionThenAction, SecretToExternalEgress} {
		if !got[want] {
			t.Errorf("expected signal %q in %v", want, sigs)
		}
	}
	// Quiet signal -> no signals (and no primary).
	if s := Signals(Signal{Verb: "read_ref", Verdict: "allow"}); len(s) != 0 {
		t.Errorf("quiet signal should produce no signals, got %v", s)
	}
	// Drift guard: for every canonical fixture, the primary is Signals[0].
	for id, fixture := range canonicalSignals {
		p, ok := Classify(fixture)
		if !ok {
			continue
		}
		s := Signals(fixture)
		if len(s) == 0 || s[0] != p.ID {
			t.Errorf("fixture %q: Signals[0]=%v != primary %v", id, s, p.ID)
		}
	}
}

// docRow is one parsed line of the routing table in siem-integration.md.
type docRow struct {
	id       ID
	severity string
	routeRaw string
}

// TestDetectionDocParity (DETECT-4) treats docs/user/siem-integration.md as an
// executable spec for the detection contract.
func TestDetectionDocParity(t *testing.T) {
	path := findSIEMDocPath(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(data)
	want := idSet(AllIDs())

	t.Run("routing_table", func(t *testing.T) {
		rows := parseRoutingTable(t, src)
		if len(rows) == 0 {
			t.Fatal("parsed zero rows from the routing table — parser broken or table removed")
		}
		got := make(map[ID]bool, len(rows))
		for _, r := range rows {
			got[r.id] = true
			meta, ok := Lookup(r.id)
			if !ok {
				t.Errorf("routing table documents unknown detection ID %q", r.id)
				continue
			}
			if !strings.EqualFold(r.severity, string(meta.Severity)) {
				t.Errorf("ID %q: doc severity %q != catalog severity %q", r.id, r.severity, meta.Severity)
			}
			if tok := routeToken(meta.BaseRoute); !strings.Contains(strings.ToLower(r.routeRaw), tok) {
				t.Errorf("ID %q: doc route %q does not mention base route %q", r.id, r.routeRaw, tok)
			}
		}
		assertSameIDSet(t, "routing table", got, want)
	})

	t.Run("inline_enumeration", func(t *testing.T) {
		// The sir.detection_id row enumerates every ID inline ("see below): `a` / `b` / ...").
		got := enumeratedIDs(src, "sir.detection_id")
		if len(got) == 0 {
			t.Fatal("found no inline detection_id enumeration to check")
		}
		assertSameIDSet(t, "inline sir.detection_id enumeration", got, want)
	})

	t.Run("prose_count", func(t *testing.T) {
		// "The <word> detection IDs and where they are routed:" must match count.
		m := regexp.MustCompile(`(?i)\bThe (\w+) detection IDs\b`).FindStringSubmatch(src)
		if m == nil {
			t.Fatal(`could not find "The <count> detection IDs" prose`)
		}
		wantWord := numberWord(len(want))
		if !strings.EqualFold(m[1], wantWord) {
			t.Errorf("prose says %q detection IDs but there are %d (%q) — update siem-integration.md", m[1], len(want), wantWord)
		}
	})
}

// parseRoutingTable extracts the "| Detection ID | Severity | Route |" table.
func parseRoutingTable(t *testing.T, src string) []docRow {
	t.Helper()
	lines := strings.Split(src, "\n")
	var rows []docRow
	inTable := false
	idCell := regexp.MustCompile("`([a-z0-9_]+)`")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "| Detection ID") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break // table ended
		}
		if strings.HasPrefix(line, "|---") || strings.HasPrefix(line, "| ---") {
			continue
		}
		cols := splitTableRow(line)
		if len(cols) < 3 {
			continue
		}
		m := idCell.FindStringSubmatch(cols[0])
		if m == nil {
			continue
		}
		rows = append(rows, docRow{id: ID(m[1]), severity: strings.TrimSpace(cols[1]), routeRaw: cols[2]})
	}
	return rows
}

// enumeratedIDs returns the backticked snake_case tokens that look like
// detection IDs from the table row whose first cell names the given field.
func enumeratedIDs(src, field string) map[ID]bool {
	out := map[ID]bool{}
	tok := regexp.MustCompile("`([a-z0-9_]+)`")
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "| `"+field+"`") {
			continue
		}
		for _, m := range tok.FindAllStringSubmatch(line, -1) {
			id := ID(m[1])
			if Valid(id) {
				out[id] = true
			}
		}
	}
	return out
}

func splitTableRow(line string) []string {
	parts := strings.Split(strings.Trim(line, "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func routeToken(r Route) string {
	switch r {
	case RouteSlack:
		return "slack"
	case RouteSIEM:
		return "siem"
	case RouteLocal:
		return "local"
	default:
		return "silent"
	}
}

func idSet(ids []ID) map[ID]bool {
	out := make(map[ID]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

func assertSameIDSet(t *testing.T, where string, got, want map[ID]bool) {
	t.Helper()
	for id := range want {
		if !got[id] {
			t.Errorf("%s is missing detection ID %q", where, id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("%s documents detection ID %q that is not in the catalog", where, id)
		}
	}
}

// numberWord spells out small counts so the prose count can be checked against
// len(AllIDs()). Covers the realistic range for a closed taxonomy.
func numberWord(n int) string {
	words := []string{
		"zero", "one", "two", "three", "four", "five", "six", "seven", "eight",
		"nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen",
		"sixteen", "seventeen", "eighteen", "nineteen", "twenty",
	}
	if n >= 0 && n < len(words) {
		return words[n]
	}
	return strconv.Itoa(n)
}

// findSIEMDocPath walks up from the test's working directory to locate
// docs/user/siem-integration.md, so the test works under `go test ./...` and
// `go test ./pkg/detect/...` alike.
func findSIEMDocPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "docs", "user", "siem-integration.md")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("docs/user/siem-integration.md not found walking up from %s", dir)
		}
		dir = parent
	}
}
