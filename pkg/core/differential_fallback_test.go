package core

// Differential parity test: Go fallback vs. real Rust mister-core.
//
// WHY THIS EXISTS
//
// core.Evaluate (core.go) forks at runtime: if the mister-core binary is on
// PATH it shells out to Rust (the oracle); if it is absent it runs the Go
// localEvaluate fallback (local_fallback*.go). The project's headline security
// invariant is "Go may add restrictions Rust cannot see, but Go must never
// widen a Rust deny" (CLAUDE.md, Core model). Concretely, on any given input
// the Go fallback must be NO MORE PERMISSIVE than Rust.
//
// Until now that guarantee was asserted by hand-written per-case tests
// (TestLocalEvaluate_* in protocol_local_fallback_test.go) plus prose comments
// like "kept byte-for-byte in step with policy_guards.rs". Those drift: a new
// Rust deny that nobody mirrors into Go — and nobody writes a case for — would
// silently make the fallback path more permissive, with no failing test.
//
// This test closes that gap mechanically (CLAUDE.md non-negotiable #10: public
// guarantees need tests or contract checks). It generates a broad corpus of
// Requests across the full verb x session-flag x label space — each labeled set
// is exercised in BOTH placements, as an immediate Intent.Labels and as an
// Intent.DerivedLabels (lineage-carried), since the two reach the flow check via
// different fields and could diverge independently — runs each through BOTH the
// real Rust binary and the Go fallback via the production core.Evaluate entry
// point, and asserts:
//
//	permissiveness(go_fallback) <= permissiveness(rust)        // never widens
//
// where allow(0) < ask(1) < deny(2). Equality is NOT required: the fallback is
// explicitly allowed to be stricter (deny where Rust asks). Only the dangerous
// direction — Go more permissive than Rust — fails the test.
//
// If the Rust binary cannot be located/built, the test SKIPS (so `go test ./...`
// stays green on machines without a Rust toolchain). In CI, where the binary is
// built, it RUNS and enforces the invariant. To force a build locally:
//
//	cargo build --release --manifest-path mister-core/Cargo.toml
//	go test ./pkg/core/ -run TestDifferentialFallbackNeverMorePermissive -v

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

// permissiveness orders verdicts from most permissive (allow) to least (deny).
// A higher number means a STRICTER decision. The invariant is that the Go
// fallback's permissiveness rank must be >= Rust's (i.e. Go is never LOWER /
// more permissive). Any unknown verdict is treated as maximally strict so a
// decode glitch can never masquerade as "more permissive and therefore a bug".
func permissiveness(v policy.Verdict) int {
	switch v {
	case policy.VerdictAllow:
		return 0
	case policy.VerdictAsk:
		return 1
	case policy.VerdictDeny:
		return 2
	default:
		return 3 // unknown — treat as strictest; never reads as "widened"
	}
}

// locateMisterCore returns the path to a runnable mister-core binary, or ""
// if none is available. It checks (in order): an explicit SIR_MISTER_CORE_BIN
// override, the cargo release/debug output dirs, then PATH.
func locateMisterCore(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SIR_MISTER_CORE_BIN"); p != "" {
		if isExecutableFile(p) {
			return p
		}
		t.Fatalf("SIR_MISTER_CORE_BIN=%q is not an executable file", p)
	}
	root := repoRootForCore(t)
	for _, rel := range []string{
		filepath.Join("target", "release", "mister-core"),
		filepath.Join("target", "debug", "mister-core"),
	} {
		cand := filepath.Join(root, rel)
		if isExecutableFile(cand) {
			return cand
		}
	}
	if p, err := exec.LookPath("mister-core"); err == nil {
		return p
	}
	return ""
}

func isExecutableFile(p string) bool {
	info, err := os.Stat(p)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

// repoRootForCore walks up from the test's working directory until it finds the
// go.mod, so the test works regardless of where `go test` is invoked from.
func repoRootForCore(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate repo root (go.mod) from test working dir")
		}
		dir = parent
	}
}

// evalRust runs a Request through the real Rust binary via the production
// core.Evaluate path. The integrity manifest is bypassed for the test binary by
// temporarily clearing it is unnecessary — Evaluate skips the check when no
// manifest exists, which is the normal case in a test tree.
func evalRust(t *testing.T, binPath string, req *Request) policy.Verdict {
	t.Helper()
	prev := CoreBinaryPath
	CoreBinaryPath = binPath
	t.Cleanup(func() { CoreBinaryPath = prev })

	resp, err := Evaluate(req)
	if err != nil {
		t.Fatalf("rust Evaluate error: %v", err)
	}
	if resp == nil {
		t.Fatal("rust Evaluate returned nil response")
	}
	return resp.Decision
}

// evalGoFallback runs the same Request through the Go fallback directly. This is
// exactly the code core.Evaluate runs when the binary is absent (core.go:84).
func evalGoFallback(t *testing.T, req *Request) policy.Verdict {
	t.Helper()
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("go fallback error: %v", err)
	}
	if resp == nil {
		t.Fatal("go fallback returned nil response")
	}
	return resp.Decision
}

// generateCorpus builds a broad, deterministic set of Requests covering the
// cross product of every known verb with a representative set of session
// postures and label conditions. It is intentionally exhaustive over verbs (the
// dimension most likely to grow and drift) and samples the session/label space
// at the points that flip native floors (secret, was-secret, untrusted-read,
// untrusted-this-turn, deny-all, credential/untrusted labels).
func generateCorpus() []namedRequest {
	// Labels must use the EXACT vocabulary mister-core's parser accepts, on all
	// three axes — Rust rejects an out-of-vocabulary value with a hard
	// "bad request" error, which core.Evaluate turns into a fail-closed deny.
	// Comparing the Go fallback against that parse-error deny (instead of the
	// real oracle verdict) silently fabricates divergences, so every field here
	// is drawn from the Rust enums:
	//   Sensitivity ∈ {public, internal, restricted, secret}  (mister-shared/src/labels.rs)
	//   Trust       ∈ {trusted, verified_origin, verified_internal, untrusted}
	//   Provenance  ∈ {user, agent, external_package, mcp_tool, package_install}
	// In particular Provenance must NOT be "local"/"external" — those are not in
	// the enum and make the Rust subprocess exit non-zero (→ deny), which is the
	// exact trap a reviewer flagged on the first revision of this test.
	secretLabel := Label{Sensitivity: "secret", Trust: "trusted", Provenance: "user"}
	untrustedLabel := Label{Sensitivity: "public", Trust: "untrusted", Provenance: "external_package"}
	// restricted is the OTHER sensitivity (besides secret) that trips Rust's
	// ifc::check_flow on an untrusted sink, so it must be exercised too.
	restrictedLabel := Label{Sensitivity: "restricted", Trust: "verified_internal", Provenance: "agent"}

	sessions := []struct {
		name string
		s    SessionInfo
	}{
		{"clean", SessionInfo{}},
		{"secret", SessionInfo{SecretSession: true}},
		{"was-secret", SessionInfo{WasSecret: true}},
		{"untrusted-read", SessionInfo{RecentlyReadUntrusted: true}},
		{"untrusted-turn", SessionInfo{UntrustedContentThisTurn: true}},
		{"deny-all", SessionInfo{DenyAll: true}},
		{"secret+untrusted", SessionInfo{SecretSession: true, UntrustedContentThisTurn: true}},
	}

	// A non-empty label set is exercised in BOTH placements: as an immediate
	// Intent.Labels and as an Intent.DerivedLabels (lineage-carried). The two
	// reach the fallback's flow check via different fields (local_fallback.go
	// merges them into effectiveLabels; hasDerivedSecret keys on DerivedLabels
	// only), and the Rust oracle distinguishes them too, so a Go vs Rust gap
	// could exist in one placement but not the other. Empty labels need no
	// placement. "derived" here means the label rides in Intent.DerivedLabels.
	type labelSet struct {
		name      string
		labels    []Label
		isDerived bool
	}
	var labelSets []labelSet
	labelSets = append(labelSets, labelSet{name: "no-labels"})
	for _, base := range []struct {
		tag   string
		label Label
	}{
		{"secret", secretLabel},
		{"untrusted", untrustedLabel},
		{"restricted", restrictedLabel},
	} {
		labelSets = append(labelSets,
			labelSet{name: base.tag + "-label", labels: []Label{base.label}, isDerived: false},
			labelSet{name: base.tag + "-derived", labels: []Label{base.label}, isDerived: true},
		)
	}

	var corpus []namedRequest
	for _, verb := range policy.AllVerbs {
		for _, sess := range sessions {
			for _, ls := range labelSets {
				intent := Intent{Verb: verb, Target: "differential-corpus-target"}
				if ls.isDerived {
					intent.DerivedLabels = ls.labels
				} else {
					intent.Labels = ls.labels
				}
				req := &Request{
					ToolName: "Bash",
					Intent:   intent,
					Session:  sess.s,
					// Supply the production default lease (empty forbidden_verbs,
					// matching lease.DefaultLease()). This is load-bearing: with NO
					// lease, Go's forbiddenVerbs() parses an empty set AND Rust falls
					// back to its OWN built-in default-deny for net_external/dns —
					// so the two engines diverge on an input production never sends
					// (loadRuntimeLease always returns DefaultLease()). Sending the
					// real default lease makes both engines evaluate the same
					// realistic posture instead of two different "no lease" defaults.
					LeaseJSON: []byte(`{"forbidden_verbs":[]}`),
				}
				corpus = append(corpus, namedRequest{
					name: verb.String() + "/" + sess.name + "/" + ls.name,
					req:  req,
				})
			}
		}
	}
	return corpus
}

type namedRequest struct {
	name string
	req  *Request
}

// knownDivergence is one quarantined (verb/session/labelset) -> (rust, go)
// entry from testdata/fallback-parity/known_divergences.txt.
type knownDivergence struct {
	rust policy.Verdict
	go_  policy.Verdict
}

// loadKnownDivergences parses the shrink-only quarantine file. Lines are
// "<case> <rust> <go>"; blank lines and "#" comments are ignored.
func loadKnownDivergences(t *testing.T) map[string]knownDivergence {
	t.Helper()
	path := filepath.Join(repoRootForCore(t), "testdata", "fallback-parity", "known_divergences.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read quarantine file %s: %v", path, err)
	}
	out := map[string]knownDivergence{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			t.Fatalf("malformed quarantine line %q (want '<case> <rust> <go>')", line)
		}
		out[fields[0]] = knownDivergence{rust: policy.Verdict(fields[1]), go_: policy.Verdict(fields[2])}
	}
	return out
}

// TestDifferentialFallbackNeverMorePermissive is the mechanical contract check
// for the "Go fallback never widens Rust" invariant. See file header.
//
// It enforces the invariant for every currently-aligned case, and pins the
// currently-known divergences to a shrink-only quarantine file. The test fails
// on (a) NEW drift not in the file, (b) a quarantined case whose verdicts moved,
// and (c) a stale quarantine entry that no longer diverges (forcing the file to
// shrink as the fallback is hardened). This satisfies CLAUDE.md #10 mechanically.
func TestDifferentialFallbackNeverMorePermissive(t *testing.T) {
	binPath := locateMisterCore(t)
	if binPath == "" {
		// Belt-and-suspenders against a silent CI false-green: when
		// SIR_REQUIRE_DIFFERENTIAL is set (the CI step sets it), a missing
		// binary is a HARD FAILURE, not a skip — a parity test that quietly
		// skips would read as green while enforcing nothing. Locally, with the
		// var unset, it skips so `go test ./...` stays green without a Rust
		// toolchain.
		msg := "mister-core binary not found (build with `cargo build --release " +
			"-p mister-core` or set SIR_MISTER_CORE_BIN)"
		if os.Getenv("SIR_REQUIRE_DIFFERENTIAL") != "" {
			t.Fatalf("%s; SIR_REQUIRE_DIFFERENTIAL is set so this test must not skip", msg)
		}
		t.Skip(msg + "; skipping differential parity test")
	}

	corpus := generateCorpus()
	if len(corpus) == 0 {
		t.Fatal("empty corpus — policy.AllVerbs is empty?")
	}
	known := loadKnownDivergences(t)
	t.Logf("differential corpus: %d cases against %s (%d quarantined divergences)",
		len(corpus), binPath, len(known))

	seen := map[string]bool{}
	var widened int
	for _, nc := range corpus {
		nc := nc
		t.Run(nc.name, func(t *testing.T) {
			// Evaluate against the real binary first, then the fallback, on
			// independent copies so neither mutates state the other reads
			// (Request caches a structural lease parse on first use).
			rustVerdict := evalRust(t, binPath, cloneRequest(nc.req))
			goVerdict := evalGoFallback(t, cloneRequest(nc.req))

			diverges := permissiveness(goVerdict) < permissiveness(rustVerdict)
			q, quarantined := known[nc.name]

			if diverges {
				seen[nc.name] = true
				switch {
				case !quarantined:
					widened++
					t.Errorf(
						"NEW DRIFT: Go fallback is MORE PERMISSIVE than Rust (not in quarantine)\n"+
							"  case:    %s\n"+
							"  rust:    %s\n"+
							"  go:      %s\n"+
							"  meaning: a session on the degraded fallback path would be allowed "+
							"something the oracle gates. Mirror the Rust rule into "+
							"local_fallback*.go (or tighten it). Do NOT add this case to the "+
							"quarantine file to silence it — new drift must be fixed.",
						nc.name, rustVerdict, goVerdict)
				case q.rust != rustVerdict || q.go_ != goVerdict:
					t.Errorf(
						"QUARANTINE MOVED: known divergence %s changed verdicts\n"+
							"  was: rust=%s go=%s\n"+
							"  now: rust=%s go=%s\n"+
							"  update or remove the line in testdata/fallback-parity/known_divergences.txt.",
						nc.name, q.rust, q.go_, rustVerdict, goVerdict)
				}
			}
		})
	}

	// Shrink-only enforcement: every quarantined case must still diverge. A
	// listed case that no longer diverges means the fallback was hardened (good)
	// but the stale line was left behind — delete it so the quarantine can only
	// shrink, never silently retain fixed entries.
	for name := range known {
		if !seen[name] {
			t.Errorf(
				"STALE QUARANTINE: %s no longer diverges — delete its line from "+
					"testdata/fallback-parity/known_divergences.txt (the quarantine must only shrink).",
				name)
		}
	}

	if widened == 0 {
		t.Logf("OK: no NEW drift; %d known divergences still quarantined across %d cases",
			len(known), len(corpus))
	}
}

// cloneRequest returns a deep-enough copy of req for an independent evaluation:
// a fresh struct with copied label slices and the lazy lease-parse cache reset.
func cloneRequest(req *Request) *Request {
	out := &Request{
		Version:   req.Version,
		ToolName:  req.ToolName,
		Intent:    req.Intent,
		Session:   req.Session,
		LeaseJSON: append([]byte(nil), req.LeaseJSON...),
	}
	out.Intent.Labels = append([]Label(nil), req.Intent.Labels...)
	out.Intent.DerivedLabels = append([]Label(nil), req.Intent.DerivedLabels...)
	out.PolicyVerdicts = append([]policy.PolicyVerdict(nil), req.PolicyVerdicts...)
	return out
}
