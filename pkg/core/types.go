package core

import "github.com/somoore/sir/pkg/policy"

// Request is the evaluation request sent to mister-core via MSTR/1.
//
// A Request is single-use and not safe for concurrent evaluation: the Go
// fallback lazily parses LeaseJSON's forbidden_verbs once and caches it on the
// request (see forbiddenVerbs), so it never re-parses the lease on a hot path.
type Request struct {
	Version   uint8       `json:"-"`
	LeaseJSON []byte      `json:"-"`
	ToolName  string      `json:"tool_name"`
	Intent    Intent      `json:"intent"`
	Session   SessionInfo `json:"session"`
	// PolicyVerdicts carries advisory verdicts from registered PolicyProviders.
	// Rust mister-core receives them via the wire and composes them under native
	// safety floors. The Go fallback mirrors that composition so provider verdicts
	// can only escalate allow to ask and never lower a native deny.
	PolicyVerdicts []policy.PolicyVerdict `json:"-"`

	// Cached structural parse of LeaseJSON's forbidden_verbs for the Go
	// fallback. Transient (json:"-"), populated on first use by forbiddenVerbs.
	// forbiddenParseErr fails closed: a lease that cannot be parsed structurally
	// is treated as forbidding everything (deny), per corrupted-state-fails-closed.
	forbiddenParsed    bool
	forbiddenParseErr  bool
	forbiddenVerbCache []policy.Verb
}

// Intent describes the classified intent of a tool call.
type Intent struct {
	Verb          policy.Verb `json:"verb"`
	Target        string      `json:"target"`
	Labels        []Label     `json:"labels"`
	DerivedLabels []Label     `json:"derived_labels,omitempty"`
	IsPosture     bool        `json:"is_posture"`
	IsSensitive   bool        `json:"is_sensitive"`
	IsTripwire    bool        `json:"is_tripwire"`
	IsDelegation  bool        `json:"is_delegation"`
}

// Label represents an IFC label.
type Label struct {
	Sensitivity string `json:"sensitivity"`
	Trust       string `json:"trust"`
	Provenance  string `json:"provenance"`
}

// SessionInfo is the session context sent to mister-core.
type SessionInfo struct {
	SecretSession bool `json:"secret_session"`
	// WasSecret is the monotonic high-water mark: true if the session has ever
	// been secret-labeled, even after the turn-scoped SecretSession flag clears
	// on a turn boundary. Carried to the oracle as session_was_secret so egress
	// and pushes re-prompt instead of silently reverting to the clean baseline.
	WasSecret             bool `json:"was_secret"`
	RecentlyReadUntrusted bool `json:"recently_read_untrusted"`
	// UntrustedContentThisTurn is the turn-scoped weak-integrity signal: any
	// untrusted content (MCP tool output / fetched web content) was ingested
	// this turn. Gates same-turn external egress; clears on the next turn so
	// cross-turn workflows stay quiet. Carried as session_untrusted_this_turn.
	UntrustedContentThisTurn bool   `json:"untrusted_content_this_turn"`
	DenyAll                  bool   `json:"deny_all"`
	ApprovalScope            string `json:"approval_scope,omitempty"`
	TurnCounter              int    `json:"turn_counter,omitempty"`
}

// ProviderFailure records a policy/advisory provider that failed to produce a
// verdict during evaluation (timeout, missing entrypoint, malformed output).
// Failures are non-fatal — evaluation falls open to native floors — but they
// are surfaced so the ledger and `sir why` can show that a provider's input was
// missing rather than silently absent. Provider/Reason are policy metadata, not
// secrets.
type ProviderFailure struct {
	Provider string `json:"provider"`
	Kind     string `json:"kind,omitempty"`
	Status   string `json:"status,omitempty"`
	Reason   string `json:"reason"`
	Behavior string `json:"behavior,omitempty"`
	TimedOut bool   `json:"timed_out"`
}

// Response is the verdict from mister-core.
//
// ProviderVerdicts and ProviderFailures are Go-populated AFTER core.Evaluate
// returns — they are NOT decoded from the Rust wire (json:"-"). The Go hook
// layer collects provider verdicts before calling Rust and attaches them here so
// they can reach the ledger and `sir why`, attributed separately from native
// policy rules.
type Response struct {
	Decision policy.Verdict `json:"verdict"`
	Reason   string         `json:"reason"`
	Risk     string         `json:"risk_tier,omitempty"`

	// BaseVerdict is the verdict BEFORE advisory policy-provider composition,
	// Go-populated by evaluatePolicy (not on the Rust wire). When provider
	// verdicts are present and the final verdict is "ask", it records what the
	// native + floor decision would have been so `sir why` can tell whether a
	// provider escalated the outcome. Empty means "same as Decision".
	BaseVerdict policy.Verdict `json:"-"`

	ProviderVerdicts []policy.PolicyVerdict `json:"-"`
	ProviderFailures []ProviderFailure      `json:"-"`

	// --- PDP authoritative-override audit (Go-populated, not on the Rust wire).
	// Set only when an authoritative policy_provider replaced the native decision.
	// These flow to the ledger's ProviderPolicyEvidence so an override is
	// forensically attributable. Empty AuthoritativeProvider means "no override".

	// AuthoritativeActive is true when an authoritative policy_provider produced
	// the final verdict (grant OR fail-closed). When set, the verdict is FINAL:
	// no downstream native convenience layer (ask→allow suppression, observe-mode
	// downgrades) may touch it. This is the structural seal that keeps the
	// override actually holding through the rest of the hook pipeline.
	AuthoritativeActive bool `json:"-"`
	// AuthoritativeProvider is the name of the authoritative provider that decided.
	AuthoritativeProvider string `json:"-"`
	// AuthoritativeNativeBase is the verdict native SIR would have returned
	// (native + advisory, floors applied) before the override — the audit delta.
	AuthoritativeNativeBase string `json:"-"`
	// AuthoritativeFloorsBypassed is true when a real authoritative verdict (not a
	// fail-closed substitute) replaced the native decision.
	AuthoritativeFloorsBypassed bool `json:"-"`
	// AuthoritativeFailClosed is true when the override is a fail-closed substitute
	// because the provider could not produce a decision.
	AuthoritativeFailClosed bool `json:"-"`
}

// CoreBinaryPath is the path to the mister-core binary.
// It can be overridden for testing.
var CoreBinaryPath = "mister-core"
