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

// Response is the verdict from mister-core.
type Response struct {
	Decision policy.Verdict `json:"verdict"`
	Reason   string         `json:"reason"`
	Risk     string         `json:"risk_tier,omitempty"`
}

// CoreBinaryPath is the path to the mister-core binary.
// It can be overridden for testing.
var CoreBinaryPath = "mister-core"
