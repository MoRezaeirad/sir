// Package ledger implements an append-only hash-chained ledger for sir.
// The ledger stores paths, labels, hashes, verdicts, timestamps, and optional
// redacted investigation evidence. Raw secrets are never persisted.
package ledger

import (
	"path/filepath"
	"time"

	"github.com/somoore/sir/pkg/session"
)

// Entry is a single ledger entry.
type Entry struct {
	Index       int       `json:"index"`
	Timestamp   time.Time `json:"timestamp"`
	PrevHash    string    `json:"prev_hash"`
	EntryHash   string    `json:"entry_hash"`
	HashVersion int       `json:"hash_version,omitempty"`

	// Tool call context
	ToolName string `json:"tool_name"`
	Verb     string `json:"verb"`
	Target   string `json:"target"`

	// Labels assigned
	Sensitivity string `json:"sensitivity,omitempty"`
	Trust       string `json:"trust,omitempty"`
	Provenance  string `json:"provenance,omitempty"`

	// Verdict
	Decision string `json:"decision"` // allow, deny, ask
	Reason   string `json:"reason"`

	// Optional metadata
	ContentHash string `json:"content_hash,omitempty"` // SHA-256 of content, never content itself
	Preview     string `json:"preview,omitempty"`      // first 80 chars, redacted if secret
	Severity    string `json:"severity,omitempty"`     // HIGH, MEDIUM, LOW
	AlertType   string `json:"alert_type,omitempty"`   // sentinel_mutation, posture_tamper, etc.
	DetectionID string `json:"detection_id,omitempty"` // stable behavior-detection ID (pkg/detect)
	// DetectionRoute is the computed escalation route (silent/local/siem/slack)
	// for this entry's detection, including dynamic promotion (suspicion,
	// repetition). It is transient: not persisted and not hashed, set at stamp
	// time and consumed by the same-process telemetry/Slack emit.
	DetectionRoute string `json:"-"`
	// SignalIDs are the additive secondary correlation tags (DETECT-1): every
	// detection that fired for this decision, primary first. Transient like
	// DetectionRoute — set at stamp time, emitted as sir.signal_ids, never
	// hashed or persisted.
	SignalIDs   []string `json:"-"`
	Evidence    string   `json:"evidence,omitempty"`     // optional redacted investigation evidence
	Agent       string   `json:"agent,omitempty"`        // target agent id for tamper alerts
	DiffSummary string   `json:"diff_summary,omitempty"` // concise diff summary for posture alerts
	Restored    bool     `json:"restored,omitempty"`     // whether auto-restore succeeded
	LatencyMs   int      `json:"latency_ms,omitempty"`   // sir decision latency in ms (perf metric)

	// BaseVerdict is the native + developer-workflow-floor verdict BEFORE any
	// advisory policy-provider composition — the same "base" that `sir policy
	// explain` computes live. Persisting it lets `sir why` show whether a
	// provider verdict actually changed the outcome (base allow → final ask) or
	// was suppressed by a floor, without re-running the engine. Empty on entries
	// written before this field existed (treated as "unknown" by readers). Not
	// hashed (advisory, post-decision metadata; mirrors ProviderVerdicts).
	BaseVerdict string `json:"base_verdict,omitempty"`
	// ProviderVerdicts records advisory verdicts from registered policy
	// providers (OPA, Cedar, custom packs) that contributed to this decision,
	// attributed separately from native policy rules. Policy metadata only —
	// never raw secrets. Not hashed (advisory, post-decision metadata).
	ProviderVerdicts []ProviderVerdictRecord `json:"provider_verdicts,omitempty"`
	// ProviderFailures records policy/advisory providers that failed to produce
	// a verdict (timeout, missing entrypoint, malformed output). Surfaced so the
	// audit trail shows a provider's input was missing (fail-open) rather than
	// silently absent. Not hashed.
	ProviderFailures []ProviderFailureRecord `json:"provider_failures,omitempty"`
}

// ProviderVerdictRecord is a single policy-provider verdict as persisted in the
// ledger. Fields are policy metadata (provider name, decision, matched rule
// IDs, reason) — never raw secrets.
type ProviderVerdictRecord struct {
	Provider     string   `json:"provider"`
	Verdict      string   `json:"verdict"`
	RulesMatched []string `json:"rules_matched,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	Used         bool     `json:"used"`
}

// ProviderFailureRecord is a single provider failure as persisted in the
// ledger. Reason is the (non-secret) error string; Status classifies the
// fail-open behavior and TimedOut remains as a compatibility flag.
type ProviderFailureRecord struct {
	Provider string `json:"provider"`
	Kind     string `json:"kind,omitempty"`
	Status   string `json:"status,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Behavior string `json:"behavior,omitempty"`
	TimedOut bool   `json:"timed_out,omitempty"`
}

const (
	legacyHashVersion  = 1
	currentHashVersion = 4
)

// LedgerPath returns the path to the ledger file for a project.
func LedgerPath(projectRoot string) string {
	return filepath.Join(session.StateDir(projectRoot), "ledger.jsonl")
}
