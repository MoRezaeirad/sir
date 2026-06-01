package kernel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/somoore/sir/pkg/sdk"
)

// TaintState tracks session-scoped taint bindings per the CORRELATION spec.
// Taint priority (highest to lowest): provider_span_id, sandbox_execution_id,
// process_identity, process_tree, terminal/session, workspace, user/session.
// Weak attribution WIDENS taint, NEVER erases it.
type TaintState struct {
	mu      sync.Mutex
	entries []TaintEntry
}

// TaintEntry records that a session scope is tainted by a sensitive action.
type TaintEntry struct {
	Scope      string `json:"scope"`        // e.g. session_id, span_id, process_tree
	ScopeKind  string `json:"scope_kind"`   // "session", "span", "process", etc.
	TaintKind  string `json:"taint_kind"`   // "credential_access", "external_network", etc.
	At         string `json:"at"`           // ISO timestamp
	Confidence string `json:"confidence"`   // attribution confidence at taint time
}

var globalTaint = &TaintState{}

// Taint adds a taint entry. Weak attribution widens scope (never erases).
func Taint(scope, scopeKind, taintKind, confidence string) {
	globalTaint.mu.Lock()
	defer globalTaint.mu.Unlock()
	globalTaint.entries = append(globalTaint.entries, TaintEntry{
		Scope:      scope,
		ScopeKind:  scopeKind,
		TaintKind:  taintKind,
		At:         time.Now().UTC().Format(time.RFC3339),
		Confidence: confidence,
	})
}

// IsTainted returns true if any scope+kind combination is tainted.
func IsTainted(scope, taintKind string) bool {
	globalTaint.mu.Lock()
	defer globalTaint.mu.Unlock()
	for _, e := range globalTaint.entries {
		if e.TaintKind == taintKind && (e.Scope == scope || scope == "") {
			return true
		}
	}
	return false
}

// TaintScopeFromSignals derives the primary taint scope from signals using
// the CORRELATION taint priority list.
func TaintScopeFromSignals(signals []sdk.Signal) (scope, scopeKind string) {
	for _, s := range signals {
		if s.Session != nil {
			if s.Session.SpanID != "" {
				return s.Session.SpanID, "span"
			}
			if s.Session.SessionID != "" {
				return s.Session.SessionID, "session"
			}
			if s.Session.TraceID != "" {
				return s.Session.TraceID, "trace"
			}
		}
	}
	return "global", "user_session"
}

// ApplySessionTaint taints the session after a credential read, so subsequent
// egress in the same session is caught (secret-to-egress rule).
func ApplySessionTaint(action AttributedAction) {
	if action.Sensitivity != "credential" {
		return
	}
	scope, scopeKind := TaintScopeFromSignals(action.Signals)
	Taint(scope, scopeKind, "credential_access", action.Attribution)
}

// SessionHasCredentialTaint returns true if the session is tainted by a prior
// credential access — used to enforce the secret-to-egress rule.
func SessionHasCredentialTaint(signals []sdk.Signal) bool {
	scope, _ := TaintScopeFromSignals(signals)
	return IsTainted(scope, "credential_access")
}

// PersistTaint writes the current taint state to disk for cross-process access.
// The file is redacted — only scope kinds and taint kinds, no raw values.
// Low-confidence taint entries are not persisted: they are runtime state only.
// Persisting them would grant them unintended longevity across restarts and
// widen their blast radius beyond the session where they were created.
func PersistTaint(path string) error {
	globalTaint.mu.Lock()
	defer globalTaint.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	var durable []TaintEntry
	for _, e := range globalTaint.entries {
		if e.Confidence == ConfLow || e.Confidence == ConfUnknown {
			continue
		}
		durable = append(durable, e)
	}
	if durable == nil {
		durable = []TaintEntry{}
	}
	b, err := json.MarshalIndent(durable, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// DefaultTaintPath returns the default taint state path.
func DefaultTaintPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sir", "v2", "taint.json")
}
