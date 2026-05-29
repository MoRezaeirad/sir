// Package session manages sir session state persistence.
// Session state tracks security-relevant flags across tool calls within a session.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/somoore/sir/pkg/policy"
)

// TurnGapThreshold is the minimum duration between tool calls that signals a new turn.
// Claude Code tool calls within a single response typically fire within milliseconds of each
// other. A gap longer than this threshold means the model finished responding and the user
// sent a new message — i.e., a new "turn".
const TurnGapThreshold = 30 * time.Second

// State holds the mutable session state for a sir session.
// All exported mutation methods are guarded by mu to prevent data races
// when Claude Code fires parallel tool calls.
type State struct {
	mu                    sync.RWMutex         `json:"-"`
	SchemaVersion         uint32               `json:"schema_version"`
	SessionID             string               `json:"session_id"`
	ProjectRoot           string               `json:"project_root"`
	StartedAt             time.Time            `json:"started_at"`
	SecretSession         bool                 `json:"secret_session"`
	SessionEverSecret     bool                 `json:"session_ever_secret,omitempty"` // monotonic high-water mark: true once secret-labeled, cleared only by `sir unlock`
	SecretSessionSince    time.Time            `json:"secret_session_since,omitempty"`
	ApprovalScope         policy.ApprovalScope `json:"approval_scope,omitempty"` // "session" (default) or "turn"
	TurnCounter           int                  `json:"turn_counter"`
	SecretApprovalTurn    int                  `json:"secret_approval_turn,omitempty"` // turn when secret was approved
	LastToolCallAt        time.Time            `json:"last_tool_call_at,omitempty"`    // timestamp of most recent PreToolUse
	RecentlyReadUntrusted bool                 `json:"recently_read_untrusted"`
	PendingInstall        *PendingInstall      `json:"pending_install,omitempty"`
	PostureHashes         map[string]string    `json:"posture_hashes,omitempty"`
	DenyAll               bool                 `json:"deny_all"`
	DenyAllReason         string               `json:"deny_all_reason,omitempty"`
	LeaseHash             string               `json:"lease_hash,omitempty"`       // SHA-256 of lease.json at session start
	GlobalHookHash        string               `json:"global_hook_hash,omitempty"` // SHA-256 of the managed hook/config subtrees for all registered host agents at session start
	SessionHash           string               `json:"session_hash,omitempty"`     // SHA-256 of session.json content (excludes this field)

	// MCP defense fields
	Posture                       policy.PostureState `json:"posture,omitempty"`                          // "normal", "elevated", "critical"
	MCPInjectionSignals           []string            `json:"mcp_injection_signals,omitempty"`            // pattern names from injection scans
	TaintedMCPServers             []string            `json:"tainted_mcp_servers,omitempty"`              // MCP servers that returned injection signals
	AcknowledgedTaintedMCPServers []string            `json:"acknowledged_tainted_mcp_servers,omitempty"` // tainted servers the developer already chose to continue using this session

	// PendingInjectionAlert is set by PostToolUse when MCP response injection is
	// detected. The next PreToolUse checks this flag and returns "ask" before
	// processing the tool call, closing the one-action window.
	PendingInjectionAlert bool   `json:"pending_injection_alert,omitempty"`
	InjectionAlertDetail  string `json:"injection_alert_detail,omitempty"`

	// Hook expansion fields
	TurnAdvancedByHook bool              `json:"turn_advanced_by_hook,omitempty"` // true if UserPromptSubmit hook advanced the turn
	InstructionHashes  map[string]string `json:"instruction_hashes,omitempty"`    // SHA-256 of loaded instruction files

	// Artifact lineage fields
	ActiveEvidence     []LineageEvidence            `json:"active_evidence,omitempty"`
	DerivedFileLineage map[string]DerivedPathRecord `json:"derived_file_lineage,omitempty"`

	// MCPOnboardingCalls counts calls to each approved MCP server in the
	// current session. Used by the onboarding gate to end the
	// speed-bump window after a configurable number of calls. Session-scoped
	// (resets per session) so the friction reappears when a new agent
	// session starts — a deliberate UX choice to re-acquaint the user with
	// unfamiliar tools, NOT a security control.
	MCPOnboardingCalls map[string]int `json:"mcp_onboarding_calls,omitempty"`

	// ApprovalGrants are explicit developer approvals recorded through
	// `sir approve`. They only convert policy ASK verdicts into ALLOW for an
	// exact verb/target retry; DENY verdicts are never overridden.
	ApprovalGrants []ApprovalGrant `json:"approval_grants,omitempty"`

	// PromptedIntents counts how many times each verb/target intent has been
	// prompted (ask) or blocked (deny) in this session. It powers the
	// real-time repeated_denied_intent detection and the dynamic egress
	// escalation. Session-scoped; never used to widen authority on its own.
	PromptedIntents map[string]int `json:"prompted_intents,omitempty"`

	// DecisionStartedAt marks when the current decision began, for measuring
	// decision latency. Transient: never persisted or hashed.
	DecisionStartedAt time.Time `json:"-"`

	// ThinkingGuardActive is set per hook invocation when the host is Claude
	// Code with extended thinking enabled. The thinking guard degrades an
	// interactive ask to a deny on that path (an ask mid-thinking-turn wedges
	// the conversation), and ledger writers consult this so the recorded
	// decision matches the agent-visible deny. Transient: never persisted or
	// hashed — it is recomputed from the environment on every invocation.
	ThinkingGuardActive bool `json:"-"`

	// MCPAuthorityChangeAt is when an approved MCP server's trust footing last
	// changed this session (binary/config drift). Used to correlate a later
	// privileged action into the mcp_change_then_privileged_use detection.
	MCPAuthorityChangeAt time.Time `json:"mcp_authority_change_at,omitempty"`

	// PendingAutoLeaseHosts records hosts whose external-egress ask is awaiting
	// observed approval. A PreToolUse ask marks the host; the matching
	// PostToolUse (which only fires if the developer approved and the tool ran)
	// consumes it to mint a short TTL host lease. Values are the mark time so
	// stale markers are ignored.
	PendingAutoLeaseHosts map[string]time.Time `json:"pending_auto_lease_hosts,omitempty"`

	// PendingMCPDriftAck / AcknowledgedMCPDrift implement MCPDRIFT-1: a drifted
	// MCP binary hash whose drift ask is awaiting observed approval is marked
	// pending at PreToolUse and promoted to acknowledged at PostToolUse (the
	// tool only runs if the developer approved). A later call with the SAME
	// acknowledged hash skips the re-ask; a NEW (different) hash is absent here
	// and still asks. Keyed server -> hash.
	PendingMCPDriftAck   map[string]string `json:"pending_mcp_drift_ack,omitempty"`
	AcknowledgedMCPDrift map[string]string `json:"acknowledged_mcp_drift,omitempty"`

	// ApprovedEphemeralPackages implements NPX-1: ephemeral packages (npx) whose
	// run was approved and observed this session, so the same package stops
	// re-prompting. Cleared on secret-session entry. Keyed by resolved package.
	ApprovedEphemeralPackages map[string]bool `json:"approved_ephemeral_packages,omitempty"`
	PendingEphemeralApproval  map[string]bool `json:"pending_ephemeral_approval,omitempty"`

	// ApprovedPushRemotes implements REMOTE-1: a git remote whose push was
	// approved and observed this session stops re-prompting (session-scoped,
	// clears with the session). Keyed by remote name.
	ApprovedPushRemotes map[string]bool `json:"approved_push_remotes,omitempty"`
	PendingPushRemote   map[string]bool `json:"pending_push_remote,omitempty"`
}

// ApprovalGrant records a manual approval for one retry or for a short-lived
// session window. Empty ExpiresAt means the grant lasts until consumed or the
// session file is discarded.
type ApprovalGrant struct {
	Verb          string    `json:"verb"`
	Target        string    `json:"target"`
	Scope         string    `json:"scope,omitempty"`
	ExpiresAt     time.Time `json:"expires_at,omitempty"`
	UsesRemaining int       `json:"uses_remaining,omitempty"`
	Reason        string    `json:"reason,omitempty"`
}

// BumpMCPOnboardingCall increments and returns the session call count for
// the named MCP server. Lock-safe; callers must hold the session handle.
func (s *State) BumpMCPOnboardingCall(serverName string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MCPOnboardingCalls == nil {
		s.MCPOnboardingCalls = make(map[string]int, 4)
	}
	s.MCPOnboardingCalls[serverName]++
	return s.MCPOnboardingCalls[serverName]
}

// MCPOnboardingCallCount returns the session call count for the named
// server without incrementing. Lock-safe.
func (s *State) MCPOnboardingCallCount(serverName string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.MCPOnboardingCalls[serverName]
}

// RecordPromptedIntent increments and returns the session count for an intent
// key (a verb/target pair). Lock-safe; callers hold the session handle.
func (s *State) RecordPromptedIntent(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PromptedIntents == nil {
		s.PromptedIntents = make(map[string]int, 4)
	}
	s.PromptedIntents[key]++
	return s.PromptedIntents[key]
}

// PromptCount returns how many times an intent key has been prompted/blocked
// this session without incrementing. Lock-safe.
func (s *State) PromptCount(key string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PromptedIntents[key]
}

// autoLeaseMarkWindow bounds how long a pending auto-lease marker stays
// consumable. A PreToolUse ask and its PostToolUse fire back-to-back, so a
// generous few-minute window is ample while preventing a much-later execution
// from minting a lease.
const autoLeaseMarkWindow = 10 * time.Minute

// MarkPendingAutoLease records that an external-egress ask for host is awaiting
// observed approval. Lock-safe.
func (s *State) MarkPendingAutoLease(host string) {
	if host == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PendingAutoLeaseHosts == nil {
		s.PendingAutoLeaseHosts = make(map[string]time.Time, 2)
	}
	s.PendingAutoLeaseHosts[host] = time.Now()
}

// ConsumePendingAutoLease reports whether host has a fresh pending marker and,
// if so, deletes it. A stale marker (older than the window) is dropped and
// returns false. Lock-safe.
func (s *State) ConsumePendingAutoLease(host string) bool {
	if host == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	markedAt, ok := s.PendingAutoLeaseHosts[host]
	if !ok {
		return false
	}
	delete(s.PendingAutoLeaseHosts, host)
	return time.Since(markedAt) <= autoLeaseMarkWindow
}

// --- MCPDRIFT-1: per-session acknowledgment of a drifted MCP binary hash ---

// MarkPendingMCPDriftAck records that a drift ask for (server, hash) is awaiting
// observed approval. Lock-safe.
func (s *State) MarkPendingMCPDriftAck(server, hash string) {
	if server == "" || hash == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PendingMCPDriftAck == nil {
		s.PendingMCPDriftAck = make(map[string]string, 2)
	}
	s.PendingMCPDriftAck[server] = hash
}

// PromotePendingMCPDriftAck moves any pending drift ack for server into the
// acknowledged set (called at PostToolUse, i.e. after the tool actually ran).
// Lock-safe.
func (s *State) PromotePendingMCPDriftAck(server string) {
	if server == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash, ok := s.PendingMCPDriftAck[server]
	if !ok {
		return
	}
	delete(s.PendingMCPDriftAck, server)
	if s.AcknowledgedMCPDrift == nil {
		s.AcknowledgedMCPDrift = make(map[string]string, 2)
	}
	s.AcknowledgedMCPDrift[server] = hash
}

// MCPDriftAcknowledged reports whether (server, hash) was approved this session.
// A new/different hash returns false and still asks. Lock-safe.
func (s *State) MCPDriftAcknowledged(server, hash string) bool {
	if server == "" || hash == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.AcknowledgedMCPDrift[server] == hash
}

// --- NPX-1: per-session reuse of an approved ephemeral (npx) package ---

// MarkPendingEphemeralApproval records that an ephemeral-exec ask for pkg is
// awaiting observed approval. Lock-safe.
func (s *State) MarkPendingEphemeralApproval(pkg string) {
	if pkg == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PendingEphemeralApproval == nil {
		s.PendingEphemeralApproval = make(map[string]bool, 2)
	}
	s.PendingEphemeralApproval[pkg] = true
}

// PromotePendingEphemeralApproval moves any pending ephemeral approval for pkg
// into the approved set (called at PostToolUse). Lock-safe.
func (s *State) PromotePendingEphemeralApproval(pkg string) {
	if pkg == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.PendingEphemeralApproval[pkg] {
		return
	}
	delete(s.PendingEphemeralApproval, pkg)
	if s.ApprovedEphemeralPackages == nil {
		s.ApprovedEphemeralPackages = make(map[string]bool, 2)
	}
	s.ApprovedEphemeralPackages[pkg] = true
}

// EphemeralApproved reports whether pkg was approved this session. Lock-safe.
func (s *State) EphemeralApproved(pkg string) bool {
	if pkg == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ApprovedEphemeralPackages[pkg]
}

// --- REMOTE-1: per-session reuse of an approved git push remote ---

// MarkPendingPushRemote records that a push to remote is awaiting observed
// approval. Lock-safe.
func (s *State) MarkPendingPushRemote(remote string) {
	if remote == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.PendingPushRemote == nil {
		s.PendingPushRemote = make(map[string]bool, 2)
	}
	s.PendingPushRemote[remote] = true
}

// PromotePendingPushRemote moves any pending push remote into the approved set
// (called at PostToolUse). Lock-safe.
func (s *State) PromotePendingPushRemote(remote string) {
	if remote == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.PendingPushRemote[remote] {
		return
	}
	delete(s.PendingPushRemote, remote)
	if s.ApprovedPushRemotes == nil {
		s.ApprovedPushRemotes = make(map[string]bool, 2)
	}
	s.ApprovedPushRemotes[remote] = true
}

// PushRemoteApproved reports whether remote was approved this session. Lock-safe.
func (s *State) PushRemoteApproved(remote string) bool {
	if remote == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ApprovedPushRemotes[remote]
}

// PendingInstall tracks an in-progress install command for sentinel pre/post comparison.
type PendingInstall struct {
	Command        string            `json:"command"`
	Manager        string            `json:"manager"`
	SentinelHashes map[string]string `json:"sentinel_hashes"`
	LockfileHash   string            `json:"lockfile_hash,omitempty"`
}

// VerifySessionIntegrity checks that session.json has not been modified outside
// of sir's Save() method. Returns true if the session is intact.
// An empty SessionHash fails the check (fail closed) — an attacker cannot bypass
// integrity verification by clearing the hash field.
func VerifySessionIntegrity(state *State) bool {
	if state.SessionHash == "" {
		return false // fail closed: empty hash = tampered or corrupted
	}
	storedHash := state.SessionHash

	state.mu.Lock()
	state.SessionHash = ""
	data, err := json.MarshalIndent(state, "", "  ")
	state.SessionHash = storedHash
	state.mu.Unlock()

	if err != nil {
		return false
	}
	h := sha256.Sum256(data)
	computed := hex.EncodeToString(h[:])
	return computed == storedHash
}

// NewState creates a new session state.
func NewState(projectRoot string) *State {
	return &State{
		SchemaVersion:      policy.SessionSchemaVersion,
		SessionID:          fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%d", projectRoot, time.Now().UnixNano()))))[:16],
		ProjectRoot:        projectRoot,
		StartedAt:          time.Now(),
		PostureHashes:      make(map[string]string),
		DerivedFileLineage: make(map[string]DerivedPathRecord),
	}
}
