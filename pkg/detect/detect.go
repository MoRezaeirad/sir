// Package detect defines sir's stable behavior-detection taxonomy.
//
// A detection is a causal, state-based judgement about a single decision:
// it is derived from the normalized verb, the verdict, the IFC sensitivity,
// the session posture (secret-session, MCP taint, pending injection,
// deny-all), and lineage — never from raw command strings. The detection
// IDs are a stable contract: they appear in the ledger, in OTLP/SIEM
// telemetry (sir.detection_id), and in curated Slack escalations, so they
// must not be renamed without a contract-test update.
//
// This package is pure: it imports only the standard library and has no
// dependency on the rest of sir, so the taxonomy can be reviewed in
// isolation and reused from the hook path, the CLI, and the exporters.
package detect

// ID is a stable detection identifier. The set is closed; new IDs are added
// deliberately and covered by Catalog plus a public-contract test.
type ID string

const (
	// SecretToExternalEgress fires when a turn carrying secret-labeled
	// context (or a secret-derived file) attempts external network egress.
	SecretToExternalEgress ID = "secret_to_external_egress" // #nosec G101 -- detection ID, not a credential
	// SecretToPushRemote fires when secret context attempts a git push to a
	// remote.
	SecretToPushRemote ID = "secret_to_push_remote"
	// MCPInjectionThenAction fires when an MCP response carried injection
	// markers and the agent then attempts an action under that taint.
	MCPInjectionThenAction ID = "mcp_injection_then_action"
	// NewMCPServerUsed fires the first times a freshly discovered/approved
	// MCP server is exercised (the onboarding window).
	NewMCPServerUsed ID = "new_mcp_server_used"
	// MCPBinaryOrConfigDrift fires when an approved MCP server's binary hash
	// or config no longer matches the recorded baseline.
	MCPBinaryOrConfigDrift ID = "mcp_binary_or_config_drift"
	// AgentPostureTamper fires when hook config, CLAUDE.md, .mcp.json, or a
	// sentinel/tripwire file changes outside sir's managed path.
	AgentPostureTamper ID = "agent_posture_tamper"
	// PackageInstallPostureMutation fires when a package install coincides
	// with a posture mutation (install that rewrites control-plane state).
	PackageInstallPostureMutation ID = "package_install_posture_mutation"
	// HookIntegrityViolation fires when a PostToolUse arrives for a tool_use_id
	// that sir denied at PreToolUse — the host executor ran a denied call,
	// ignoring sir's deny. The session is taken to deny-all.
	HookIntegrityViolation ID = "hook_integrity_violation"
	// RepeatedDeniedIntent fires when the same (verb,target) is denied or
	// asked repeatedly in a session — a developer-facing friction signal,
	// not a security escalation.
	RepeatedDeniedIntent ID = "repeated_denied_intent"
	// CredentialInToolOutput fires when a credential pattern is detected in
	// tool or MCP output.
	CredentialInToolOutput ID = "credential_in_tool_output" // #nosec G101 -- detection ID, not a credential
	// ControlPlaneIntegrityFailure fires when sir's own control plane is
	// compromised: deny-all posture, an unrestored hook tamper, or ledger
	// chain corruption.
	ControlPlaneIntegrityFailure ID = "control_plane_integrity_failure"
	// MCPChangeThenPrivilegedUse is a compound detection: an approved MCP
	// server's trust footing changed (binary/config drift) and the session
	// then exercised privileged authority (egress, push, delegation,
	// persistence) within the correlation window.
	MCPChangeThenPrivilegedUse ID = "mcp_change_then_privileged_use"
)

// Severity is the operator-facing severity band, aligned with the existing
// ledger/OTLP severity vocabulary (HIGH/MEDIUM/LOW).
type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

// Route is the escalation tier for a detection. Higher tiers subsume lower
// ones: a Slack-routed detection is also written locally and to the SIEM.
// Routing is what keeps sir quiet — most decisions produce no detection
// (RouteSilent) and never reach a developer or a channel.
type Route int

const (
	// RouteSilent means no detection fired; normal coding stays quiet.
	RouteSilent Route = iota
	// RouteLocal records to the ledger only (developer-facing, e.g. repeated
	// denies). It is deliberately not escalated to a channel.
	RouteLocal
	// RouteSIEM records to the ledger and the OTLP/SIEM stream, but not Slack.
	RouteSIEM
	// RouteSlack records everywhere and escalates to Slack/security.
	RouteSlack
)

// String renders the route as a short stable token for display and tests.
func (r Route) String() string {
	switch r {
	case RouteSilent:
		return "silent"
	case RouteLocal:
		return "local"
	case RouteSIEM:
		return "siem"
	case RouteSlack:
		return "slack"
	default:
		return "unknown"
	}
}

// Signal is the normalized, command-string-free input to Classify. It carries
// only verbs, verdicts, IFC sensitivity, and session/posture state so that
// detection stays causal rather than pattern-matching raw arguments.
type Signal struct {
	Verb        string // normalized policy verb, e.g. "net_external"
	Verdict     string // allow, deny, ask (would_* is normalized away by Classify)
	AlertType   string // existing ledger alert taxonomy, e.g. "mcp_injection"
	Sensitivity string // IFC sensitivity, e.g. "secret"

	SecretSession     bool // turn carries secret-labeled context
	DerivedFromSecret bool // target path has secret-derived lineage
	MCPTaint          bool // at least one MCP server is tainted
	InjectionAlert    bool // a pending MCP injection alert exists
	DenyAll           bool // session-fatal deny-all posture is active
	TamperRestored    bool // for tamper alerts: auto-restore succeeded
	NewMCPServer      bool // server is inside its onboarding window
	PostureMutation   bool // the action mutates a posture/control-plane file

	// RepeatedCount is how many prior asks/denies of this exact (verb,target)
	// already occurred in the session. Zero for a first occurrence.
	RepeatedCount int
	// Unusual marks a target as not-seen-before in this repo/session (e.g. a
	// first-contact external host). It promotes egress detections to Slack.
	Unusual bool
	// RecentMCPChange is true when an approved MCP server's trust footing
	// changed earlier in the session (binary/config drift) within the
	// correlation window. Combined with a privileged verb it yields the
	// mcp_change_then_privileged_use compound detection.
	RecentMCPChange bool
	// Suspicious is the non-blocking "third taint tier": the session carries
	// soft risk (an untrusted read, an acknowledged-tainted MCP server,
	// elevated posture) that does not block on its own but promotes a
	// detection's route one tier for extra visibility.
	Suspicious bool
}

// Detection is the result of classifying a Signal.
type Detection struct {
	ID       ID
	Severity Severity
	Route    Route
}

// blocked reports whether the verdict represents a block or prompt (deny/ask),
// tolerating the observe-mode "would_" prefix.
func blocked(verdict string) bool {
	switch verdict {
	case "deny", "ask", "would_deny", "would_ask":
		return true
	default:
		return false
	}
}

func isExternalEgressVerb(verb string) bool {
	switch verb {
	case "net_external", "dns_lookup", "mcp_network_unapproved":
		return true
	default:
		return false
	}
}

func isPushVerb(verb string) bool {
	return verb == "push_remote" || verb == "push_origin"
}

// isPrivilegedVerb reports whether a verb exercises authority worth correlating
// against a recent trust change: network egress, push, delegation, or
// persistence. Routine reads/writes/tests are excluded to keep the compound
// detection high-signal.
func isPrivilegedVerb(verb string) bool {
	switch verb {
	case "net_external", "net_allowlisted", "dns_lookup", "mcp_network_unapproved",
		"push_origin", "push_remote", "delegate", "persistence", "sudo":
		return true
	default:
		return false
	}
}

// Classify maps a Signal to at most one detection — the highest-signal one —
// or returns ok=false when nothing fires (the common, quiet case). When the
// session is suspicious (a non-blocking "third taint tier" risk signal), a
// borderline detection's route is promoted one tier so it gets more
// visibility, without ever changing the allow/deny verdict.
func Classify(s Signal) (Detection, bool) {
	d, ok := classifyBase(s)
	if !ok {
		return d, false
	}
	if s.Suspicious {
		d.Route = promoteRoute(d.Route)
	}
	return d, true
}

// promoteRoute escalates a route one tier toward Slack (Local→SIEM→Slack),
// capped at Slack. Silent stays silent.
func promoteRoute(r Route) Route {
	switch r {
	case RouteLocal:
		return RouteSIEM
	case RouteSIEM:
		return RouteSlack
	default:
		return r
	}
}

// detectionRules is the ordered set of causal detection predicates. Classify
// returns the FIRST match (highest-signal); Signals returns ALL matches as
// secondary correlation tags. Keeping both behaviors driven by one ordered
// table is what guarantees the primary detection and the signal_ids can never
// drift apart. Order = priority: control-plane first, friction last.
var detectionRules = []func(s Signal) (Detection, bool){
	// Control-plane integrity is the most severe class: sir itself is
	// compromised or wedged. Deny-all posture and unrestored tamper both qualify.
	func(s Signal) (Detection, bool) {
		if s.DenyAll {
			return Detection{ControlPlaneIntegrityFailure, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	func(s Signal) (Detection, bool) {
		if isTamperAlert(s.AlertType) && !s.TamperRestored && integrityCritical(s.AlertType) {
			return Detection{ControlPlaneIntegrityFailure, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	// Posture tamper (restored or lower-criticality).
	func(s Signal) (Detection, bool) {
		if isTamperAlert(s.AlertType) {
			return Detection{AgentPostureTamper, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	// Credential exposure in tool/MCP output.
	func(s Signal) (Detection, bool) {
		if s.AlertType == "credential_in_output" || s.AlertType == "mcp_credential" || s.Verb == "credential_detected" || s.Verb == "mcp_credential_leak" {
			return Detection{CredentialInToolOutput, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	// MCP injection followed by an action under taint (explicit signal).
	func(s Signal) (Detection, bool) {
		if s.AlertType == "mcp_injection" || s.Verb == "mcp_injection_detected" {
			return Detection{MCPInjectionThenAction, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	// MCP injection followed by a blocked action under taint.
	func(s Signal) (Detection, bool) {
		if (s.InjectionAlert || s.MCPTaint) && blocked(s.Verdict) {
			return Detection{MCPInjectionThenAction, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	// Compound: an MCP trust change followed by privileged authority use.
	func(s Signal) (Detection, bool) {
		if s.RecentMCPChange && isPrivilegedVerb(s.Verb) {
			return Detection{MCPChangeThenPrivilegedUse, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	// MCP binary/config drift.
	func(s Signal) (Detection, bool) {
		if s.AlertType == "mcp_binary_drift" || s.Verb == "mcp_binary_drift" {
			return Detection{MCPBinaryOrConfigDrift, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	// Package install that mutates control-plane posture.
	func(s Signal) (Detection, bool) {
		if s.Verb == "persistence" && s.PostureMutation {
			return Detection{PackageInstallPostureMutation, SeverityHigh, RouteSlack}, true
		}
		return Detection{}, false
	},
	// Secret context reaching an external sink (egress / push).
	func(s Signal) (Detection, bool) {
		if (s.SecretSession || s.DerivedFromSecret) && blocked(s.Verdict) && isExternalEgressVerb(s.Verb) {
			return Detection{SecretToExternalEgress, SeverityHigh, egressRoute(s)}, true
		}
		return Detection{}, false
	},
	func(s Signal) (Detection, bool) {
		if (s.SecretSession || s.DerivedFromSecret) && blocked(s.Verdict) && isPushVerb(s.Verb) {
			return Detection{SecretToPushRemote, SeverityHigh, egressRoute(s)}, true
		}
		return Detection{}, false
	},
	// New MCP server exercised inside its onboarding window.
	func(s Signal) (Detection, bool) {
		if s.NewMCPServer || s.Verb == "mcp_onboarding" {
			return Detection{NewMCPServerUsed, SeverityMedium, RouteSIEM}, true
		}
		return Detection{}, false
	},
	// Repeated denied/asked intent — developer-facing friction only.
	func(s Signal) (Detection, bool) {
		if s.RepeatedCount >= 1 && blocked(s.Verdict) {
			return Detection{RepeatedDeniedIntent, SeverityLow, RouteLocal}, true
		}
		return Detection{}, false
	},
}

func classifyBase(s Signal) (Detection, bool) {
	for _, rule := range detectionRules {
		if d, ok := rule(s); ok {
			return d, true
		}
	}
	return Detection{}, false
}

// Signals returns every detection ID that fires for s, in priority order and
// deduplicated — the primary (Classify) ID first, followed by any secondary
// correlation tags. It is the source of the additive sir.signal_ids SIEM field:
// analysts get the full causal picture (e.g. an MCP-injection action that is
// ALSO a secret egress) while routing still keys on the single primary
// detection. Returns nil when nothing fires (the common, quiet case).
func Signals(s Signal) []ID {
	var ids []ID
	seen := make(map[ID]bool, 3)
	for _, rule := range detectionRules {
		d, ok := rule(s)
		if !ok || seen[d.ID] {
			continue
		}
		seen[d.ID] = true
		ids = append(ids, d.ID)
	}
	return ids
}

// egressRoute escalates a secret-egress detection to Slack only when the sink
// is unusual or the attempt has repeated; otherwise it stays SIEM-local.
func egressRoute(s Signal) Route {
	if s.Unusual || s.RepeatedCount >= 1 {
		return RouteSlack
	}
	return RouteSIEM
}

func isTamperAlert(alertType string) bool {
	switch alertType {
	case "hook_tamper", "posture_change", "posture_change_session_end",
		"config_change_posture", "sentinel_mutation":
		return true
	default:
		return false
	}
}

// integrityCritical reports whether a tamper alert touches sir's own control
// plane (hooks/sentinels) as opposed to advisory posture files.
func integrityCritical(alertType string) bool {
	return alertType == "hook_tamper" || alertType == "sentinel_mutation"
}
