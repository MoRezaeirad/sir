package kernel

import (
	"strings"

	"github.com/somoore/sir/pkg/sdk"
)

// policyRule is an initial policy rule matching labeled actions.
type policyRule struct {
	ID          string
	Description string
	match       func(a AttributedAction) bool
	verdict     string
	effects     []PlannedEffect
}

// initialPolicies implements the PLAN Phase 4 initial policy set.
var initialPolicies = []policyRule{
	{
		ID:          "deny-agent-credential-read",
		Description: "AI agents cannot read credential files directly.",
		match: func(a AttributedAction) bool {
			return hasLabel(a.Labels, "ai_agent_actor") && hasLabel(a.Labels, "credential_access")
		},
		verdict: VerdictDeny,
		effects: []PlannedEffect{
			{Type: sdk_EffectBlock, Required: true, FailClosed: true},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		},
	},
	{
		ID:          "deny-secret-to-egress",
		Description: "Block external egress when session is tainted by credential access.",
		match: func(a AttributedAction) bool {
			// Session-scoped taint: credential_access in labels + external_egress
			return hasLabel(a.Labels, "credential_access") && hasLabel(a.Labels, "external_egress")
		},
		verdict: VerdictDeny,
		effects: []PlannedEffect{
			{Type: sdk_EffectBlock, Required: true, FailClosed: true},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		},
	},
	{
		ID:          "ask-external-egress",
		Description: "Ask before new external network egress.",
		match: func(a AttributedAction) bool {
			return hasLabel(a.Labels, "external_egress")
		},
		verdict: VerdictAsk,
		effects: []PlannedEffect{
			{Type: sdk_EffectPrompt, Required: false, FailClosed: false},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		},
	},
	{
		ID:          "ask-dangerous-shell",
		Description: "Ask before dangerous shell commands (rm -rf, chmod 777, etc.).",
		match: func(a AttributedAction) bool {
			return hasLabel(a.Labels, "shell_execution") && hasLabel(a.Labels, "dangerous_shell")
		},
		verdict: VerdictAsk,
		effects: []PlannedEffect{
			{Type: sdk_EffectPrompt, Required: false, FailClosed: false},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		},
	},
	{
		ID:          "ask-new-mcp-server",
		Description: "Ask before a new MCP server is trusted.",
		match: func(a AttributedAction) bool {
			return a.ActionType == "mcp_trust" || hasLabel(a.Labels, "new_mcp_server")
		},
		verdict: VerdictAsk,
		effects: []PlannedEffect{
			{Type: sdk_EffectPrompt, Required: false, FailClosed: false},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		},
	},
	{
		ID:          "ask-cicd-edit",
		Description: "Ask before editing CI/CD configuration files.",
		match: func(a AttributedAction) bool {
			return hasLabel(a.Labels, "cicd_edit")
		},
		verdict: VerdictAsk,
		effects: []PlannedEffect{
			{Type: sdk_EffectPrompt, Required: false, FailClosed: false},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		},
	},
	{
		// Forward-looking v2 mirror of the production posture floor: in the
		// shipping engine a write to .git/hooks/* is classified as a posture
		// file and asked (pkg/lease PostureFiles → mister-core). This keeps the
		// v2 kernel aligned on intent so the parity suite proves Go == Rust when
		// v2 becomes the decision path. ASK (not deny) — see deny-vs-ask
		// rationale in docs/policy.md; humans and hook frameworks approve once.
		ID:          "ask-git-hook-tamper",
		Description: "Ask before writing a git hook (execution-on-commit vector).",
		match: func(a AttributedAction) bool {
			return hasLabel(a.Labels, "git_hook_tamper")
		},
		verdict: VerdictAsk,
		effects: []PlannedEffect{
			{Type: sdk_EffectPrompt, Required: false, FailClosed: false},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		},
	},
	{
		ID:          "deny-sir-config-tamper",
		Description: "Block attempts to modify SIR's own configuration.",
		match: func(a AttributedAction) bool {
			return hasLabel(a.Labels, "sir_config_tamper")
		},
		verdict: VerdictDeny,
		effects: []PlannedEffect{
			{Type: sdk_EffectBlock, Required: true, FailClosed: true},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		},
	},
}

// sdk_Effect* aliases keep policy.go free of the sdk import cycle; these
// reference the string constants from sdk via their values.
const (
	sdk_EffectBlock  = "block"
	sdk_EffectRecord = "record"
	sdk_EffectPrompt = "prompt"
	sdk_EffectNudge  = "nudge"
)

// PolicyResult holds the policy evaluation output.
type PolicyResult struct {
	Verdict string
	Rules   []string
	Effects []PlannedEffect
}

// AdvisoryRisk is an optional risk level from an advisory_provider.
// Advisory engines may raise deterministic risk but may NEVER lower it (PRD §10.6-7).
type AdvisoryRisk struct {
	Level  string // "low", "medium", "high"
	Reason string
}

// EvaluatePolicy applies the initial policy set to an attributed action.
// Hard deny wins; multiple matches accumulate rules but the first deny dominates.
// Advisory engines are consulted but can only escalate, never de-escalate.
//
// priorTaint carries taint labels from previous kernel evaluations in the same
// session (passed explicitly — no global state). This enables cross-action
// causal policy: credential read in turn N, egress in turn N+1.
func EvaluatePolicy(action AttributedAction, priorTaint []string) PolicyResult {
	result := PolicyResult{Verdict: VerdictAllow}
	result.Effects = []PlannedEffect{{Type: sdk_EffectRecord, Required: true}}

	// Cross-action taint check (must run before same-action rules so deny fires
	// even when only one of the two labels is present in this action).
	if hasLabel(priorTaint, "credential_access") && hasLabel(action.Labels, "external_egress") {
		result.Rules = append(result.Rules, "deny-secret-to-egress")
		result.Verdict = VerdictDeny
		result.Effects = []PlannedEffect{
			{Type: sdk_EffectBlock, Required: true, FailClosed: true},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		}
		return result
	}

	for _, rule := range initialPolicies {
		if !rule.match(action) {
			continue
		}
		result.Rules = append(result.Rules, rule.ID)
		// Hard deny always wins.
		if rule.verdict == VerdictDeny {
			result.Verdict = VerdictDeny
			result.Effects = rule.effects
			break
		}
		// Ask only if not already deny.
		if result.Verdict != VerdictDeny && rule.verdict == VerdictAsk {
			result.Verdict = VerdictAsk
			result.Effects = rule.effects
		}
	}
	return result
}

// ApplyAdvisoryRisk applies advisory risk signal to an existing policy result.
// Implements PRD §10.6: "advisory engines may raise risk but may not lower
// deterministic risk." A high advisory risk escalates allow→ask; it cannot
// turn deny into ask or ask into allow.
func ApplyAdvisoryRisk(result PolicyResult, advisory *AdvisoryRisk) PolicyResult {
	if advisory == nil || advisory.Level == "" || advisory.Level == "low" {
		return result
	}
	if advisory.Level == "high" && result.Verdict == VerdictAllow {
		result.Verdict = VerdictAsk
		result.Rules = append(result.Rules, "advisory-high-risk")
		result.Effects = []PlannedEffect{
			{Type: sdk_EffectPrompt, Required: false, FailClosed: false},
			{Type: sdk_EffectRecord, Required: true, FailClosed: false},
		}
	}
	// Advisory can never lower: deny stays deny, ask stays ask.
	return result
}

func hasLabel(labels []string, label string) bool {
	for _, l := range labels {
		if l == label {
			return true
		}
	}
	return false
}

// ApplyDangerousShellLabel adds "dangerous_shell" label for known dangerous patterns.
func ApplyDangerousShellLabel(labels []string, signals []sdk.Signal) []string {
	dangerous := []string{"rm -rf", "chmod 777", "chmod 0777", "mkfs", "dd if=", ":(){:|:&};:", "> /dev/sda"}
	for _, sig := range signals {
		target, _ := sig.ActionClaim["target"].(map[string]any)
		if target == nil {
			continue
		}
		display, _ := target["display"].(string)
		lower := strings.ToLower(display)
		for _, pattern := range dangerous {
			if strings.Contains(lower, pattern) {
				return appendUnique(labels, "dangerous_shell")
			}
		}
	}
	return labels
}

// ApplyCICDLabel adds "cicd_edit" label for CI/CD file edits.
func ApplyCICDLabel(labels []string, signals []sdk.Signal) []string {
	cicdPaths := []string{".github/workflows", ".gitlab-ci", "Jenkinsfile", ".circleci", "Makefile", ".travis.yml"}
	for _, sig := range signals {
		target, _ := sig.ActionClaim["target"].(map[string]any)
		if target == nil {
			continue
		}
		display, _ := target["display"].(string)
		for _, p := range cicdPaths {
			if strings.Contains(display, p) {
				return appendUnique(labels, "cicd_edit")
			}
		}
	}
	return labels
}

// ApplyGitHookTamperLabel adds "git_hook_tamper" for writes to a git hook file.
// A planted .git/hooks/* runs on the next commit, so it is an execution-on-commit
// vector. The production engine handles this via the posture-file mechanism
// (pkg/lease PostureFiles → ask); this label is the v2-kernel mirror that keeps
// the harness parity suite honest. Substring match on ".git/hooks/" — the same
// shape as ApplySIRTamperLabel and ApplyCICDLabel — never matching ".git/config"
// (the credential-helper config vector, a documented gap, not a floor).
func ApplyGitHookTamperLabel(labels []string, signals []sdk.Signal) []string {
	for _, sig := range signals {
		target, _ := sig.ActionClaim["target"].(map[string]any)
		if target == nil {
			continue
		}
		display, _ := target["display"].(string)
		if strings.Contains(display, ".git/hooks/") {
			return appendUnique(labels, "git_hook_tamper")
		}
	}
	return labels
}

// ApplySIRTamperLabel adds "sir_config_tamper" for SIR self-modification attempts.
func ApplySIRTamperLabel(labels []string, signals []sdk.Signal) []string {
	sirPaths := []string{".claude/settings", "sir.yaml", ".sir/", "sir-posture"}
	for _, sig := range signals {
		target, _ := sig.ActionClaim["target"].(map[string]any)
		if target == nil {
			continue
		}
		display, _ := target["display"].(string)
		for _, p := range sirPaths {
			if strings.Contains(display, p) {
				return appendUnique(labels, "sir_config_tamper")
			}
		}
	}
	return labels
}
