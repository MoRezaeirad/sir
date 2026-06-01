//! sir-core: SIR v2 pure decision kernel.
//!
//! evaluate(EvaluationInput) -> EvaluationOutput
//!
//! Rules:
//!   - No filesystem access.
//!   - No network access.
//!   - No shell execution.
//!   - No hidden global state.
//!   - No external crate dependencies (JSON via mister-shared).
//!   - No unsafe code.
//!
//! The Go orchestrator owns: decision_id, timestamps, ledger writes,
//! taint store, friction counters, provider supervision.

// ── Constant pools ────────────────────────────────────────────────────────────

pub mod modes {
    pub const OBSERVE: &str = "observe";
    pub const ADVISE: &str = "advise";
    pub const HOOK_GATE: &str = "hook_gate";
    pub const OS_OBSERVED: &str = "os_observed";
    pub const MEDIATED: &str = "mediated";
    pub const CONTAINED: &str = "contained";
    pub const MANAGED: &str = "managed";
}

pub mod classes {
    pub const ENFORCES: &str = "enforces";
    pub const DETECTS: &str = "detects";
    pub const BLIND: &str = "blind";
}

pub mod verdicts {
    pub const ALLOW: &str = "allow";
    pub const ASK: &str = "ask";
    pub const DENY: &str = "deny";
}

pub mod conf {
    pub const HIGH: &str = "high";
    pub const MEDIUM: &str = "medium";
    pub const LOW: &str = "low";
    pub const UNKNOWN: &str = "unknown";
}

pub mod decision_classes {
    pub const PROCEED_AND_RECONCILE: &str = "proceed_and_reconcile";
    pub const BLOCK_AND_WAIT: &str = "block_and_wait";
    pub const DENY_NOW: &str = "deny_now";
    pub const RECORD_POST_HOC: &str = "record_post_hoc";
}

pub mod reliability {
    pub const DECLARED_INTENT: &str = "declared_intent";
    pub const MEDIATED_ACTION: &str = "mediated_action";
    pub const OBSERVED_RUNTIME: &str = "observed_runtime";
    pub const ENFORCED_BOUNDARY: &str = "enforced_boundary";
    pub const ADVISORY_SIGNAL: &str = "advisory_signal";
    pub const USER_DECISION: &str = "user_decision";
    pub const ADMIN_POLICY: &str = "admin_policy";
}

pub mod timing {
    pub const PRE_EXEC: &str = "pre_exec";
    pub const DURING_EXEC: &str = "during_exec";
    pub const POST_EXEC: &str = "post_exec";
    pub const UNKNOWN: &str = "unknown";
}

pub mod effects {
    pub const RECORD: &str = "record";
    pub const BLOCK: &str = "block";
    pub const PROMPT: &str = "prompt";
    pub const NUDGE: &str = "nudge";
}

pub mod spoofing {
    pub const NONE: &str = "none";
    pub const LOW: &str = "low";
    pub const MEDIUM: &str = "medium";
    pub const HIGH: &str = "high";
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SignalSource {
    pub reliability: String,
    pub timing: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ActionTarget {
    pub display: String,
    pub sensitivity: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ActionClaim {
    pub action_type: String,
    pub target: ActionTarget,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Signal {
    pub source: SignalSource,
    pub action_claim: ActionClaim,
    pub actor_kind: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EvasionFlags {
    pub span_stripped: bool,
    pub span_forged: bool,
    pub detached_child: bool,
    pub hook_missing: bool,
    pub required_effect_unavail: bool,
    pub fail_closed: bool,
}

/// Complete, explicit input to evaluate(). Stateful context (prior_taint,
/// provider_capabilities) is passed in — the kernel reads nothing from
/// global state. This is also the JSON wire format for sir-core-eval.
#[derive(Debug, Clone, Default)]
pub struct EvaluationInput {
    pub case_id: String,
    pub mode: String,
    pub signals: Vec<Signal>,
    pub evasion: EvasionFlags,
    /// Taint labels accumulated from prior evaluate() calls in the same session.
    pub prior_taint: Vec<String>,
    /// Provider capabilities (e.g. "contain" => true) threaded in by orchestrator.
    pub provider_capabilities: Vec<String>,
    /// Resolved actor kind set by the stateful orchestrator when it has fused a
    /// shell/unknown signal with agent-session evidence (PID+start-time matching
    /// an active agent session). Empty = use the signal's own actor_kind.
    /// Mirrors PriorTaint: stateful context threaded in so evaluate() stays pure.
    pub resolved_actor_kind: String,
    /// Advisory verdicts from registered policy providers (OPA, Cedar, custom
    /// packs). Composed under the native floors and the developer-workflow floor.
    /// Empty reproduces the no-provider baseline exactly. Mirrors the Go kernel's
    /// EvaluationInput.PolicyVerdicts so harness parity exercises composition.
    pub policy_verdicts: Vec<PolicyVerdict>,
    /// "real" when the active effect provider demonstrably enforces containment,
    /// "simulated"/"" when it only declares the capability (a stub). A declared
    /// block/contain capability only yields ClassEnforces when this is "real".
    /// Mirrors the Go kernel exactly — closes the false-enforces soundness gap.
    pub provider_enforcement: String,
    /// Optional action-scoped capability (item 8): action types the provider
    /// demonstrably enforces. Empty = enforces every action (backward-compatible
    /// default). When non-empty, a contained/managed provider with real
    /// enforcement only yields ClassEnforces for a covered action; an uncovered
    /// action degrades to ClassDetects. Mirrors Go EnforceabilityInput.EnforcedActions.
    pub provider_enforced_actions: Vec<String>,
}

/// Kernel-local advisory policy verdict. Mirrors sir.policy_verdict.v0.
#[derive(Debug, Clone, Default)]
pub struct PolicyVerdict {
    pub provider: String,
    pub verdict: String, // allow | ask | deny
    pub rules_matched: Vec<String>,
    pub reason: String,
    pub is_advisory: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlannedEffect {
    pub effect_type: String,
    pub required: bool,
    pub fail_closed: bool,
}

/// The parity fields that Go and Rust must agree on.
/// decision_id and timestamp are NOT here — Go stamps those.
#[derive(Debug, Clone, Default)]
pub struct EvaluationOutput {
    pub verdict: String,
    pub decision_class: String,
    pub enforceability: String,
    pub attribution: String,
    /// Spoofing risk: none/low/medium/high. Matches sir.attribution.v0 enum.
    pub spoofing_risk: String,
    pub policy_rules: Vec<String>,
    pub effects: Vec<PlannedEffect>,
    pub action_type: String,
    pub sensitivity: String,
    /// New taint produced by this action; the orchestrator merges into taint store.
    pub new_taint: Vec<String>,
}

// ── Signal helpers ────────────────────────────────────────────────────────────

/// Compute spoofing risk from evasion flags and signal set.
/// Mirrors Go's ComputeSpoofingRisk exactly.
pub fn compute_spoofing_risk(input: &EvaluationInput) -> &'static str {
    let ef = &input.evasion;
    let signals = &input.signals;
    if ef.span_forged {
        return spoofing::HIGH;
    }
    if has_signal(signals, reliability::ENFORCED_BOUNDARY, "") {
        return spoofing::NONE;
    }
    if ef.span_stripped || ef.detached_child || ef.hook_missing {
        return if has_signal(signals, reliability::OBSERVED_RUNTIME, "") {
            spoofing::MEDIUM
        } else {
            spoofing::HIGH
        };
    }
    if has_signal(signals, reliability::DECLARED_INTENT, "")
        || has_signal(signals, reliability::MEDIATED_ACTION, "")
    {
        return spoofing::LOW;
    }
    spoofing::HIGH
}

fn has_signal(signals: &[Signal], rel: &str, tim: &str) -> bool {
    signals.iter().any(|s| {
        (rel.is_empty() || s.source.reliability == rel)
            && (tim.is_empty() || s.source.timing == tim)
    })
}

fn attribution_confidence(signals: &[Signal]) -> &'static str {
    let mut best = conf::UNKNOWN;
    for s in signals {
        match s.source.reliability.as_str() {
            r if r == reliability::ENFORCED_BOUNDARY => return conf::HIGH,
            r if r == reliability::MEDIATED_ACTION || r == reliability::DECLARED_INTENT => {
                if best == conf::UNKNOWN || best == conf::LOW {
                    best = conf::MEDIUM;
                }
            }
            r if r == reliability::OBSERVED_RUNTIME => {
                if best == conf::UNKNOWN {
                    best = conf::LOW;
                }
            }
            _ => {}
        }
    }
    best
}

fn primary_action_type(signals: &[Signal]) -> &str {
    signals
        .iter()
        .find(|s| !s.action_claim.action_type.is_empty())
        .map(|s| s.action_claim.action_type.as_str())
        .unwrap_or("unknown")
}

fn primary_sensitivity(signals: &[Signal]) -> &str {
    // Order: credential=3, external_network=2, high=2, medium=1, low=0
    let rank = |s: &str| match s {
        "credential" => 3i32,
        "external_network" | "high" => 2,
        "medium" => 1,
        _ => 0,
    };
    signals
        .iter()
        .map(|s| s.action_claim.target.sensitivity.as_str())
        .max_by_key(|s| rank(s))
        .unwrap_or("low")
}

// ── Enforceability analysis ───────────────────────────────────────────────────

fn provider_can(input: &EvaluationInput, cap: &str) -> bool {
    input.provider_capabilities.iter().any(|c| c == cap)
}

// action_enforced reports whether a provider scoping its enforcement to
// enforced_actions covers action_type. Empty = enforces everything (the
// backward-compatible default). An "unknown" action is never in a non-empty
// list, so it correctly degrades to detects. Mirrors Go actionEnforced.
fn action_enforced(enforced_actions: &[String], action_type: &str) -> bool {
    enforced_actions.is_empty() || enforced_actions.iter().any(|a| a == action_type)
}

/// The canonical enforceability function. Ported exactly from Go's
/// pkg/kernel/pipeline.go:AnalyzeEnforceability. Order matters.
pub fn analyze_enforceability(input: &EvaluationInput) -> (&'static str, String) {
    let ef = &input.evasion;
    let signals = &input.signals;
    let mode = input.mode.as_str();

    if ef.required_effect_unavail {
        return if ef.fail_closed {
            (
                classes::ENFORCES,
                "required effect unavailable: fail_closed=true denies".into(),
            )
        } else {
            (
                classes::DETECTS,
                "required effect unavailable: recorded but not blocked".into(),
            )
        };
    }

    match mode {
        m if m == modes::CONTAINED || m == modes::MANAGED => {
            // An enforced_boundary signal is inherent proof (hardware/OS).
            if has_signal(signals, reliability::ENFORCED_BOUNDARY, "") {
                return (
                    classes::ENFORCES,
                    "enforced-boundary signal proves containment".into(),
                );
            }
            // A declared block/contain capability only yields enforces when the
            // provider's enforcement is DEMONSTRATED (real), not merely declared.
            // A stub provider classifies at most detects — closes the
            // false-enforces soundness gap. Mirrors Go AnalyzeEnforceability.
            if provider_can(input, "block") || provider_can(input, "contain") {
                if input.provider_enforcement == "real" {
                    // Action-scoped capability (item 8): a provider may enforce
                    // only some action types. If it scopes enforcement and the
                    // current action is uncovered, it cannot claim to enforce
                    // THIS action — degrade to detects (still observes in the
                    // jail). Empty = enforces everything. Deliberately NOT applied
                    // to the enforced_boundary branch above: that signal is
                    // per-action proof, not a capability declaration. Mirrors Go.
                    if !action_enforced(
                        &input.provider_enforced_actions,
                        primary_action_type(signals),
                    ) {
                        return (classes::DETECTS, "provider enforces a different action set — this action type is observed, not contained".into());
                    }
                    return (
                        classes::ENFORCES,
                        "provider-backed mode with demonstrated (real) enforcement".into(),
                    );
                }
                return (classes::DETECTS, "provider declares block/contain but enforcement is simulated/unproven — detects only".into());
            }
            (
                classes::DETECTS,
                "contained/managed mode but no capable provider available".into(),
            )
        }
        m if m == modes::MEDIATED => {
            if ef.span_stripped || ef.detached_child {
                if has_signal(signals, reliability::OBSERVED_RUNTIME, "") {
                    return (
                        classes::DETECTS,
                        "mediated span severed; runtime signal caught residue".into(),
                    );
                }
                return (classes::BLIND, "mediated span severed; no fallback".into());
            }
            if has_signal(signals, "", timing::PRE_EXEC) {
                // Demonstrated-mediation gate (item 9), parallel to the contained
                // real-enforcement gate. A pre-exec signal alone is a DECLARED
                // control point; mediated enforces only when mediation is
                // demonstrated — provider_enforcement=="real" (an active runner
                // that genuinely wraps execution, e.g. the macOS sandbox-exec
                // provider, backed by capture proof) or an enforced_boundary
                // signal. Declared-only degrades to detects. Mirrors Go exactly.
                if input.provider_enforcement == "real"
                    || has_signal(signals, reliability::ENFORCED_BOUNDARY, "")
                {
                    return (
                        classes::ENFORCES,
                        "mediated pre-exec control with demonstrated mediation".into(),
                    );
                }
                return (
                    classes::DETECTS,
                    "mediated pre-exec signal declared but mediation unproven — detects only"
                        .into(),
                );
            }
            (classes::DETECTS, "no pre-exec signal".into())
        }
        m if m == modes::HOOK_GATE => {
            if ef.hook_missing || ef.span_stripped || ef.span_forged || ef.detached_child {
                if has_signal(signals, reliability::OBSERVED_RUNTIME, "") {
                    return (
                        classes::DETECTS,
                        "hook/span unreliable; fallback observed".into(),
                    );
                }
                return (classes::BLIND, "hook/span unreliable; no fallback".into());
            }
            if has_signal(signals, reliability::DECLARED_INTENT, timing::PRE_EXEC) {
                return (
                    classes::ENFORCES,
                    "cooperative pre-exec hook can gate".into(),
                );
            }
            (classes::DETECTS, "no cooperative pre-exec hook".into())
        }
        m if m == modes::OS_OBSERVED => {
            if has_signal(signals, reliability::OBSERVED_RUNTIME, "") {
                return (
                    classes::DETECTS,
                    "post-hoc or partial runtime observation".into(),
                );
            }
            (classes::BLIND, "no runtime signal".into())
        }
        m if m == modes::OBSERVE || m == modes::ADVISE => {
            if !signals.is_empty() {
                return (
                    classes::DETECTS,
                    format!("{} mode records/explains but does not enforce", mode),
                );
            }
            (classes::BLIND, "no signals".into())
        }
        _ => (classes::BLIND, "unknown mode".into()),
    }
}

// ── Label derivation ──────────────────────────────────────────────────────────

const DANGEROUS_SHELL: &[&str] = &[
    "rm -rf",
    "chmod 777",
    "chmod 0777",
    "mkfs",
    "dd if=",
    ":(){:|:&};:",
    "> /dev/sda",
];
const CICD_PATHS: &[&str] = &[
    ".github/workflows",
    ".gitlab-ci",
    "Jenkinsfile",
    ".circleci",
    "Makefile",
    ".travis.yml",
];
const SIR_CONFIG_PATHS: &[&str] = &[".claude/settings", "sir.yaml", ".sir/", "sir-posture"];

fn labelize(action_type: &str, sensitivity: &str, signals: &[Signal]) -> Vec<String> {
    let mut labels = Vec::new();
    if sensitivity == "credential" {
        labels.push("credential_access".into());
    }
    if sensitivity == "external_network" {
        labels.push("external_egress".into());
    }
    if action_type.contains("shell_exec") {
        labels.push("shell_execution".into());
    }
    if action_type.contains("file_write") {
        labels.push("file_mutation".into());
    }
    if signals.iter().any(|s| s.actor_kind == "ai_coding_agent")
        && !labels.iter().any(|l| l == "ai_agent_actor")
    {
        labels.push("ai_agent_actor".into());
    }
    // Dangerous shell patterns
    for sig in signals {
        let display_lower = sig.action_claim.target.display.to_lowercase();
        if DANGEROUS_SHELL.iter().any(|p| display_lower.contains(p))
            && !labels.iter().any(|l| l == "dangerous_shell")
        {
            labels.push("dangerous_shell".into());
        }
        // CI/CD paths
        if CICD_PATHS
            .iter()
            .any(|p| sig.action_claim.target.display.contains(p))
            && !labels.iter().any(|l| l == "cicd_edit")
        {
            labels.push("cicd_edit".into());
        }
        // Git-hook tamper: a planted .git/hooks/* runs on the next commit.
        // Forward-looking v2 mirror of the production posture floor (ask). Must
        // not match ".git/config" (credential-helper config vector — a
        // documented gap, not a floor).
        if sig.action_claim.target.display.contains(".git/hooks/")
            && !labels.iter().any(|l| l == "git_hook_tamper")
        {
            labels.push("git_hook_tamper".into());
        }
        // SIR config tamper
        if SIR_CONFIG_PATHS
            .iter()
            .any(|p| sig.action_claim.target.display.contains(p))
            && !labels.iter().any(|l| l == "sir_config_tamper")
        {
            labels.push("sir_config_tamper".into());
        }
    }
    labels
}

// ── Policy evaluation ─────────────────────────────────────────────────────────

fn has_label(labels: &[String], label: &str) -> bool {
    labels.iter().any(|l| l == label)
}

struct PolicyRule {
    id: &'static str,
    verdict: &'static str,
    effects: &'static [(&'static str, bool, bool)], // (type, required, fail_closed)
}

fn rule_matches(rule: &PolicyRule, labels: &[String], _prior_taint: &[String]) -> bool {
    match rule.id {
        "deny-agent-credential-read" => {
            has_label(labels, "ai_agent_actor") && has_label(labels, "credential_access")
        }
        "deny-secret-to-egress" => {
            // Same-action: both credential and egress in this action.
            // Cross-action handled before rules loop via prior_taint.
            has_label(labels, "credential_access") && has_label(labels, "external_egress")
        }
        "ask-external-egress" => has_label(labels, "external_egress"),
        "ask-dangerous-shell" => {
            has_label(labels, "shell_execution") && has_label(labels, "dangerous_shell")
        }
        "ask-new-mcp-server" => has_label(labels, "new_mcp_server"),
        "ask-cicd-edit" => has_label(labels, "cicd_edit"),
        "ask-git-hook-tamper" => has_label(labels, "git_hook_tamper"),
        "deny-sir-config-tamper" => has_label(labels, "sir_config_tamper"),
        _ => false,
    }
}

const INITIAL_POLICIES: &[PolicyRule] = &[
    PolicyRule {
        id: "deny-agent-credential-read",
        verdict: verdicts::DENY,
        effects: &[("block", true, true), ("record", true, false)],
    },
    PolicyRule {
        id: "deny-secret-to-egress",
        verdict: verdicts::DENY,
        effects: &[("block", true, true), ("record", true, false)],
    },
    PolicyRule {
        id: "ask-external-egress",
        verdict: verdicts::ASK,
        effects: &[("prompt", false, false), ("record", true, false)],
    },
    PolicyRule {
        id: "ask-dangerous-shell",
        verdict: verdicts::ASK,
        effects: &[("prompt", false, false), ("record", true, false)],
    },
    PolicyRule {
        id: "ask-new-mcp-server",
        verdict: verdicts::ASK,
        effects: &[("prompt", false, false), ("record", true, false)],
    },
    PolicyRule {
        id: "ask-cicd-edit",
        verdict: verdicts::ASK,
        effects: &[("prompt", false, false), ("record", true, false)],
    },
    PolicyRule {
        id: "ask-git-hook-tamper",
        verdict: verdicts::ASK,
        effects: &[("prompt", false, false), ("record", true, false)],
    },
    PolicyRule {
        id: "deny-sir-config-tamper",
        verdict: verdicts::DENY,
        effects: &[("block", true, true), ("record", true, false)],
    },
];

fn make_effects(spec: &[(&'static str, bool, bool)]) -> Vec<PlannedEffect> {
    spec.iter()
        .map(|(t, r, fc)| PlannedEffect {
            effect_type: t.to_string(),
            required: *r,
            fail_closed: *fc,
        })
        .collect()
}

fn evaluate_policy(
    labels: &[String],
    prior_taint: &[String],
) -> (String, Vec<String>, Vec<PlannedEffect>) {
    let default_effects = vec![PlannedEffect {
        effect_type: effects::RECORD.into(),
        required: true,
        fail_closed: false,
    }];
    let mut verdict = verdicts::ALLOW.to_string();
    let mut rules: Vec<String> = Vec::new();
    let mut planned_effects = default_effects;

    // Cross-action taint check (prior_taint from orchestrator).
    if has_label(prior_taint, "credential_access") && has_label(labels, "external_egress") {
        rules.push("deny-secret-to-egress".into());
        return (
            verdicts::DENY.to_string(),
            rules,
            make_effects(&[("block", true, true), ("record", true, false)]),
        );
    }

    for rule in INITIAL_POLICIES {
        if !rule_matches(rule, labels, prior_taint) {
            continue;
        }
        rules.push(rule.id.into());
        if rule.verdict == verdicts::DENY {
            verdict = verdicts::DENY.to_string();
            planned_effects = make_effects(rule.effects);
            break;
        }
        if verdict != verdicts::DENY && rule.verdict == verdicts::ASK {
            verdict = verdicts::ASK.to_string();
            planned_effects = make_effects(rule.effects);
        }
    }
    (verdict, rules, planned_effects)
}

// ── Decision composition ──────────────────────────────────────────────────────

fn resolve_decision_class(verdict: &str, enforceability: &str) -> &'static str {
    match verdict {
        v if v == verdicts::DENY => decision_classes::DENY_NOW,
        v if v == verdicts::ASK => {
            if enforceability == classes::ENFORCES {
                decision_classes::BLOCK_AND_WAIT
            } else {
                decision_classes::RECORD_POST_HOC
            }
        }
        _ => decision_classes::PROCEED_AND_RECONCILE,
    }
}

fn apply_low_confidence_escalation(
    verdict: String,
    mut rules: Vec<String>,
    attribution: &str,
    sensitivity: &str,
) -> (String, Vec<String>) {
    if attribution != conf::LOW && attribution != conf::UNKNOWN {
        return (verdict, rules);
    }
    let high = matches!(sensitivity, "credential" | "high" | "critical");
    if high && verdict == verdicts::ALLOW {
        rules.push("low-confidence-escalation".into());
        return (verdicts::ASK.to_string(), rules);
    }
    (verdict, rules)
}

/// Action types protected by the developer-workflow floor. On a clean session
/// (no credential taint) an advisory provider cannot escalate these. Mirrors the
/// Go kernel's cleanDeveloperWorkflowActions EXACTLY — both must agree for parity.
/// Push is deliberately excluded (it stays escalatable).
const CLEAN_DEV_WORKFLOW_ACTIONS: &[&str] = &[
    "file_read",
    "file_write",
    "file_list",
    "run_tests",
    "search_code",
    "vcs_status",
    "vcs_diff",
    "vcs_commit",
];

fn is_clean_developer_workflow(prior_taint: &[String], action_type: &str) -> bool {
    if prior_taint.iter().any(|t| t == "credential_access") {
        return false;
    }
    CLEAN_DEV_WORKFLOW_ACTIONS.contains(&action_type)
}

/// Fold advisory policy-provider verdicts into the base verdict. Returns the
/// (possibly escalated) verdict and the provider rule IDs that contributed.
/// Pure and deterministic — mirrors the Go kernel's composePolicyVerdicts EXACTLY
/// so the harness parity check exercises the production decision path.
///
/// Rules:
///  1. Developer-workflow floor: a clean-session allow on a protected action type
///     is returned unchanged — no advisory verdict can escalate it.
///  2. Otherwise an advisory ask/deny verdict escalates allow->ask.
///  3. A deny is never widened; advisory cannot lower a native deny.
fn compose_policy_verdicts(
    verdicts: &[PolicyVerdict],
    base: String,
    prior_taint: &[String],
    action_type: &str,
) -> (String, Vec<String>) {
    let mut verdict = base;
    let mut provider_rules: Vec<String> = Vec::new();

    if verdict == verdicts::ALLOW && is_clean_developer_workflow(prior_taint, action_type) {
        return (verdict, provider_rules);
    }

    for pv in verdicts {
        if !pv.is_advisory {
            continue;
        }
        if (pv.verdict == verdicts::ASK || pv.verdict == verdicts::DENY)
            && verdict == verdicts::ALLOW
        {
            verdict = verdicts::ASK.to_string();
            let mut tag = format!("policy:{}", pv.provider);
            if !pv.rules_matched.is_empty() {
                tag.push(':');
                tag.push_str(&pv.rules_matched.join(","));
            }
            provider_rules.push(tag);
        }
    }
    (verdict, provider_rules)
}

// ── Public entrypoint ─────────────────────────────────────────────────────────

/// The single pure entrypoint. Deterministic given the same input.
pub fn evaluate(input: &EvaluationInput) -> EvaluationOutput {
    let signals = &input.signals;

    let (enf_class, _enf_reason) = analyze_enforceability(input);
    let attribution = attribution_confidence(signals);
    let action_type = primary_action_type(signals).to_string();
    let sensitivity = primary_sensitivity(signals).to_string();
    let mut labels = labelize(&action_type, &sensitivity, signals);
    // Apply resolved actor kind from orchestrator. When the orchestrator has
    // fused a shell signal with agent-session evidence, add ai_agent_actor so
    // policy rules that key on it can fire. Mirrors Go Evaluate() exactly.
    if input.resolved_actor_kind == "ai_coding_agent"
        && !labels.iter().any(|l| l == "ai_agent_actor")
    {
        labels.push("ai_agent_actor".into());
    }

    let (pre_escalation_verdict, mut rules, mut effects) =
        evaluate_policy(&labels, &input.prior_taint);
    let (verdict, low_conf_rules) = apply_low_confidence_escalation(
        pre_escalation_verdict.clone(),
        rules,
        attribution,
        &sensitivity,
    );
    rules = low_conf_rules;

    // Advisory policy-verdict composition. Runs AFTER all native floors and
    // low-confidence escalation, mirroring the Go kernel exactly. Advisory
    // verdicts can only escalate allow->ask; they never widen a deny and cannot
    // bypass the developer-workflow floor. Empty verdicts => no-op (parity baseline).
    let (verdict, provider_rules) = compose_policy_verdicts(
        &input.policy_verdicts,
        verdict,
        &input.prior_taint,
        &action_type,
    );
    rules.extend(provider_rules);

    // When any escalation promoted allow -> ask, prepend a prompt effect so the
    // developer is notified. Without this the ask verdict has no prompt (silent UX).
    if pre_escalation_verdict == verdicts::ALLOW && verdict == verdicts::ASK {
        effects.insert(
            0,
            PlannedEffect {
                effect_type: effects::PROMPT.into(),
                required: false,
                fail_closed: false,
            },
        );
    }

    let decision_class = resolve_decision_class(&verdict, enf_class).to_string();

    // Compute new taint produced by this action.
    let new_taint = if sensitivity == "credential" {
        vec!["credential_access".to_string()]
    } else {
        vec![]
    };

    EvaluationOutput {
        verdict,
        decision_class,
        enforceability: enf_class.to_string(),
        attribution: attribution.to_string(),
        spoofing_risk: compute_spoofing_risk(input).to_string(),
        policy_rules: rules,
        effects,
        action_type,
        sensitivity,
        new_taint,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn signal_with(reliability: &str, timing: &str) -> Signal {
        Signal {
            source: SignalSource {
                reliability: reliability.into(),
                timing: timing.into(),
            },
            ..Default::default()
        }
    }

    fn cred_signal() -> Signal {
        Signal {
            source: SignalSource {
                reliability: reliability::ENFORCED_BOUNDARY.into(),
                timing: timing::PRE_EXEC.into(),
            },
            action_claim: ActionClaim {
                action_type: "file_read".into(),
                target: ActionTarget {
                    display: "~/.aws/credentials".into(),
                    sensitivity: "credential".into(),
                },
            },
            actor_kind: "ai_coding_agent".into(),
        }
    }

    #[test]
    fn hook_gate_with_pre_exec_enforces() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![signal_with(reliability::DECLARED_INTENT, timing::PRE_EXEC)],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.enforceability, classes::ENFORCES);
    }

    #[test]
    fn hook_gate_span_stripped_detects() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![signal_with(
                reliability::OBSERVED_RUNTIME,
                timing::POST_EXEC,
            )],
            evasion: EvasionFlags {
                span_stripped: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.enforceability, classes::DETECTS);
    }

    #[test]
    fn hook_gate_no_fallback_blind() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![],
            evasion: EvasionFlags {
                span_stripped: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.enforceability, classes::BLIND);
    }

    #[test]
    fn contained_without_provider_detects() {
        // Mode alone does not imply enforcement. Without an enforced_boundary signal
        // or provider_capabilities declaring block/contain, contained mode can only detect.
        let input = EvaluationInput {
            mode: modes::CONTAINED.into(),
            signals: vec![],
            provider_capabilities: vec![],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.enforceability, classes::DETECTS);
    }

    #[test]
    fn contained_with_declared_only_capability_detects() {
        // Soundness fix (item 3): a DECLARED contain capability with no demonstrated
        // enforcement (provider_enforcement unset/simulated) yields detects, not
        // enforces. A stub provider cannot make the kernel claim it enforces.
        let input = EvaluationInput {
            mode: modes::CONTAINED.into(),
            signals: vec![],
            provider_capabilities: vec!["contain".into(), "record".into()],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.enforceability,
            classes::DETECTS,
            "declared-only contain must be detects, not enforces"
        );
    }

    #[test]
    fn contained_with_demonstrated_capability_enforces() {
        // A declared contain capability WITH demonstrated enforcement (real) → enforces.
        let input = EvaluationInput {
            mode: modes::CONTAINED.into(),
            signals: vec![],
            provider_capabilities: vec!["contain".into(), "record".into()],
            provider_enforcement: "real".into(),
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.enforceability,
            classes::ENFORCES,
            "demonstrated (real) contain must enforce"
        );
    }

    // Item 8: action-scoped capability. A provider scoping real enforcement to a
    // subset of action types only enforces a covered action; an uncovered (or
    // unknown) action degrades to detects. Must match Go pkg/kernel exactly.
    fn action_signal(action_type: &str) -> Signal {
        Signal {
            source: SignalSource {
                reliability: reliability::DECLARED_INTENT.into(),
                timing: timing::PRE_EXEC.into(),
            },
            action_claim: ActionClaim {
                action_type: action_type.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn netjail_input(action_type: &str) -> EvaluationInput {
        EvaluationInput {
            mode: modes::CONTAINED.into(),
            signals: vec![action_signal(action_type)],
            provider_capabilities: vec!["block".into(), "record".into()],
            provider_enforcement: "real".into(),
            provider_enforced_actions: vec!["network_connect".into()],
            ..Default::default()
        }
    }

    #[test]
    fn action_scoped_covered_enforces() {
        let (class, _) = analyze_enforceability(&netjail_input("network_connect"));
        assert_eq!(class, classes::ENFORCES, "covered action must enforce");
    }

    #[test]
    fn action_scoped_uncovered_detects() {
        let (class, _) = analyze_enforceability(&netjail_input("file_write"));
        assert_eq!(
            class,
            classes::DETECTS,
            "uncovered action must degrade to detects, not over-claim enforces"
        );
    }

    #[test]
    fn action_scoped_unknown_action_detects() {
        // No action type → primary_action_type is "unknown", never in a non-empty
        // enforced list → detects.
        let mut input = netjail_input("network_connect");
        input.signals = vec![];
        let (class, _) = analyze_enforceability(&input);
        assert_eq!(
            class,
            classes::DETECTS,
            "unknown action must not claim enforces"
        );
    }

    #[test]
    fn action_scoped_empty_list_enforces_all() {
        // Backward compat: empty provider_enforced_actions = enforces everything.
        let mut input = netjail_input("file_write");
        input.provider_enforced_actions = vec![];
        let (class, _) = analyze_enforceability(&input);
        assert_eq!(
            class,
            classes::ENFORCES,
            "empty list must enforce all (backward compat)"
        );
    }

    // Item 9: mediated demonstrated-mediation gate. Mediated enforces only with
    // provider_enforcement=="real" or an enforced_boundary signal; a declared-only
    // pre-exec signal degrades to detects. Must match Go pkg/kernel exactly.
    #[test]
    fn mediated_real_enforcement_enforces() {
        let input = EvaluationInput {
            mode: modes::MEDIATED.into(),
            signals: vec![action_signal("network_connect")],
            provider_enforcement: "real".into(),
            ..Default::default()
        };
        let (class, _) = analyze_enforceability(&input);
        assert_eq!(class, classes::ENFORCES, "real mediation must enforce");
    }

    #[test]
    fn mediated_declared_only_detects() {
        let input = EvaluationInput {
            mode: modes::MEDIATED.into(),
            signals: vec![action_signal("network_connect")],
            ..Default::default()
        };
        let (class, _) = analyze_enforceability(&input);
        assert_eq!(
            class,
            classes::DETECTS,
            "declared-only mediation must degrade to detects, not over-claim enforces"
        );
    }

    #[test]
    fn mediated_enforced_boundary_signal_enforces() {
        let input = EvaluationInput {
            mode: modes::MEDIATED.into(),
            signals: vec![signal_with(
                reliability::ENFORCED_BOUNDARY,
                timing::PRE_EXEC,
            )],
            ..Default::default()
        };
        let (class, _) = analyze_enforceability(&input);
        assert_eq!(
            class,
            classes::ENFORCES,
            "enforced-boundary signal proves mediation"
        );
    }

    #[test]
    fn contained_with_enforced_boundary_signal_enforces() {
        // An enforced_boundary signal proves the sandbox is active even without
        // provider_capabilities being declared in the input.
        let input = EvaluationInput {
            mode: modes::CONTAINED.into(),
            signals: vec![Signal {
                source: SignalSource {
                    reliability: reliability::ENFORCED_BOUNDARY.into(),
                    timing: timing::PRE_EXEC.into(),
                },
                ..Default::default()
            }],
            provider_capabilities: vec![],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.enforceability, classes::ENFORCES);
    }

    #[test]
    fn required_effect_unavailable_fail_closed_enforces() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![signal_with(reliability::DECLARED_INTENT, timing::PRE_EXEC)],
            evasion: EvasionFlags {
                required_effect_unavail: true,
                fail_closed: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.enforceability, classes::ENFORCES);
    }

    #[test]
    fn deny_agent_credential_read() {
        let input = EvaluationInput {
            mode: modes::CONTAINED.into(),
            signals: vec![cred_signal()],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.verdict, verdicts::DENY);
        assert!(out
            .policy_rules
            .contains(&"deny-agent-credential-read".to_string()));
        assert_eq!(out.decision_class, decision_classes::DENY_NOW);
    }

    #[test]
    fn cross_action_secret_to_egress_via_prior_taint() {
        // Credential taint from a previous evaluation is passed as prior_taint.
        let egress_signal = Signal {
            source: SignalSource {
                reliability: reliability::DECLARED_INTENT.into(),
                timing: timing::PRE_EXEC.into(),
            },
            action_claim: ActionClaim {
                action_type: "network_connect".into(),
                target: ActionTarget {
                    display: "https://unknown.example".into(),
                    sensitivity: "external_network".into(),
                },
            },
            actor_kind: "ai_coding_agent".into(),
        };
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![egress_signal],
            prior_taint: vec!["credential_access".into()],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.verdict, verdicts::DENY);
        assert!(out
            .policy_rules
            .contains(&"deny-secret-to-egress".to_string()));
    }

    #[test]
    fn different_session_no_taint_no_deny() {
        // Same egress, but no prior taint — should be ask, not deny.
        let egress_signal = Signal {
            source: SignalSource {
                reliability: reliability::DECLARED_INTENT.into(),
                timing: timing::PRE_EXEC.into(),
            },
            action_claim: ActionClaim {
                action_type: "network_connect".into(),
                target: ActionTarget {
                    display: "https://unknown.example".into(),
                    sensitivity: "external_network".into(),
                },
            },
            actor_kind: "ai_coding_agent".into(),
        };
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![egress_signal],
            prior_taint: vec![], // no prior credential read
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.verdict, verdicts::ASK); // ask-external-egress fires, not deny
        assert!(!out
            .policy_rules
            .contains(&"deny-secret-to-egress".to_string()));
    }

    #[test]
    fn low_confidence_credential_escalates_to_ask() {
        let input = EvaluationInput {
            mode: modes::OS_OBSERVED.into(),
            signals: vec![Signal {
                source: SignalSource {
                    reliability: reliability::OBSERVED_RUNTIME.into(),
                    timing: timing::POST_EXEC.into(),
                },
                action_claim: ActionClaim {
                    action_type: "file_read".into(),
                    target: ActionTarget {
                        display: "~/.ssh/id_rsa".into(),
                        sensitivity: "credential".into(),
                    },
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let out = evaluate(&input);
        // low attribution + credential → escalates allow to ask
        assert_eq!(out.attribution, conf::LOW);
        assert_eq!(out.verdict, verdicts::ASK);
        assert!(out
            .policy_rules
            .contains(&"low-confidence-escalation".to_string()));
        // Escalation must add a prompt effect so the developer is notified.
        assert!(
            out.effects.iter().any(|e| e.effect_type == effects::PROMPT),
            "escalation must include prompt effect; got: {:?}",
            out.effects
        );
    }

    // ── Item 3: Actor attribution resolution ─────────────────────────────────

    fn shell_cred_signal() -> Signal {
        Signal {
            source: SignalSource {
                reliability: reliability::DECLARED_INTENT.into(),
                timing: timing::PRE_EXEC.into(),
            },
            action_claim: ActionClaim {
                action_type: "shell_exec".into(),
                target: ActionTarget {
                    display: "cat ~/.aws/credentials".into(),
                    sensitivity: "credential".into(),
                },
            },
            // Shell provider is honest: actor_kind="shell", not ai_coding_agent.
            actor_kind: "shell".into(),
        }
    }

    #[test]
    fn resolved_actor_kind_deny_fires_for_agent() {
        // With orchestrator resolution: deny-agent-credential-read MUST fire.
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![shell_cred_signal()],
            resolved_actor_kind: "ai_coding_agent".into(),
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.verdict,
            verdicts::DENY,
            "resolved ai_coding_agent + credential → want deny"
        );
        assert!(
            out.policy_rules
                .contains(&"deny-agent-credential-read".to_string()),
            "deny-agent-credential-read must fire for resolved agent; got {:?}",
            out.policy_rules
        );
    }

    // ── Item 4+5: SpoofingRisk and attribution goldens ──────────────────────────

    #[test]
    fn spoofing_risk_enforced_boundary_none() {
        let input = EvaluationInput {
            mode: modes::CONTAINED.into(),
            signals: vec![Signal {
                source: SignalSource {
                    reliability: reliability::ENFORCED_BOUNDARY.into(),
                    timing: timing::PRE_EXEC.into(),
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.spoofing_risk,
            spoofing::NONE,
            "enforced_boundary → none"
        );
        assert_eq!(
            out.attribution,
            conf::HIGH,
            "enforced_boundary → high confidence"
        );
    }

    #[test]
    fn spoofing_risk_declared_intent_low() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![signal_with(reliability::DECLARED_INTENT, timing::PRE_EXEC)],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.spoofing_risk,
            spoofing::LOW,
            "declared_intent no evasion → low"
        );
        assert_eq!(out.attribution, conf::MEDIUM);
    }

    #[test]
    fn spoofing_risk_span_forged_high() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![signal_with(reliability::DECLARED_INTENT, timing::PRE_EXEC)],
            evasion: EvasionFlags {
                span_forged: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.spoofing_risk, spoofing::HIGH, "span_forged → high");
    }

    #[test]
    fn spoofing_risk_span_stripped_no_fallback_high() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![signal_with(reliability::DECLARED_INTENT, timing::PRE_EXEC)],
            evasion: EvasionFlags {
                span_stripped: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.spoofing_risk,
            spoofing::HIGH,
            "span_stripped no fallback → high"
        );
    }

    #[test]
    fn spoofing_risk_span_stripped_with_fallback_medium() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![
                signal_with(reliability::DECLARED_INTENT, timing::PRE_EXEC),
                signal_with(reliability::OBSERVED_RUNTIME, timing::POST_EXEC),
            ],
            evasion: EvasionFlags {
                span_stripped: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.spoofing_risk,
            spoofing::MEDIUM,
            "span_stripped + os fallback → medium"
        );
    }

    #[test]
    fn spoofing_risk_no_signals_high() {
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(out.spoofing_risk, spoofing::HIGH, "no signals → high");
        assert_eq!(
            out.attribution,
            conf::UNKNOWN,
            "no signals → unknown confidence"
        );
    }

    #[test]
    fn resolved_actor_kind_deny_does_not_fire_without_resolution() {
        // Without orchestrator resolution: deny-agent-credential-read must NOT fire.
        // A developer's own shell credential access must not be silently denied.
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![shell_cred_signal()],
            resolved_actor_kind: "".into(), // no agent-session evidence
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_ne!(
            out.verdict,
            verdicts::DENY,
            "shell credential access without agent resolution must not deny"
        );
        assert!(
            !out.policy_rules
                .contains(&"deny-agent-credential-read".to_string()),
            "deny-agent-credential-read must NOT fire without resolution; got {:?}",
            out.policy_rules
        );
        // declared_intent → medium attribution
        assert_eq!(out.attribution, conf::MEDIUM);
    }

    // ── Policy-verdict composition (item 1) + non-bypassable floors (item 7) ──

    fn dev_signal(action_type: &str, sensitivity: &str, actor: &str) -> Signal {
        Signal {
            source: SignalSource {
                reliability: reliability::DECLARED_INTENT.into(),
                timing: timing::PRE_EXEC.into(),
            },
            action_claim: ActionClaim {
                action_type: action_type.into(),
                target: ActionTarget {
                    display: action_type.into(),
                    sensitivity: sensitivity.into(),
                },
            },
            actor_kind: actor.into(),
        }
    }

    fn advisory(verdict: &str, rules: &[&str]) -> PolicyVerdict {
        PolicyVerdict {
            provider: "opa-bridge".into(),
            verdict: verdict.into(),
            rules_matched: rules.iter().map(|s| s.to_string()).collect(),
            reason: String::new(),
            is_advisory: true,
        }
    }

    #[test]
    fn compose_clean_commit_floor_suppresses_advisory_deny() {
        // Clean human commit + OPA deny → floor protects → allow, no provider rule.
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![dev_signal("vcs_commit", "low", "human_developer")],
            policy_verdicts: vec![advisory(verdicts::DENY, &["forbid-all-commits"])],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.verdict,
            verdicts::ALLOW,
            "clean commit must stay allow despite OPA deny"
        );
        assert!(
            out.policy_rules.is_empty(),
            "floor returns before adding provider rule; got {:?}",
            out.policy_rules
        );
    }

    #[test]
    fn compose_agent_push_advisory_ask_escalates() {
        // Agent push (not floored) + OPA ask → escalate allow->ask with provider rule.
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![dev_signal("vcs_push", "low", "ai_coding_agent")],
            policy_verdicts: vec![advisory(verdicts::ASK, &["agent-push-review"])],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.verdict,
            verdicts::ASK,
            "push is not floored; advisory ask must escalate"
        );
        assert!(
            out.policy_rules
                .contains(&"policy:opa-bridge:agent-push-review".to_string()),
            "expected provider rule attribution; got {:?}",
            out.policy_rules
        );
    }

    #[test]
    fn compose_advisory_cannot_widen_native_deny() {
        // Native deny (agent + credential) + advisory ask/deny → stays deny.
        for adv in [verdicts::ASK, verdicts::DENY, verdicts::ALLOW] {
            let input = EvaluationInput {
                mode: modes::HOOK_GATE.into(),
                signals: vec![dev_signal("vcs_commit", "credential", "ai_coding_agent")],
                policy_verdicts: vec![advisory(adv, &["x"])],
                ..Default::default()
            };
            let out = evaluate(&input);
            assert_eq!(
                out.verdict,
                verdicts::DENY,
                "advisory '{adv}' must not change a native deny; got {}",
                out.verdict
            );
        }
    }

    #[test]
    fn compose_no_verdicts_is_noop() {
        // Absence of policy verdicts reproduces the pre-provider baseline exactly.
        let base = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![dev_signal("vcs_push", "low", "ai_coding_agent")],
            ..Default::default()
        };
        let out = evaluate(&base);
        assert_eq!(
            out.verdict,
            verdicts::ALLOW,
            "clean agent push with no verdicts = allow baseline"
        );
    }

    #[test]
    fn compose_non_advisory_verdict_ignored() {
        // A verdict marked is_advisory=false must not affect composition.
        let mut pv = advisory(verdicts::ASK, &["x"]);
        pv.is_advisory = false;
        let input = EvaluationInput {
            mode: modes::HOOK_GATE.into(),
            signals: vec![dev_signal("vcs_push", "low", "ai_coding_agent")],
            policy_verdicts: vec![pv],
            ..Default::default()
        };
        let out = evaluate(&input);
        assert_eq!(
            out.verdict,
            verdicts::ALLOW,
            "non-advisory verdict must be ignored by composition"
        );
    }
}
