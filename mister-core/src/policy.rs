//! Policy rule evaluation.
//!
//! Maps verb + labels + session state to verdict (allow/deny/ask).
//! Enforces the documented runtime-security contract for sir.

#[path = "policy_common.rs"]
mod policy_common;
#[path = "policy_guards.rs"]
mod policy_guards;
#[path = "policy_sinks.rs"]
mod policy_sinks;

use crate::lease::Lease;
use crate::session::SessionState;
use mister_shared::{EvalRequest, PolicyVerdict, Verb, Verdict};
pub use policy_common::PolicyResult;
use policy_common::{
    ask_verb_result, default_unknown_verb_result, evaluate_allowed_verb, forbidden_verb_result,
    parse_verb,
};
use policy_guards::{
    evaluate_delegation_guardrails, evaluate_network_guardrails, evaluate_preapproval_guards,
    evaluate_secret_session_guards, evaluate_session_preconditions,
    evaluate_untrusted_publish_guardrails,
};
use policy_sinks::evaluate_derived_secret_sink;

/// Evaluate the policy for a given request against the lease and session state.
///
/// Enforcement gradient:
/// ```text
/// Secret file read                    -> ask (developer decides)
/// Secret session + external egress    -> block
/// Untrusted content + external egress -> block (integrity wall)
/// Secret session + unapproved push    -> block
/// Secret session + loopback/approved  -> allow
/// Posture file write                  -> ask (always)
/// Posture file tampered via Bash      -> session-fatal deny-all
/// New MCP server                      -> ask
/// Agent delegation after untrusted    -> ask
/// Tripwire file touched               -> block
/// Unlocked package install            -> ask
/// Normal coding (read/write/test/commit) -> silent allow
/// ```
pub fn evaluate(req: &EvalRequest, lease: &Lease, session: &SessionState) -> PolicyResult {
    let result = evaluate_inner(req, lease, session);
    // Apply advisory policy verdicts from external providers AFTER all native
    // safety floors have run. Advisory providers can only escalate allow → ask;
    // they cannot override a deny or bypass any native floor.
    compose_policy_verdicts(&req.policy_verdicts, result, req)
}

fn evaluate_inner(req: &EvalRequest, lease: &Lease, session: &SessionState) -> PolicyResult {
    if let Some(result) = evaluate_session_preconditions(req, lease, session) {
        return result;
    }

    let verb = match parse_verb(req) {
        Ok(verb) => verb,
        Err(result) => return result,
    };

    if let Some(result) = evaluate_preapproval_guards(req, verb) {
        return result;
    }

    if let Some(result) = evaluate_derived_secret_sink(req, verb) {
        if lease.is_verb_forbidden(verb) && !matches!(result.verdict, Verdict::Deny) {
            return forbidden_verb_result(verb);
        }
        return result;
    }

    if let Some(result) = evaluate_network_guardrails(req, lease, verb) {
        return result;
    }

    if lease.is_verb_forbidden(verb) {
        return forbidden_verb_result(verb);
    }

    if let Some(result) = evaluate_secret_session_guards(req, session, verb) {
        return result;
    }

    if let Some(result) = evaluate_untrusted_publish_guardrails(req, verb) {
        return result;
    }

    if let Some(result) = evaluate_delegation_guardrails(req, lease, session, verb) {
        return result;
    }

    if lease.is_verb_ask(verb) {
        return ask_verb_result(verb);
    }

    if lease.is_verb_allowed(verb) {
        return evaluate_allowed_verb(req, verb);
    }

    default_unknown_verb_result(req, verb)
}

/// Compose advisory policy verdicts from external providers with the base
/// kernel verdict.
///
/// Composition rules (in priority order):
/// 1. Developer workflow floor: canonical coding verbs (read, write, test,
///    commit, list, search) on a clean session are NEVER escalated by advisory
///    providers. This protects developers from policy packs that might ask on
///    every file read or test run. Taint (session_was_secret, session_secret)
///    lifts this floor so the was-secret push rule still fires when needed.
/// 2. Native safety floors already ran in evaluate_inner and cannot be overridden.
/// 3. Advisory providers can only escalate: allow → ask (never allow → deny).
/// 4. A deny from an advisory provider is treated as ask (cannot mandate deny).
/// 5. The base verdict is returned unchanged if no advisory escalation applies.
///
/// This preserves the invariant: Rust sir-core is the final authority; external
/// providers supply evidence, not enforcement.
fn compose_policy_verdicts(
    verdicts: &[PolicyVerdict],
    base: PolicyResult,
    req: &EvalRequest,
) -> PolicyResult {
    let mut result = base;

    // Developer workflow floor: protect clean-session coding verbs from advisory
    // escalation. A policy provider that asks on `git commit` or `ls` would make
    // SIR unusable; this floor prevents that without restricting the policy
    // provider's ability to supply verdicts for genuinely risky actions.
    if matches!(result.verdict, Verdict::Allow) && is_clean_developer_workflow(req) {
        return result;
    }

    for pv in verdicts {
        if !pv.is_advisory {
            continue; // non-advisory verdicts rejected at parse time; belt-and-suspenders
        }
        if matches!(pv.verdict, Verdict::Ask | Verdict::Deny)
            && matches!(result.verdict, Verdict::Allow)
        {
            result.verdict = Verdict::Ask;
            if !pv.rules_matched.is_empty() {
                result.reason = format!(
                    "{}. [policy:{} rules:{}]",
                    result.reason,
                    pv.provider_name,
                    pv.rules_matched.join(",")
                );
            }
        }
    }
    result
}

/// Reports whether this request is a clean-session developer workflow action
/// that advisory policy providers must not escalate.
///
/// The floor only holds when BOTH conditions are true:
/// - No live credentials in session (session_secret = false)
/// - No prior credential taint (session_was_secret = false)
///
/// Once either flag is set, the floor lifts and advisory providers (e.g.
/// was-secret-push-origin) can escalate normally.
fn is_clean_developer_workflow(req: &EvalRequest) -> bool {
    if req.session_secret || req.session_was_secret {
        return false;
    }
    let verb = match parse_verb(req) {
        Ok(v) => v,
        Err(_) => return false, // unknown verb: not protected
    };
    matches!(
        verb,
        Verb::ReadRef
            | Verb::StageWrite
            | Verb::ExecuteDryRun
            | Verb::RunTests
            | Verb::Commit
            | Verb::ListFiles
            | Verb::SearchCode
            | Verb::NetLocal
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mister_shared::{Label, Verb};

    fn default_lease() -> Lease {
        Lease::default_lease()
    }

    fn clean_session() -> SessionState {
        SessionState::new()
    }

    fn secret_session() -> SessionState {
        let mut s = SessionState::new();
        s.mark_secret();
        s
    }

    fn make_request(verb: &str) -> EvalRequest {
        EvalRequest {
            verb: verb.to_string(),
            target: String::new(),
            tool_name: String::new(),
            labels: vec![],
            derived_labels: vec![],
            session_secret: false,
            session_was_secret: false,
            session_untrusted_read: false,
            session_untrusted_this_turn: false,
            is_posture_file: false,
            is_sensitive_path: false,
            is_delegation: false,
            is_tripwire: false,
            policy_verdicts: vec![],
        }
    }

    // --- Normal coding: silent allow ---

    #[test]
    fn test_read_normal_file_allowed() {
        let req = make_request("read_ref");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_write_normal_file_allowed() {
        let req = make_request("stage_write");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_run_tests_allowed() {
        let req = make_request("run_tests");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_git_commit_allowed() {
        let req = make_request("commit");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_execute_dry_run_allowed() {
        let req = make_request("execute_dry_run");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_net_local_allowed() {
        let req = make_request("net_local");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_push_origin_allowed() {
        let req = make_request("push_origin");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    // --- Secret file read: ask ---

    #[test]
    fn test_read_sensitive_file_asks() {
        let mut req = make_request("read_ref");
        req.is_sensitive_path = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("sensitive"));
    }

    // --- Posture file write: always ask ---

    #[test]
    fn test_write_posture_file_asks() {
        let mut req = make_request("stage_write");
        req.is_posture_file = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("security settings"));
    }

    // --- Secret session + external egress: block ---

    #[test]
    fn test_net_external_denied() {
        let req = make_request("net_external");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_net_external_with_secret_session_denied() {
        let mut req = make_request("net_external");
        req.session_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    // --- Secret session + loopback: allow ---

    #[test]
    fn test_net_local_with_secret_session_allowed() {
        let mut req = make_request("net_local");
        req.session_secret = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    // --- Secret session + approved host: allow ---

    #[test]
    fn test_net_allowlisted_with_secret_session_allowed() {
        let mut req = make_request("net_allowlisted");
        req.session_secret = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    // --- Secret session + push origin: ask ---

    #[test]
    fn test_push_origin_with_secret_session_asks() {
        let mut req = make_request("push_origin");
        req.session_secret = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("credentials"));
    }

    // --- Secret session + push remote (unapproved): block ---

    #[test]
    fn test_push_remote_with_secret_session_denied() {
        let mut req = make_request("push_remote");
        req.session_secret = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    // --- Push remote (no secret): ask ---

    #[test]
    fn test_push_remote_no_secret_asks() {
        let req = make_request("push_remote");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    // --- High-water mark (was-secret, turn-scoped flag cleared) ---

    #[test]
    fn test_push_origin_was_secret_allows_from_oracle() {
        // The was-secret re-prompt rule has been moved to the policy provider
        // layer (compose_policy_verdicts). Without an advisory verdict in
        // policy_verdicts, push_origin + session_was_secret = Allow from the
        // Rust oracle — PushOrigin is in AllowedVerbs and the live-secret floor
        // did not fire (session_secret=false). The policy provider (sir-policy-pack)
        // supplies the was-secret advisory verdict that escalates this to Ask.
        let mut req = make_request("push_origin");
        req.session_was_secret = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_push_origin_was_secret_asks_with_advisory_verdict() {
        // When a policy provider supplies an advisory ask verdict (as the native
        // policy pack does for was-secret sessions), compose_policy_verdicts
        // escalates Allow → Ask.
        use mister_shared::PolicyVerdict;
        let mut req = make_request("push_origin");
        req.session_was_secret = true;
        req.policy_verdicts = vec![PolicyVerdict {
            provider_name: "sir-policy-pack".to_string(),
            verdict: Verdict::Ask,
            rules_matched: vec!["was-secret-push-origin".to_string()],
            is_advisory: true,
        }];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    #[test]
    fn test_push_remote_was_secret_asks() {
        let mut req = make_request("push_remote");
        req.session_was_secret = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    #[test]
    fn test_net_external_was_secret_still_at_least_asks() {
        // net_external is handled by the network guardrail before the secret
        // guard; a was-secret session must never silently allow egress.
        let mut req = make_request("net_external");
        req.session_was_secret = true;
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_ne!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_was_secret_never_widens_a_forbidding_lease() {
        // A lease that forbids push must still deny even when only the
        // high-water mark (not the live secret flag) is set.
        let mut req = make_request("push_origin");
        req.session_was_secret = true;
        let mut lease = default_lease();
        lease.forbidden_verbs.push(Verb::PushOrigin);
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_live_secret_beats_was_secret_for_push_remote() {
        // When the live secret flag is set, push_remote is a hard deny — the
        // was-secret downgrade must not soften it.
        let mut req = make_request("push_remote");
        req.session_secret = true;
        req.session_was_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_stage_write_with_derived_secret_asks() {
        let mut req = make_request("stage_write");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_commit_with_derived_secret_asks() {
        let mut req = make_request("commit");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_push_origin_with_derived_secret_asks_without_session_secret() {
        let mut req = make_request("push_origin");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_push_remote_with_derived_secret_denied_without_session_secret() {
        let mut req = make_request("push_remote");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("staged content derives"));
    }

    #[test]
    fn test_forbidden_verb_beats_derived_secret_sink_override() {
        let mut req = make_request("push_origin");
        req.derived_labels = vec![Label::secret()];
        let mut lease = default_lease();
        lease.forbidden_verbs.push(Verb::PushOrigin);

        let result = evaluate(&req, &lease, &clean_session());

        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("forbidden by your security policy"));
    }

    #[test]
    fn test_forbidden_verb_denies_without_derived_labels() {
        let req = make_request("push_origin");
        let mut lease = default_lease();
        lease.forbidden_verbs.push(Verb::PushOrigin);

        let result = evaluate(&req, &lease, &clean_session());

        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("forbidden by your security policy"));
    }

    #[test]
    fn test_net_allowlisted_with_derived_secret_asks_without_session_secret() {
        let mut req = make_request("net_allowlisted");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_net_external_with_derived_secret_denied_without_session_secret() {
        let mut req = make_request("net_external");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_dns_lookup_with_derived_secret_denied_without_session_secret() {
        let mut req = make_request("dns_lookup");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    // --- Run ephemeral (npx): always ask ---

    #[test]
    fn test_run_ephemeral_asks() {
        let req = make_request("run_ephemeral");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("Remote code execution"));
    }

    // --- Tripwire: block ---

    #[test]
    fn test_tripwire_denies() {
        let mut req = make_request("read_ref");
        req.is_tripwire = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("Tripwire"));
    }

    // --- Delegation: allowed by default lease in clean sessions ---

    #[test]
    fn test_delegation_allowed_by_default_lease_clean_session() {
        // Default lease has allow_delegation: true and "delegate" in AllowedVerbs.
        // Clean session (no secrets, no untrusted reads) → Allow.
        let mut req = make_request("delegate");
        req.is_delegation = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_delegation_denied_when_lease_disallows() {
        // If allow_delegation is false, step 2 denies it regardless of verb.
        let mut req = make_request("read_ref");
        req.is_delegation = true;
        let mut lease = default_lease();
        lease.allow_delegation = false;
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("Delegation"));
    }

    // --- Delegation after untrusted: ask ---

    #[test]
    fn test_delegation_after_untrusted_asks() {
        let mut req = make_request("read_ref");
        req.is_delegation = true;
        let mut lease = default_lease();
        lease.allow_delegation = true;
        let mut session = clean_session();
        session.mark_untrusted_read();
        let result = evaluate(&req, &lease, &session);
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("untrusted"));
    }

    // --- Session deny-all ---

    #[test]
    fn test_deny_all_session() {
        let req = make_request("read_ref");
        let mut session = clean_session();
        session.mark_deny_all();
        let result = evaluate(&req, &default_lease(), &session);
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("deny-all"));
    }

    // --- Unknown verb: ask ---

    #[test]
    fn test_unknown_verb_asks() {
        let req = make_request("some_unknown_verb");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    // --- Net allowlisted without secret: ask ---

    #[test]
    fn test_net_allowlisted_no_secret_asks() {
        let req = make_request("net_allowlisted");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    // --- Read .env.example (not sensitive): allow ---

    #[test]
    fn test_read_non_sensitive_allowed() {
        // The is_sensitive_path flag is false for .env.example (Go layer handles exclusions).
        let req = make_request("read_ref");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    // --- EnvRead: ask ---

    #[test]
    fn test_env_read_asks() {
        let req = make_request("env_read");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.to_lowercase().contains("environment"));
    }

    // --- DnsLookup / NetExternal egress gradient (NET-1/NET-2) ---

    #[test]
    fn test_dns_lookup_clean_asks_when_not_forbidden() {
        // NET-2: on a clean session with a personal/team lease (dns not
        // forbidden), an outbound DNS lookup is an approval prompt, not a block.
        let req = make_request("dns_lookup");
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("DNS"));
    }

    #[test]
    fn test_dns_lookup_forbidden_denied() {
        // Strict/managed forbid dns_lookup -> hard Deny even on a clean session.
        let req = make_request("dns_lookup");
        let mut lease = default_lease();
        lease.forbidden_verbs = vec![Verb::DnsLookup];
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_net_external_clean_asks_when_not_forbidden() {
        // NET-1: clean session, not forbidden (personal/team) -> approval prompt.
        let req = make_request("net_external");
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    // --- Integrity-flow egress wall (P0.3): untrusted content + egress -> block ---

    #[test]
    fn test_net_external_untrusted_read_denied_even_when_not_forbidden() {
        // The trifecta exfil leg: untrusted content was ingested this session
        // (detected MCP injection, or external-package read), so external egress
        // escalates from the clean-session Ask to a hard Deny — even on a
        // personal lease that does not forbid net_external.
        let mut req = make_request("net_external");
        req.session_untrusted_read = true;
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("untrusted content"));
        // Distinct from the secret wall — this is the integrity wall.
        assert!(!result.reason.contains("credentials"));
    }

    #[test]
    fn test_dns_lookup_untrusted_read_denied_even_when_not_forbidden() {
        let mut req = make_request("dns_lookup");
        req.session_untrusted_read = true;
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("untrusted content"));
    }

    #[test]
    fn test_net_external_untrusted_read_secret_session_still_credentials_deny() {
        // The secret wall runs first: when BOTH flags are set, the credentials
        // deny wins so the message stays accurate. Integrity wall never widens it.
        let mut req = make_request("net_external");
        req.session_untrusted_read = true;
        req.session_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    #[test]
    fn test_net_external_no_untrusted_read_still_asks_clean() {
        // Regression: the integrity wall must NOT fire on a clean session with no
        // untrusted ingestion — that would be over-blocking.
        let req = make_request("net_external");
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    #[test]
    fn test_net_external_untrusted_this_turn_denied() {
        // Weak turn-scoped signal: untrusted content (MCP/web) was ingested this
        // turn. Same-turn external egress is the dangerous injection shape -> deny,
        // even though session_untrusted_read (the strong signal) is not set.
        let mut req = make_request("net_external");
        req.session_untrusted_this_turn = true;
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("untrusted content"));
    }

    #[test]
    fn test_dns_lookup_untrusted_this_turn_denied() {
        let mut req = make_request("dns_lookup");
        req.session_untrusted_this_turn = true;
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_push_remote_untrusted_this_turn_denied() {
        let mut req = make_request("push_remote");
        req.session_untrusted_this_turn = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("untrusted content"));
    }

    #[test]
    fn test_push_remote_untrusted_read_denied() {
        let mut req = make_request("push_remote");
        req.session_untrusted_read = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("untrusted content"));
    }

    #[test]
    fn test_push_origin_untrusted_this_turn_asks() {
        let mut req = make_request("push_origin");
        req.session_untrusted_this_turn = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("untrusted content"));
    }

    #[test]
    fn test_net_external_untrusted_this_turn_cleared_reverts_to_ask() {
        // Quiet on normal coding: once the turn-scoped flag clears (next turn),
        // egress is back to a plain approval prompt — cross-turn fetch-then-egress
        // is not blocked.
        let mut req = make_request("net_external");
        req.session_untrusted_this_turn = false; // boundary cleared it
        let mut lease = default_lease();
        lease.forbidden_verbs.clear();
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    #[test]
    fn test_dns_lookup_with_secret_session_denied() {
        let mut req = make_request("dns_lookup");
        req.session_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    // --- Persistence: ask ---

    #[test]
    fn test_persistence_asks() {
        let req = make_request("persistence");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("Scheduled task"));
    }

    // --- Sudo: ask ---

    #[test]
    fn test_sudo_asks() {
        let req = make_request("sudo");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("Elevated"));
    }

    // --- DeletePosture: ask ---

    #[test]
    fn test_delete_posture_asks() {
        let req = make_request("delete_posture");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("security"));
    }

    #[test]
    fn test_delete_posture_with_posture_flag_asks() {
        let mut req = make_request("delete_posture");
        req.is_posture_file = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("security"));
    }

    // --- Delegate verb ---

    #[test]
    fn test_delegate_clean_session_allowed() {
        // Default lease: "delegate" in AllowedVerbs + allow_delegation: true → silent allow in clean session.
        let req = make_request("delegate");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_delegate_secret_session_denied() {
        let mut req = make_request("delegate");
        req.session_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    #[test]
    fn test_delegate_after_untrusted_read_asks() {
        let req = make_request("delegate");
        let mut session = clean_session();
        session.mark_untrusted_read();
        let result = evaluate(&req, &default_lease(), &session);
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("untrusted"));
    }

    // --- McpUnapproved verb ---

    #[test]
    fn test_mcp_unapproved_asks() {
        let req = make_request("mcp_unapproved");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("MCP"));
    }

    // --- check_flow integration ---

    #[test]
    fn test_check_flow_secret_label_to_external_denied() {
        // Even if net_external were somehow in allowed verbs (it's not), check_flow would catch it.
        // Test via stage_write (trusted sink) with secret label — should allow.
        let mut req = make_request("stage_write");
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow); // secret → trusted sink is fine
    }

    #[test]
    fn test_check_flow_secret_label_normal_write_allowed() {
        let mut req = make_request("stage_write");
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_check_flow_public_label_external_denied_by_policy() {
        // net_external is in ForbiddenVerbs, so it denies before check_flow
        let req = make_request("net_external");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
    }

    // ── Developer workflow floor tests ──────────────────────────────────────

    #[test]
    fn test_clean_session_commit_not_escalated_by_advisory() {
        // A clean-session commit must never be escalated by advisory providers.
        // This is the core developer-workflow protection: a policy pack that
        // inadvertently matches "commit" on a clean session is suppressed.
        use mister_shared::PolicyVerdict;
        let mut req = make_request("commit");
        req.policy_verdicts = vec![PolicyVerdict {
            provider_name: "overzealous-pack".to_string(),
            verdict: Verdict::Ask,
            rules_matched: vec!["ask-everything".to_string()],
            is_advisory: true,
        }];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(
            result.verdict,
            Verdict::Allow,
            "clean-session commit must be Allow even with advisory ask verdict"
        );
    }

    #[test]
    fn test_clean_session_read_ref_not_escalated() {
        use mister_shared::PolicyVerdict;
        let mut req = make_request("read_ref");
        req.policy_verdicts = vec![PolicyVerdict {
            provider_name: "test".to_string(),
            verdict: Verdict::Ask,
            rules_matched: vec![],
            is_advisory: true,
        }];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(
            result.verdict,
            Verdict::Allow,
            "clean-session read_ref must stay Allow regardless of advisory verdicts"
        );
    }

    #[test]
    fn test_tainted_session_lifts_developer_floor() {
        // When session_was_secret=true the developer floor lifts, allowing
        // advisory providers to escalate push_origin to Ask.
        use mister_shared::PolicyVerdict;
        let mut req = make_request("push_origin");
        req.session_was_secret = true;
        req.policy_verdicts = vec![PolicyVerdict {
            provider_name: "sir-policy-pack".to_string(),
            verdict: Verdict::Ask,
            rules_matched: vec!["was-secret-push-origin".to_string()],
            is_advisory: true,
        }];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(
            result.verdict,
            Verdict::Ask,
            "was-secret push_origin must escalate to Ask when session_was_secret=true"
        );
    }

    #[test]
    fn test_live_secret_session_lifts_developer_floor_for_push() {
        // With session_secret=true the developer floor lifts and the native
        // secret-session guard fires — advisory composition is irrelevant.
        let mut req = make_request("push_origin");
        req.session_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        // Native guard produces Ask (live credentials, known remote).
        assert_eq!(result.verdict, Verdict::Ask);
    }

    #[test]
    fn test_non_workflow_verb_not_protected_by_floor() {
        // push_origin on a clean session is in AllowedVerbs → Allow.
        // An advisory ask verdict CAN escalate it (floor only covers
        // the core coding verbs, not push).
        use mister_shared::PolicyVerdict;
        let mut req = make_request("push_origin");
        req.policy_verdicts = vec![PolicyVerdict {
            provider_name: "custom-pack".to_string(),
            verdict: Verdict::Ask,
            rules_matched: vec!["always-ask-push".to_string()],
            is_advisory: true,
        }];
        let result = evaluate(&req, &default_lease(), &clean_session());
        // push_origin is not in the developer workflow floor — advisory can escalate.
        assert_eq!(result.verdict, Verdict::Ask);
    }

    #[test]
    fn test_advisory_verdict_cannot_widen_native_deny() {
        // Item 7: an advisory verdict (ask OR deny) must never change a native
        // deny. A lease that forbids a verb produces a native deny; no advisory
        // verdict from any provider can flip it to allow or otherwise weaken it.
        use mister_shared::PolicyVerdict;
        for adv in [Verdict::Ask, Verdict::Deny, Verdict::Allow] {
            let mut req = make_request("push_origin");
            req.policy_verdicts = vec![PolicyVerdict {
                provider_name: "rogue-pack".to_string(),
                verdict: adv,
                rules_matched: vec!["override-attempt".to_string()],
                is_advisory: true,
            }];
            let mut lease = default_lease();
            lease.forbidden_verbs.push(Verb::PushOrigin);
            let result = evaluate(&req, &lease, &clean_session());
            assert_eq!(
                result.verdict,
                Verdict::Deny,
                "advisory {adv:?} must not change a native (forbidden-verb) deny",
            );
        }
    }

    #[test]
    fn test_advisory_cannot_lower_secret_session_deny() {
        // Item 7: the live-credential floor (secret session + unapproved push)
        // is a hard deny. An advisory allow must not lower it.
        use mister_shared::PolicyVerdict;
        let mut req = make_request("push_remote");
        req.session_secret = true;
        req.policy_verdicts = vec![PolicyVerdict {
            provider_name: "rogue-pack".to_string(),
            verdict: Verdict::Allow,
            rules_matched: vec!["allow-all".to_string()],
            is_advisory: true,
        }];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(
            result.verdict,
            Verdict::Deny,
            "advisory allow must not lower a live-secret push_remote deny"
        );
    }
}
