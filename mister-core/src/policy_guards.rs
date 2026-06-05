use crate::lease::Lease;
use crate::session::SessionState;
use mister_shared::{EvalRequest, RiskTier, Verb, Verdict};

use super::policy_common::{policy_result, PolicyResult};

pub(super) fn evaluate_session_preconditions(
    req: &EvalRequest,
    lease: &Lease,
    session: &SessionState,
) -> Option<PolicyResult> {
    if session.deny_all {
        return Some(policy_result(
            Verdict::Deny,
            "Session in deny-all state: security settings were modified unexpectedly.",
            RiskTier::R4,
        ));
    }
    if req.is_tripwire {
        return Some(policy_result(
            Verdict::Deny,
            "Tripwire file accessed.",
            RiskTier::R4,
        ));
    }
    if req.is_delegation {
        if !lease.allow_delegation {
            return Some(policy_result(
                Verdict::Deny,
                "Delegation not allowed by your security policy.",
                RiskTier::R4,
            ));
        }
        if session.recently_read_untrusted {
            return Some(policy_result(
                Verdict::Ask,
                "Delegation after untrusted data read.",
                RiskTier::R3,
            ));
        }
    }
    None
}

pub(super) fn evaluate_preapproval_guards(req: &EvalRequest, verb: Verb) -> Option<PolicyResult> {
    if req.is_posture_file && matches!(verb, Verb::StageWrite | Verb::DeletePosture) {
        let reason = if matches!(verb, Verb::DeletePosture) {
            "Delete/link of security settings file requires approval."
        } else {
            "Write to security settings file requires approval."
        };
        return Some(policy_result(Verdict::Ask, reason, RiskTier::R3));
    }
    if matches!(verb, Verb::DeletePosture) {
        return Some(policy_result(
            Verdict::Ask,
            "Delete/link targeting security-relevant file requires approval.",
            RiskTier::R3,
        ));
    }
    if req.is_sensitive_path && matches!(verb, Verb::ReadRef) {
        return Some(policy_result(
            Verdict::Ask,
            "Read of sensitive file requires approval.",
            RiskTier::R3,
        ));
    }
    match verb {
        Verb::EnvRead => Some(policy_result(
            Verdict::Ask,
            "Environment variable read may expose secrets.",
            RiskTier::R3,
        )),
        Verb::Persistence => Some(policy_result(
            Verdict::Ask,
            "Scheduled task creation requires approval.",
            RiskTier::R3,
        )),
        Verb::Sudo => Some(policy_result(
            Verdict::Ask,
            "Elevated privilege execution requires approval.",
            RiskTier::R3,
        )),
        Verb::DangerousShell => Some(policy_result(
            Verdict::Ask,
            "Destructive shell operation requires approval.",
            RiskTier::R3,
        )),
        Verb::SirSelf => Some(policy_result(
            Verdict::Ask,
            "sir CLI self-modification requires developer approval.",
            RiskTier::R3,
        )),
        Verb::McpUnapproved => Some(policy_result(
            Verdict::Ask,
            "MCP server not in approved list — unknown server.",
            RiskTier::R3,
        )),
        Verb::McpNetworkUnapproved => Some(policy_result(
            Verdict::Ask,
            "MCP tool argument URL host not in approved hosts — gate honest MCPs only; malicious MCPs may ignore args.",
            RiskTier::R3,
        )),
        Verb::McpOnboarding => Some(policy_result(
            Verdict::Ask,
            "MCP server is within its onboarding window (recently approved or low call count). Friction, not containment.",
            RiskTier::R3,
        )),
        Verb::McpBinaryDrift => Some(policy_result(
            Verdict::Ask,
            "MCP command binary changed since approval — hash mismatch. Re-approve after verifying the change.",
            RiskTier::R3,
        )),
        _ => None,
    }
}

/// INTEGRITY-FLOW egress wall (P0.3, the FIDES "low-integrity must not reach a
/// high-integrity sink" rule, applied to outbound network actions).
///
/// Fires on either of two untrusted-ingestion signals:
///   - `session_untrusted_read` (strong, session-scoped): a detected MCP prompt
///     injection, or a read of external-package-provenance content.
///   - `session_untrusted_this_turn` (weak, turn-scoped): any untrusted content
///     (MCP tool output / fetched web content) ingested this turn, even if the
///     injection scanner did not flag it. This clears at the next turn boundary,
///     so it gates the dangerous *same-turn* untrusted->egress shape without
///     making cross-turn fetch-then-egress workflows loud.
///
/// In both cases the ingested untrusted content must not be allowed to silently
/// drive outbound egress — the *exfiltration leg* of the lethal trifecta. It is
/// the integrity dual of the confidentiality `session_secret` wall: secret data
/// must not flow OUT; untrusted instructions must not steer the flow OUT.
///
/// This only ever converts the clean-session **Ask into a Deny** (it is the last
/// branch, reached only after the secret-session and forbidden-lease Deny
/// branches), so it strictly tightens and can never widen a deny. The escape
/// hatch is the same as the secret wall: verify intent, then `sir unlock`.
fn untrusted_egress_deny(action: &str) -> PolicyResult {
    policy_result(
        Verdict::Deny,
        // No "credentials" wording: this is the integrity wall, not the secret
        // wall. Distinct reason so the ledger and `sir why` can tell them apart.
        match action {
            "DNS lookup" => "DNS lookup blocked — untrusted content was ingested this session (possible prompt injection); outbound requests are held. Verify intent, then `sir unlock`.",
            _ => "External network egress blocked — untrusted content was ingested this session (possible prompt injection); outbound requests are held. Verify intent, then `sir unlock`.",
        },
        RiskTier::R4,
    )
}

pub(super) fn evaluate_untrusted_publish_guardrails(
    req: &EvalRequest,
    verb: Verb,
) -> Option<PolicyResult> {
    if !(req.session_untrusted_read || req.session_untrusted_this_turn) {
        return None;
    }
    match verb {
        Verb::PushRemote => Some(policy_result(
            Verdict::Deny,
            "Code-host publish blocked — untrusted content was ingested this session (possible prompt injection); outbound publish is held. Verify intent, then `sir unlock`.",
            RiskTier::R4,
        )),
        Verb::PushOrigin => Some(policy_result(
            Verdict::Ask,
            "Code-host publish after untrusted content requires approval. Verify intent, then `sir unlock`.",
            RiskTier::R3,
        )),
        _ => None,
    }
}

pub(super) fn evaluate_network_guardrails(
    req: &EvalRequest,
    lease: &Lease,
    verb: Verb,
) -> Option<PolicyResult> {
    match verb {
        Verb::DnsLookup => {
            if req.session_secret {
                Some(policy_result(
                    Verdict::Deny,
                    "DNS lookup blocked — your session contains credentials.",
                    RiskTier::R4,
                ))
            } else if lease.is_verb_forbidden(verb) {
                Some(policy_result(
                    Verdict::Deny,
                    "DNS lookup (outbound request) not allowed by your security policy.",
                    RiskTier::R4,
                ))
            } else if req.session_untrusted_read || req.session_untrusted_this_turn {
                Some(untrusted_egress_deny("DNS lookup"))
            } else {
                // NET-2: on a clean session (no secret in context) an outbound
                // DNS lookup is an approval prompt, not a hard block — there is
                // no exfil to prevent, only friction. The secret-session and
                // forbidden (strict/managed) cases above still Deny.
                Some(policy_result(
                    Verdict::Ask,
                    "DNS lookup (outbound request) requires approval.",
                    RiskTier::R3,
                ))
            }
        }
        Verb::NetExternal => {
            if req.session_secret {
                Some(policy_result(
                    Verdict::Deny,
                    "Network requests blocked — your session contains credentials.",
                    RiskTier::R4,
                ))
            } else if lease.is_verb_forbidden(verb) {
                Some(policy_result(
                    Verdict::Deny,
                    "Network requests to external hosts are blocked by your security policy.",
                    RiskTier::R4,
                ))
            } else if req.session_untrusted_read || req.session_untrusted_this_turn {
                Some(untrusted_egress_deny("External network request"))
            } else {
                // NET-1: on a clean session, external egress is an approval
                // prompt, not a hard block. A secret session is still denied
                // here AND independently by evaluate_secret_session_guards
                // (triple-guarded with policy_sinks), so this branch can never
                // widen a secret-session deny — it only removes friction when
                // there is provably no secret to exfiltrate.
                Some(policy_result(
                    Verdict::Ask,
                    "External network request requires approval.",
                    RiskTier::R3,
                ))
            }
        }
        _ => None,
    }
}

pub(super) fn evaluate_secret_session_guards(
    req: &EvalRequest,
    _session: &SessionState,
    verb: Verb,
) -> Option<PolicyResult> {
    if req.session_secret {
        return match verb {
            Verb::NetExternal => Some(policy_result(
                Verdict::Deny,
                "session carries secret data; external network egress blocked",
                RiskTier::R4,
            )),
            Verb::PushOrigin => Some(policy_result(
                Verdict::Ask,
                "Git push to approved remote while session contains credentials.",
                RiskTier::R3,
            )),
            Verb::PushRemote => Some(policy_result(
                Verdict::Deny,
                "Git push to unapproved remote blocked — your session contains credentials.",
                RiskTier::R4,
            )),
            Verb::NetLocal => Some(policy_result(
                Verdict::Allow,
                "Loopback network access allowed.",
                RiskTier::R0,
            )),
            Verb::NetAllowlisted => Some(policy_result(
                Verdict::Allow,
                "Approved host network access allowed.",
                RiskTier::R1,
            )),
            _ => None,
        };
    }

    // session_was_secret push re-prompt moved to the policy provider layer.
    //
    // The was-secret re-prompt (ask on push when session ever held credentials)
    // is now advisory: the native policy pack emits a verdict of "ask" which
    // compose_policy_verdicts() escalates from allow → ask. This lets developers
    // configure the was-secret rule per-project via `sir provider configure
    // sir-policy-pack --set was-secret-push=warn` without weakening the live-
    // credential floor above.
    //
    // The live-credential floors (session_secret=true) remain hardcoded above as
    // safety floors because they cannot be advisory: a session actively holding
    // credentials must not push externally without explicit human approval, and
    // that invariant must not be configurable away.

    None
}

pub(super) fn evaluate_delegation_guardrails(
    req: &EvalRequest,
    lease: &Lease,
    session: &SessionState,
    verb: Verb,
) -> Option<PolicyResult> {
    if !matches!(verb, Verb::Delegate) {
        return None;
    }
    if req.session_secret {
        return Some(policy_result(
            Verdict::Deny,
            "Delegation blocked — your session contains credentials.",
            RiskTier::R4,
        ));
    }
    if session.recently_read_untrusted {
        return Some(policy_result(
            Verdict::Ask,
            "Delegation after untrusted content was read.",
            RiskTier::R3,
        ));
    }
    if !lease.is_verb_allowed(verb) && !lease.is_verb_ask(verb) && !lease.is_verb_forbidden(verb) {
        return Some(policy_result(
            Verdict::Ask,
            "Agent delegation requires approval.",
            RiskTier::R3,
        ));
    }
    None
}
