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

    // High-water mark (monotonic secret taint). The turn-scoped `session_secret`
    // deny floor clears on a turn boundary (instantly on the next user message),
    // but a session that *ever* held secret data must not silently revert to the
    // clean-session baseline — a secret laundered through model context can be
    // re-emitted as agent-authored bytes a turn later. So a push from a
    // was-secret session re-prompts (ask) instead of being silently allowed.
    //
    // This only ever TIGHTENS (allow -> ask); it never widens a deny:
    //   - net_external / dns_lookup are already forced to >= ask earlier by
    //     evaluate_network_guardrails (and to deny under a forbidding lease),
    //     so they never reach this branch — no need to re-handle them here.
    //   - a lease that forbids push is decided by the forbidden-verb check that
    //     runs before this guard, so the deny stands.
    // The explicit, logged way to clear the high-water mark is `sir unlock`.
    if req.session_was_secret {
        return match verb {
            Verb::PushOrigin | Verb::PushRemote => Some(policy_result(
                Verdict::Ask,
                "session previously held secret data this session; re-approve this push (taint persists across turns)",
                RiskTier::R3,
            )),
            _ => None,
        };
    }

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
