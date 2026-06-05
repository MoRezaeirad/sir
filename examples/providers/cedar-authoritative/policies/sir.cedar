// SIR authoritative policy (Cedar).
//
// Mirrors examples/providers/opa-authoritative/policy/sir.rego in Cedar's
// principal/action/resource/context model:
//   principal = SIR::Actor::"ai_coding_agent" | "human_developer" | "unknown"
//   action    = SIR::Action::"read_ref" | "net_external" | "run_ephemeral" | ...
//   resource  = SIR::Target::"<path|url|command|server>"
//   context   = { taint:[String], session_secret, session_was_secret,
//                 session_untrusted_read, session_untrusted_this_turn,
//                 target_is_credential, target_lower, ... }
//
// Cedar has only permit/forbid. The bridge maps a FORBID whose @id starts with
// "ask:" to SIR's "ask" verdict; any other forbid → "deny"; permit → "allow".
// Cedar's "any forbid overrides any permit" gives most-restrictive for free, and
// the bridge prefers a real deny over an ask when both match.

// ─────────────────────────────────────────────────────────────────────────────
// Default: permit. (Demo policy is permissive-by-default; a production policy for
// egress would invert this to default-deny. Documented as a policy-author choice.)
// ─────────────────────────────────────────────────────────────────────────────
@id("default-permit")
permit (principal, action, resource);

// ═══ C. RE-IMPLEMENTED INTEGRITY FLOORS (authoritative mode = our job) ════════

// C1. Confidentiality wall: a live secret in context must not reach an external
// sink. (Forbid out-ranks the default permit.)
@id("floor-secret-egress")
forbid (
    principal,
    action in [SIR::Action::"net_external", SIR::Action::"dns_lookup", SIR::Action::"push_remote"],
    resource
)
when { context has session_secret && context.session_secret };

// C2. Integrity wall (lethal-trifecta exfil leg): untrusted content ingested →
// hold outbound egress.
@id("floor-untrusted-egress")
forbid (
    principal,
    action in [SIR::Action::"net_external", SIR::Action::"dns_lookup", SIR::Action::"push_remote"],
    resource
)
when { (context has session_untrusted_read && context.session_untrusted_read) || (context has session_untrusted_this_turn && context.session_untrusted_this_turn) };

// C3. High-water mark: a session that EVER held a secret re-prompts on push.
// This is an ASK (the "ask:" prefix tells the bridge).
@id("ask:floor-was-secret-push")
forbid (
    principal,
    action in [SIR::Action::"push_origin", SIR::Action::"push_remote"],
    resource
)
when { context has session_was_secret && context.session_was_secret };

// ═══ B. RESTRICT — org rules native does not enforce ═════════════════════════

// B0. Privilege escalation / persistence are always at least an ask. Under
// authoritative mode the native sudo/persistence asks no longer run, so the
// policy must re-assert them — otherwise the default permit would GRANT sudo.
@id("ask:privileged")
forbid (
    principal,
    action in [SIR::Action::"sudo", SIR::Action::"persistence"],
    resource
);

// B1. AI agents may not read raw credential files.
@id("deny-agent-credential-read")
forbid (
    principal == SIR::Actor::"ai_coding_agent",
    action == SIR::Action::"read_ref",
    resource
)
when { context has target_is_credential && context.target_is_credential };

// B2. No delegation to subagents while untrusted content is in play.
@id("deny-delegate-after-untrusted")
forbid (
    principal,
    action == SIR::Action::"delegate",
    resource
)
when { (context has session_untrusted_read && context.session_untrusted_read) || (context has session_untrusted_this_turn && context.session_untrusted_this_turn) };

// B4. sir self-modification is always at least an ask (defense in depth on top of
// SIR's own non-delegable sir-self floor).
@id("ask:sir-self")
forbid (
    principal,
    action == SIR::Action::"sir_self",
    resource
);

// B5. Detected MCP credential leak / injection are hard denies.
@id("deny-mcp-credential-leak")
forbid (principal, action == SIR::Action::"mcp_credential_leak", resource);

@id("deny-mcp-injection")
forbid (principal, action == SIR::Action::"mcp_injection_detected", resource);

// NOTE on B3 (denylisted skills): Cedar's CLI string ops can't substring-match a
// free-form target, so skill-denylisting is done in the bridge-provided
// `target_lower` context field via a forbid below. We forbid when the target
// contains a denylisted skill name. (Cedar `like` supports wildcard match.)
@id("deny-denylisted-skill")
forbid (
    principal,
    action in [SIR::Action::"delegate", SIR::Action::"run_ephemeral", SIR::Action::"execute_dry_run"],
    resource
)
when {
    context has target_lower && (
        context.target_lower like "*data-exfil*" ||
        context.target_lower like "*shell-runner*" ||
        context.target_lower like "*auto-deploy*"
    )
};

// ═══ A. GRANT — remove friction native imposes (the point of PDP) ════════════
// Grants are PERMITs; they only matter where they would otherwise be gated. They
// are still overridden by any forbid above (most-restrictive), so a grant can
// never punch through a floor. These are documentary — the default-permit above
// already allows them; explicit ids make `--verbose` show the intent.

@id("grant-ephemeral-clean")
permit (
    principal,
    action == SIR::Action::"run_ephemeral",
    resource
)
when { !(context has session_secret && context.session_secret) && !(context has session_untrusted_read && context.session_untrusted_read) && !(context has session_untrusted_this_turn && context.session_untrusted_this_turn) };

@id("grant-mcp-network")
permit (
    principal,
    action == SIR::Action::"mcp_network_unapproved",
    resource
)
when { !(context has session_secret && context.session_secret) && !(context has session_untrusted_read && context.session_untrusted_read) && !(context has session_untrusted_this_turn && context.session_untrusted_this_turn) };
