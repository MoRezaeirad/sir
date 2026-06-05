# SIR authoritative policy (OPA / Rego).
#
# Wired as an AUTHORITATIVE policy_provider, this policy's verdict REPLACES SIR's
# native decision — it can GRANT actions the native engine would gate, and it can
# RESTRICT actions the native engine would allow. When SIR is configured this way,
# the native integrity floors do NOT run automatically: "policy is the whole
# truth." So this file both (a) uses that power to remove friction and add
# org-specific rules, and (b) RE-IMPLEMENTS the exfiltration wall, because under
# authoritative mode it is this policy's job to keep it.
#
# Input is a sir.policy_request (v0 fields + v1 session/integrity signals):
#   input.action                       — verb, e.g. "run_ephemeral", "delegate",
#                                         "mcp_network_unapproved", "net_external"
#   input.target                       — path / URL / command / MCP server name
#   input.resolved_actor               — "ai_coding_agent" | "human_developer" | "unknown"
#   input.taint                        — ["credential_access","untrusted_content","mcp_injection"]
#   input.session_secret               — live secret in context (v1)
#   input.session_was_secret           — session ever held a secret (v1, high-water)
#   input.session_untrusted_read       — untrusted content ingested this session (v1)
#   input.session_untrusted_this_turn  — untrusted content this turn (v1)
#
# Output: data.sir.policy = { verdict, rules_matched, reason }
#   verdict ∈ {"allow","ask","deny"}.  Most-restrictive wins if several fire.
package sir.policy

import rego.v1

# ── Result assembly ──────────────────────────────────────────────────────────
# Collect every rule that fires, then reduce to the most restrictive verdict so a
# permissive rule can never accidentally override a deny. This mirrors SIR's own
# most-restrictive reduction for authoritative providers.

default decision := {"verdict": "allow", "rules_matched": [], "reason": ""}

decision := out if {
	count(fired) > 0
	v := most_restrictive([f.verdict | some f in fired])
	matched := [f.rule | some f in fired]

	# Prefer the reason of a rule whose verdict equals the final verdict.
	reasons := [f.reason | some f in fired; f.verdict == v]
	out := {"verdict": v, "rules_matched": matched, "reason": concat(" ", reasons)}
}

# The SDK bridge reads {verdict, rules_matched, reason} at data.sir.policy.
verdict := decision.verdict
rules_matched := decision.rules_matched
reason := decision.reason

rank := {"allow": 0, "ask": 1, "deny": 2}

most_restrictive(vs) := v if {
	v := vs[i]
	every other in vs {
		rank[v] >= rank[other]
	}
}

# ═══════════════════════════════════════════════════════════════════════════════
# A. GRANT — remove friction the native engine imposes (the whole point of PDP)
# ═══════════════════════════════════════════════════════════════════════════════

# A1. Trusted team can run npx/ephemeral packages without a prompt. Native asks
# on every `run_ephemeral`; here we grant it on a clean session.
fired contains {
	"rule": "grant-ephemeral-clean",
	"verdict": "allow",
	"reason": "npx/ephemeral exec allowed for this project on a clean session (org policy).",
} if {
	input.action == "run_ephemeral"
	clean_session
}

# A2. Allow an approved MCP server to make network calls to argument URLs without
# a prompt on a clean session. Native asks (mcp_network_unapproved); we grant.
fired contains {
	"rule": "grant-mcp-network",
	"verdict": "allow",
	"reason": "MCP argument-host network allowed on a clean session (org policy).",
} if {
	input.action == "mcp_network_unapproved"
	clean_session
}

# A3. Allow external egress to org-approved hosts even though native would ask —
# but ONLY on a clean session (the integrity wall in section C still applies).
#
# SECURITY: match the parsed HOST, never a substring of the raw URL target. Rego
# is not a URL parser, and substring matching is bypassable — e.g.
# "https://api.github.com.evil.example/" or "https://evil.example/?u=https://api.github.com"
# both contain an approved host as a substring yet must NOT be granted. The bridge
# (provider.py) parses the authority with the stdlib urllib.parse and passes it as
# the trusted `input.target_host`; the policy just does an exact / true-subdomain
# comparison on that field. (See provider.py:enrich — parse hosts where there is a
# real parser, match them where there is a real matcher.)
approved_egress_hosts := {"api.github.com", "registry.npmjs.org", "pypi.org"}

fired contains {
	"rule": "grant-approved-egress",
	"verdict": "allow",
	"reason": "External egress to an org-approved host on a clean session.",
} if {
	input.action == "net_external"
	clean_session
	host_is_approved(input.target_host)
}

# host_is_approved is true when the parsed host equals an approved host exactly,
# or is a true subdomain of one (e.g. "objects.pypi.org" for "pypi.org"). The
# leading-dot check is what stops "api.github.com.evil.example" from matching.
host_is_approved(host) if host in approved_egress_hosts

host_is_approved(host) if {
	some approved in approved_egress_hosts
	endswith(host, concat("", [".", approved]))
}

# ═══════════════════════════════════════════════════════════════════════════════
# B. RESTRICT — org-specific rules native does not enforce (agents/skills/hooks)
# ═══════════════════════════════════════════════════════════════════════════════

# B0. Privilege escalation / persistence are always at least an ask. Under
# authoritative mode the native sudo/persistence asks no longer run, so the
# policy must re-assert them — otherwise the permissive default would GRANT sudo.
fired contains {
	"rule": "ask-privileged",
	"verdict": "ask",
	"reason": "Elevated-privilege or persistence action requires approval.",
} if {
	input.action in {"sudo", "persistence"}
}

# B1. AI agents may not read raw credential files (deny, not ask).
fired contains {
	"rule": "deny-agent-credential-read",
	"verdict": "deny",
	"reason": "AI agents may not read raw credential files — use a secret manager.",
} if {
	input.action == "read_ref"
	input.resolved_actor == "ai_coding_agent"
	is_credential_path(input.target)
}

# B2. No delegation to subagents while untrusted content is in play (prompt-
# injection containment for the agent-spawns-agent path).
fired contains {
	"rule": "deny-delegate-after-untrusted",
	"verdict": "deny",
	"reason": "Delegation to a subagent is blocked after untrusted content was ingested (injection containment).",
} if {
	input.action == "delegate"
	untrusted_ingested
}

# B3. Block a denylisted skill outright (skills run as the agent; treat an
# unreviewed skill as code execution). Skills surface as a delegate/exec verb
# with the skill name in the target.
denylisted_skills := {"shell-runner", "data-exfil", "auto-deploy"}

fired contains {
	"rule": "deny-denylisted-skill",
	"verdict": "deny",
	"reason": sprintf("Skill %q is not approved for this project.", [input.target]),
} if {
	input.action in {"delegate", "run_ephemeral", "execute_dry_run"}
	some skill in denylisted_skills
	contains(lower(input.target), skill)
}

# B4. sir self-modification is always at least an ask — defense in depth on top of
# SIR's own non-delegable sir-self floor (which an authoritative provider cannot
# override anyway, but we make the org stance explicit).
fired contains {
	"rule": "ask-sir-self",
	"verdict": "ask",
	"reason": "Modifying sir's own configuration requires explicit human approval.",
} if {
	input.action == "sir_self"
}

# B5. Detected MCP credential leak / injection are hard denies regardless.
fired contains {
	"rule": "deny-mcp-credential-leak",
	"verdict": "deny",
	"reason": "Credential pattern detected in MCP tool arguments.",
} if {
	input.action == "mcp_credential_leak"
}

fired contains {
	"rule": "deny-mcp-injection",
	"verdict": "deny",
	"reason": "Prompt-injection content detected from an MCP server.",
} if {
	input.action == "mcp_injection_detected"
}

# ═══════════════════════════════════════════════════════════════════════════════
# C. RE-IMPLEMENT the integrity floors (authoritative mode = floors are OUR job)
# ═══════════════════════════════════════════════════════════════════════════════

# C1. Confidentiality wall: a live secret in context must not flow to an external
# sink. Native enforces this as a floor; under authoritative mode WE must.
egress_actions := {"net_external", "dns_lookup", "push_remote"}

fired contains {
	"rule": "floor-secret-egress",
	"verdict": "deny",
	"reason": "A credential is in context — external egress is blocked (exfiltration wall).",
} if {
	input.action in egress_actions
	input.session_secret
}

# C2. Integrity wall (the lethal-trifecta exfil leg): untrusted content was
# ingested this session, so outbound egress is held — an injected instruction
# must not be able to drive data out.
fired contains {
	"rule": "floor-untrusted-egress",
	"verdict": "deny",
	"reason": "Untrusted content was ingested this session — outbound egress is held (prompt-injection exfiltration wall).",
} if {
	input.action in egress_actions
	untrusted_ingested
}

# C3. High-water mark: even after the live secret flag clears on a turn boundary,
# a session that EVER held a secret re-prompts on push (taint is monotonic).
fired contains {
	"rule": "floor-was-secret-push",
	"verdict": "ask",
	"reason": "This session previously held credentials — re-approve the push.",
} if {
	input.action in {"push_origin", "push_remote"}
	input.session_was_secret
}

# ── Helpers ──────────────────────────────────────────────────────────────────

clean_session if {
	not input.session_secret
	not untrusted_ingested
}

untrusted_ingested if input.session_untrusted_read
untrusted_ingested if input.session_untrusted_this_turn
untrusted_ingested if "untrusted_content" in object.get(input, "taint", [])
untrusted_ingested if "mcp_injection" in object.get(input, "taint", [])

credential_patterns := [".env", ".aws", ".ssh", "credentials", "id_rsa", ".pem", "secrets", ".npmrc", ".git-credentials"]

is_credential_path(path) if {
	some pattern in credential_patterns
	contains(lower(path), pattern)
}
