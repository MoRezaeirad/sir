# SIR policy for OPA bridge.
#
# The full sir.policy_request.v0 is available as `input`.
# Fields: input.action, input.target, input.resolved_actor,
#         input.attribution_confidence, input.taint, input.enforceability, input.mode
#
# Return object: { verdict, rules_matched, reason }
#   verdict:       "allow" | "ask" | "deny"
#   rules_matched: list of rule IDs that fired (shown in sir log / sir why)
#   reason:        human-readable explanation
#
# IMPORTANT: This policy is advisory. The SIR Rust oracle applies native
# safety floors (secret session + external egress = deny) regardless of what
# this policy returns. Advisory verdicts can only escalate allow → ask.

package sir.policy

import rego.v1

# Default: allow everything not explicitly covered.
default verdict := "allow"
default rules_matched := []
default reason := ""

# ── Was-secret push rules ─────────────────────────────────────────────────────

verdict := "ask" if {
    "credential_access" in input.taint
    input.action == "push_origin"
}

rules_matched := ["was-secret-push-origin"] if {
    "credential_access" in input.taint
    input.action == "push_origin"
}

reason := "Session previously held credentials; re-approve push to origin." if {
    "credential_access" in input.taint
    input.action == "push_origin"
}

verdict := "ask" if {
    "credential_access" in input.taint
    input.action == "push_remote"
}

rules_matched := ["was-secret-push-remote"] if {
    "credential_access" in input.taint
    input.action == "push_remote"
}

# ── AI agent credential read ──────────────────────────────────────────────────

verdict := "deny" if {
    input.resolved_actor == "ai_coding_agent"
    input.action == "read_ref"
    is_credential_path(input.target)
}

rules_matched := ["deny-agent-credential-read"] if {
    input.resolved_actor == "ai_coding_agent"
    input.action == "read_ref"
    is_credential_path(input.target)
}

reason := "AI agents cannot read raw credential files." if {
    input.resolved_actor == "ai_coding_agent"
    input.action == "read_ref"
    is_credential_path(input.target)
}

# ── Helpers ───────────────────────────────────────────────────────────────────

credential_patterns := [".env", ".aws", ".ssh", "credentials", "id_rsa", ".pem", "secrets"]

is_credential_path(path) if {
    some pattern in credential_patterns
    contains(lower(path), pattern)
}

lower(s) := x if {
    x := lower_builtin(s)
}

lower_builtin(s) := y if {
    y := s
}
