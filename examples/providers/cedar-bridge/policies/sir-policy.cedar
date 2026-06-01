// SIR Cedar policy.
//
// Cedar maps: Principal = Actor, Action = SIR verb, Resource = target
// Context fields: taint (list), attribution_confidence, enforceability, mode
//
// IMPORTANT: This policy is advisory. SIR's Rust oracle applies native safety
// floors regardless of what Cedar returns. Cedar can only advise ask or deny;
// the Rust composer can still allow if advisory verdicts don't meet the floor.

// Deny AI agent reads of credential files.
forbid (
    principal == SIR::Actor::"ai_coding_agent",
    action == SIR::Action::"read_ref",
    resource
)
when {
    resource has credentials || resource has aws || resource has env
};

// Deny network egress when session held credentials.
forbid (
    principal,
    action == SIR::Action::"net_external",
    resource
)
when {
    context.taint.contains("credential_access")
};

// Deny push to unapproved remote when session held credentials.
forbid (
    principal,
    action == SIR::Action::"push_remote",
    resource
)
when {
    context.taint.contains("credential_access")
};

// Permit all other actions (SIR native floors still apply).
permit (
    principal,
    action,
    resource
);
