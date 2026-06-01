#!/usr/bin/env python3
"""
Policy provider — emits advisory policy verdicts from built-in rules.

Policy providers produce verdicts (allow/ask/deny) but NEVER make the final
decision. The decision composer (Rust sir-core) owns final decisions.

Wire format (sir.policy_request.v0) — received on stdin:
  {
    "op": "evaluate",
    "schema_version": "sir.policy_request.v0",
    "action": "push_origin",          # verb (push_origin, push_remote, net_external, ...)
    "target": "origin",               # target of the action
    "resolved_actor": "ai_coding_agent",  # attribution
    "taint": ["credential_access"],   # prior-session taint labels
    "enforceability": "enforces",     # enforces | detects | blind
    "mode": "hook_gate"               # operating mode
  }

Response (sir.policy_verdict.v0) — written to stdout:
  {
    "schema_version": "sir.policy_verdict.v0",
    "provider": "sir-policy-pack",
    "verdict": "ask",
    "rules_matched": ["was-secret-push-origin"],
    "is_authoritative": false
  }

is_authoritative is always false — this provider is advisory only.

Per-rule behaviour can be tuned via the registry without editing this file:
  sir provider configure sir-policy-pack --set was-secret-push-origin=warn
  sir provider configure sir-policy-pack --set was-secret-push-origin=ask   (default)
  sir provider configure sir-policy-pack --set was-secret-push-origin=allow (suppress)
"""
import os
import sys
import json

PROVIDER_NAME = "sir-policy-pack"
PROVIDER_VERSION = "0.2.0"


def load_provider_config() -> dict:
    """Load this provider's config from ~/.sir/providers.json."""
    try:
        home = os.path.expanduser("~")
        registry_path = os.path.join(home, ".sir", "providers.json")
        with open(registry_path) as f:
            registry = json.load(f)
        for entry in registry.get("providers", []):
            if entry.get("name") == PROVIDER_NAME:
                return entry.get("config") or {}
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return {}


# Load config once at startup (provider is short-lived, one evaluation per spawn).
_CONFIG = load_provider_config()


def caps():
    return {
        "schema_version": "sir.capabilities.v0",
        "provider": PROVIDER_NAME,
        "kind": "policy_provider",
        "capabilities": {
            "verdict_types": ["allow", "ask", "deny"],
            "is_advisory": True,
            "schema_version_supported": "sir.policy_request.v0",
            "note": "Advisory only — decision composer makes the final call",
        },
    }


# Rules evaluated in order. First "deny" wins; first "ask" is noted but
# evaluation continues (a later deny still wins). "allow" is the default.
#
# Each rule: id, match(event)->bool, verdict, reason.
RULES = [
    # ── Credential protection ─────────────────────────────────────────────────
    {
        "id": "deny-agent-credential-read",
        "match": lambda e: (
            e.get("resolved_actor") == "ai_coding_agent"
            and "credential_access" in e.get("taint", [])
            and e.get("action") in ("read_ref",)
        ),
        "verdict": "deny",
        "reason": "AI agents cannot read raw credential files directly",
    },
    # ── Was-secret push rules (moved from hardcoded Rust oracle) ──────────────
    # These rules fire when the session previously held credentials
    # (credential_access in taint) and the agent attempts a push.
    #
    # Configurable per-project:
    #   ask   (default) — interactive re-approval prompt
    #   allow           — suppress entirely (trust the developer)
    #   warn            — alias for allow; allow but note in reason
    {
        "id": "was-secret-push-origin",
        "match": lambda e: (
            "credential_access" in e.get("taint", [])
            and e.get("action") == "push_origin"
            and _CONFIG.get("was-secret-push-origin", "ask") not in ("allow", "warn")
        ),
        "verdict": "ask",
        "reason": "Session previously held credentials; re-approve push to origin (taint persists across turns)",
    },
    {
        "id": "was-secret-push-remote",
        "match": lambda e: (
            "credential_access" in e.get("taint", [])
            and e.get("action") == "push_remote"
            and _CONFIG.get("was-secret-push-remote", "ask") not in ("allow", "warn")
        ),
        "verdict": "ask",
        "reason": "Session previously held credentials; re-approve push to unapproved remote",
    },
    # ── External egress ───────────────────────────────────────────────────────
    {
        "id": "ask-external-egress",
        "match": lambda e: e.get("action") in ("net_external", "dns_lookup"),
        "verdict": "ask",
        "reason": "Ask before new external network egress",
    },
    # ── SIR integrity ─────────────────────────────────────────────────────────
    {
        "id": "deny-sir-config-tamper",
        "match": lambda e: e.get("action") == "sir_config_tamper",
        "verdict": "deny",
        "reason": "Block SIR self-modification attempts",
    },
]


def evaluate(event: dict) -> dict:
    """Evaluate the event against all rules and return a policy verdict."""
    matched_rules = []
    verdict = "allow"

    for rule in RULES:
        if rule["match"](event):
            matched_rules.append(rule["id"])
            if rule["verdict"] == "deny":
                verdict = "deny"
                break
            elif verdict != "deny" and rule["verdict"] == "ask":
                verdict = "ask"
                # Continue — a later deny still wins.

    return {
        "schema_version": "sir.policy_verdict.v0",
        "provider": PROVIDER_NAME,
        "verdict": verdict,
        "rules_matched": matched_rules,
        "is_advisory": True,
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("op") == "capabilities":
            print(json.dumps(caps()), flush=True)
            continue

        result = evaluate(event)
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
