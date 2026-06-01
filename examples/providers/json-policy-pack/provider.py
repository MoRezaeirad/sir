#!/usr/bin/env python3
"""
JSON policy pack provider for SIR — zero dependencies.

Reads policy rules from a sibling ``rules.json`` and emits advisory
sir.policy_verdict.v0 responses. JSON is in the Python standard library, so
this provider has no external dependencies and is a friendly starting point for
users who do not want to install OPA or Cedar.

How it works:
  1. SIR sends a sir.policy_request.v0 to this provider's stdin.
  2. This provider matches the request against each rule in rules.json.
  3. The first matching DENY wins; otherwise the first matching ASK wins;
     otherwise the request is allowed (no verdict emitted).

rules.json format:

  {
    "rules": [
      {
        "id": "was-secret-push-origin",
        "match": { "action": "push_origin", "taint": "credential_access" },
        "verdict": "ask",
        "reason": "session held credentials; re-approve push to origin"
      }
    ]
  }

Each rule has:
  id       — rule identifier (shown in `sir log` / `sir why`)
  match    — object of conditions, all of which must hold:
               action  → request.action must equal this value
               taint   → this label must be present in request.taint
               actor   → request.resolved_actor must equal this value
             (omit a key to skip that check; an empty match object matches all)
  verdict  — allow | ask | deny
  reason   — human-readable explanation

Quick start:
  sir provider install ./examples/providers/json-policy-pack/provider.yaml
  sir provider use json-policy-pack
  $EDITOR ./examples/providers/json-policy-pack/rules.json
"""
import json
import os
import sys

import sir_sdk

PROVIDER_NAME = "json-policy-pack"
PROVIDER_VERSION = "0.1.0"

# Rules file — override with RULES_FILE env var.
RULES_FILE = os.environ.get(
    "RULES_FILE",
    os.path.join(os.path.dirname(__file__), "rules.json"),
)


def load_rules() -> list:
    try:
        with open(RULES_FILE) as f:
            data = json.load(f)
    except OSError as exc:
        print(f"[json-policy-pack] WARNING: cannot read {RULES_FILE}: {exc}",
              file=sys.stderr)
        return []
    except json.JSONDecodeError as exc:
        print(f"[json-policy-pack] WARNING: {RULES_FILE} is not valid JSON: {exc}",
              file=sys.stderr)
        return []
    rules = data.get("rules", [])
    return rules if isinstance(rules, list) else []


# Rules load once at startup (provider is short-lived).
_RULES = load_rules()


def caps():
    return sir_sdk.capabilities(PROVIDER_NAME, sir_sdk.KIND_POLICY, {
        "verdict_types": [sir_sdk.VERDICT_ALLOW, sir_sdk.VERDICT_ASK, sir_sdk.VERDICT_DENY],
        "is_advisory": True,
        "policy_engine": "json-policy-pack",
        "policy_file": RULES_FILE,
    })


def rule_matches(rule: dict, request: dict) -> bool:
    """A rule matches when every condition in its `match` object holds."""
    match = rule.get("match", {})
    if not isinstance(match, dict):
        return False

    want_action = match.get("action")
    if want_action and request.get("action") != want_action:
        return False

    want_taint = match.get("taint")
    if want_taint and want_taint not in request.get("taint", []):
        return False

    want_actor = match.get("actor")
    if want_actor and request.get("resolved_actor") != want_actor:
        return False

    return True


def evaluate(request: dict):
    """Evaluate the request against rules.json. First deny wins, else first ask."""
    verdict = sir_sdk.VERDICT_ALLOW
    matched = []
    reason = ""

    for rule in _RULES:
        if not isinstance(rule, dict) or not rule_matches(rule, request):
            continue
        rule_verdict = rule.get("verdict", sir_sdk.VERDICT_ALLOW)
        matched.append(rule.get("id", "unnamed-rule"))
        if rule_verdict == sir_sdk.VERDICT_DENY:
            verdict = sir_sdk.VERDICT_DENY
            reason = rule.get("reason", "")
            break
        if rule_verdict == sir_sdk.VERDICT_ASK and verdict != sir_sdk.VERDICT_DENY:
            if verdict != sir_sdk.VERDICT_ASK:
                verdict = sir_sdk.VERDICT_ASK
                reason = rule.get("reason", "")

    if verdict == sir_sdk.VERDICT_ALLOW:
        return None  # allow — emit no verdict

    return sir_sdk.policy_verdict(PROVIDER_NAME, verdict, rules_matched=matched, reason=reason)


sir_sdk.run_policy_provider(caps, evaluate)
