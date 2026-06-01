#!/usr/bin/env python3
"""
Simple YAML policy provider for SIR — zero dependencies.

Reads policy rules from a sibling ``rules.yaml`` and emits advisory
sir.policy_verdict.v0 responses. This is a starting point for users who do not
want to install OPA or Cedar: rules live in a plain, line-based YAML-ish file
that a non-programmer can edit.

How it works:
  1. SIR sends a sir.policy_request.v0 to this provider's stdin.
  2. This provider matches the request against each rule in rules.yaml.
  3. The first matching DENY wins; otherwise the first matching ASK wins;
     otherwise the request is allowed (no verdict emitted).

rules.yaml format (a minimal, flat, hand-parsed subset — NOT full YAML):

  - id: was-secret-push-origin
    action: push_origin
    taint: credential_access
    verdict: ask
    reason: session held credentials; re-approve push to origin

  - id: ask-external-egress
    action: net_external
    verdict: ask
    reason: ask before new external network egress

Each rule is a list item ("- id: ...") followed by ``key: value`` lines.
Supported keys:
  id       — rule identifier (shown in `sir log` / `sir why`)
  action   — match request.action exactly (omit to match any action)
  taint    — require this label in request.taint (omit to skip taint check)
  verdict  — allow | ask | deny
  reason   — human-readable explanation

No pyyaml — the parser below handles exactly this flat shape and nothing more.

Quick start:
  sir provider install ./examples/providers/simple-yaml-policy/provider.yaml
  sir provider use simple-yaml-policy
  $EDITOR ./examples/providers/simple-yaml-policy/rules.yaml
"""
import os
import sys

import sir_sdk

PROVIDER_NAME = "simple-yaml-policy"
PROVIDER_VERSION = "0.1.0"

# Rules file — override with RULES_FILE env var.
RULES_FILE = os.environ.get(
    "RULES_FILE",
    os.path.join(os.path.dirname(__file__), "rules.yaml"),
)


def parse_rules(text: str) -> list:
    """Parse the minimal flat YAML rule format. No external dependencies.

    Recognizes list items introduced by ``- key: value`` and subsequent
    ``key: value`` lines belonging to the same item. Blank lines and lines
    starting with ``#`` are ignored. Quotes around values are stripped.
    """
    rules = []
    current = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- "):
            # Start of a new rule; the remainder is its first key: value.
            if current is not None:
                rules.append(current)
            current = {}
            stripped = stripped[2:].strip()

        if current is None:
            # Content before any list item — ignore.
            continue

        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip()
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        if key:
            current[key] = value

    if current is not None:
        rules.append(current)
    return rules


def load_rules() -> list:
    try:
        with open(RULES_FILE) as f:
            return parse_rules(f.read())
    except OSError as exc:
        print(f"[simple-yaml-policy] WARNING: cannot read {RULES_FILE}: {exc}",
              file=sys.stderr)
        return []


# Rules load once at startup (provider is short-lived).
_RULES = load_rules()


def caps():
    return sir_sdk.capabilities(PROVIDER_NAME, sir_sdk.KIND_POLICY, {
        "verdict_types": [sir_sdk.VERDICT_ALLOW, sir_sdk.VERDICT_ASK, sir_sdk.VERDICT_DENY],
        "is_advisory": True,
        "policy_engine": "simple-yaml",
        "policy_file": RULES_FILE,
    })


def rule_matches(rule: dict, request: dict) -> bool:
    """A rule matches when its action (if set) and taint (if set) match."""
    want_action = rule.get("action")
    if want_action and request.get("action") != want_action:
        return False
    want_taint = rule.get("taint")
    if want_taint and want_taint not in request.get("taint", []):
        return False
    return True


def evaluate(request: dict):
    """Evaluate the request against rules.yaml. First deny wins, else first ask."""
    verdict = sir_sdk.VERDICT_ALLOW
    matched = []
    reason = ""

    for rule in _RULES:
        if not rule_matches(rule, request):
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
