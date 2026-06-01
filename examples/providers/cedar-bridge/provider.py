#!/usr/bin/env python3
"""
Cedar policy bridge for SIR.

Cedar uses a principal/action/resource model. This bridge maps sir.policy_request.v0
fields to Cedar's authorization model and calls `cedar authorize` (or the cedar-agent
HTTP API) to evaluate policies.

Cedar model for SIR:
  Principal  = Actor (SIR::Actor::"ai_coding_agent", SIR::Actor::"human_developer")
  Action     = Verb  (SIR::Action::"push_origin", SIR::Action::"read_ref", ...)
  Resource   = Target (SIR::Target::"origin", SIR::Target::"~/.aws/credentials", ...)
  Context    = { taint, attribution_confidence, enforceability, mode, ... }

Prerequisites:
  - `cedar` CLI on PATH (https://github.com/cedar-policy/cedar)
    OR a cedar-agent HTTP server at CEDAR_AGENT_URL

Quick start:
  sir provider install ./examples/providers/cedar-bridge/provider.yaml
  sir provider use cedar-bridge

Configuration:
  CEDAR_AGENT_URL   — URL of cedar-agent HTTP API (default: use cedar CLI)
  CEDAR_POLICY_DIR  — directory containing *.cedar policy files (default: ./policies)
  CEDAR_SCHEMA_FILE — path to schema.cedarschema (optional but recommended)
"""
import json
import os
import subprocess
import sys
from urllib import request as urllib_request
from urllib.error import URLError

import sir_sdk

PROVIDER_NAME = "cedar-bridge"
PROVIDER_VERSION = "0.1.0"

CEDAR_AGENT_URL = os.environ.get("CEDAR_AGENT_URL", "")
POLICY_DIR = os.environ.get(
    "CEDAR_POLICY_DIR",
    os.path.join(os.path.dirname(__file__), "policies"),
)
SCHEMA_FILE = os.environ.get("CEDAR_SCHEMA_FILE", "")


def caps():
    return sir_sdk.capabilities(PROVIDER_NAME, sir_sdk.KIND_POLICY, {
        "verdict_types": [sir_sdk.VERDICT_ALLOW, sir_sdk.VERDICT_ASK, sir_sdk.VERDICT_DENY],
        "is_advisory": True,
        "policy_engine": "cedar",
        "mode": "agent_api" if CEDAR_AGENT_URL else "cedar_cli",
    })


def evaluate(request: dict):
    """Bridge a sir.policy_request.v0 to Cedar and return a sir.policy_verdict.v0."""
    try:
        if CEDAR_AGENT_URL:
            result = query_cedar_agent(request)
        else:
            result = query_cedar_cli(request)
    except FileNotFoundError:
        print(
            "[cedar-bridge] WARNING: 'cedar' CLI not found and CEDAR_AGENT_URL not set. "
            "Install from https://github.com/cedar-policy/cedar",
            file=sys.stderr,
        )
        return None
    except Exception as exc:
        print(f"[cedar-bridge] ERROR: {exc}", file=sys.stderr)
        return None

    verdict = result.get("verdict", sir_sdk.VERDICT_ALLOW)
    rules   = result.get("rules_matched", [])
    reason  = result.get("reason", "")

    return sir_sdk.policy_verdict(PROVIDER_NAME, verdict, rules_matched=rules, reason=reason)


# ── Cedar CLI path ────────────────────────────────────────────────────────────

def query_cedar_cli(request: dict) -> dict:
    """Evaluate via the `cedar authorize` CLI."""
    principal, action, resource, context = map_to_cedar(request)

    cmd = [
        "cedar", "authorize",
        "--policies", POLICY_DIR,
        "--principal", principal,
        "--action", action,
        "--resource", resource,
        "--context", json.dumps(context),
    ]
    if SCHEMA_FILE:
        cmd += ["--schema", SCHEMA_FILE]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=0.15,
    )

    # Cedar CLI exits 0 for ALLOW, non-zero for DENY.
    if proc.returncode == 0:
        return {"verdict": sir_sdk.VERDICT_ALLOW}

    # Parse the deny reason from stderr/stdout.
    rules = parse_cedar_deny_reasons(proc.stdout + proc.stderr)
    return {
        "verdict": sir_sdk.VERDICT_DENY,
        "rules_matched": rules,
        "reason": "Cedar policy denied the request",
    }


# ── Cedar Agent HTTP path ─────────────────────────────────────────────────────

def query_cedar_agent(request: dict) -> dict:
    """Evaluate via cedar-agent HTTP API."""
    principal, action, resource, context = map_to_cedar(request)

    payload = json.dumps({
        "principal": principal,
        "action": action,
        "resource": resource,
        "context": context,
    }).encode()

    url = CEDAR_AGENT_URL.rstrip("/") + "/v1/is_authorized"
    req = urllib_request.Request(url, data=payload, method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib_request.urlopen(req, timeout=0.15) as resp:
            body = json.loads(resp.read())
    except URLError as e:
        raise RuntimeError(f"cedar-agent unavailable: {e}")

    decision = body.get("decision", "DENY")
    if decision == "ALLOW":
        return {"verdict": sir_sdk.VERDICT_ALLOW}

    reasons = [r.get("id", "") for r in body.get("diagnostics", {}).get("reasons", [])]
    errors  = [e.get("message", "") for e in body.get("diagnostics", {}).get("errors", [])]
    return {
        "verdict": sir_sdk.VERDICT_DENY,
        "rules_matched": [r for r in reasons if r],
        "reason": "; ".join(errors) if errors else "Cedar policy denied the request",
    }


# ── Mapping helpers ───────────────────────────────────────────────────────────

def map_to_cedar(request: dict):
    """Map sir.policy_request.v0 fields to Cedar principal/action/resource/context."""
    actor  = request.get("resolved_actor", "unknown")
    action = request.get("action", "unknown")
    target = request.get("target", "")

    # Cedar entity types are namespaced: SIR::Actor, SIR::Action, SIR::Target
    principal = f'SIR::Actor::"{actor}"'
    cedar_action = f'SIR::Action::"{action}"'
    resource  = f'SIR::Target::"{target}"' if target else 'SIR::Target::"unknown"'

    context = {
        "taint": request.get("taint", []),
        "attribution_confidence": request.get("attribution_confidence", "unknown"),
        "enforceability": request.get("enforceability", ""),
        "mode": request.get("mode", ""),
    }
    return principal, cedar_action, resource, context


def parse_cedar_deny_reasons(output: str) -> list:
    """Extract policy IDs from Cedar CLI deny output."""
    rules = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("policy") or "forbid" in line.lower():
            rules.append(line.split()[0] if line.split() else line)
    return rules or ["cedar-deny"]


sir_sdk.run_policy_provider(caps, evaluate)
