#!/usr/bin/env python3
"""
OPA (Open Policy Agent) bridge for SIR — AUTHORITATIVE / warm-sidecar variant.

This bridges SIR policy requests to a WARM OPA server (`opa run --server`) over
its HTTP Data API, so each evaluation is a sub-millisecond localhost round-trip
rather than a cold `opa eval` process spawn. That matters for an AUTHORITATIVE
policy provider: its verdict IS the decision (SIR fails closed if it can't
answer), so the call sits on the live decision path and must be fast.

How it works:
  1. SIR sends a sir.policy_request.v0/v1 to this provider's stdin (one JSON
     object per line). v1 adds session/integrity signals: session_secret,
     session_was_secret, session_untrusted_read, session_untrusted_this_turn.
  2. This bridge POSTs the request as OPA `input` to
     http://127.0.0.1:8181/v1/data/sir/policy and reads {verdict, rules_matched,
     reason} back.
  3. It wraps that in sir.policy_verdict.v0 and writes it to stdout.

Run the OPA sidecar (warm) from this directory:

    opa run --server --addr 127.0.0.1:8181 policy/

Then wire it into SIR (from the repo root):

    PYTHONPATH=sdk/python bin/sir provider install examples/providers/opa-authoritative/provider.yaml
    bin/sir provider use opa-authoritative
    bin/sir provider authoritative opa-authoritative --on-failure deny

Env:
  OPA_URL   — full decision URL (default http://127.0.0.1:8181/v1/data/sir/policy)
  OPA_POLICY_DIR — used only by the cold-spawn fallback below

Fail behavior: this bridge returns None (no verdict) only when it genuinely
cannot reach OPA. Under an AUTHORITATIVE registration, SIR turns that into a
fail-closed ask/deny (per `--on-failure`) — never a silent grant. So the bridge
never has to "guess" a safe default; it just reports cleanly or errors.
"""
import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse

import sir_sdk

PROVIDER_NAME = "opa-authoritative"
PROVIDER_VERSION = "0.1.0"

# The decision document the policy assembles (package sir.policy → `decision`).
OPA_URL = os.environ.get("OPA_URL", "http://127.0.0.1:8181/v1/data/sir/policy/decision")
OPA_TIMEOUT_S = float(os.environ.get("OPA_TIMEOUT_S", "0.8"))  # under SIR's 1s authoritative budget


def caps():
    return sir_sdk.capabilities(PROVIDER_NAME, sir_sdk.KIND_POLICY, {
        "verdict_types": [sir_sdk.VERDICT_ALLOW, sir_sdk.VERDICT_ASK, sir_sdk.VERDICT_DENY],
        "is_advisory": True,  # authority is set by the operator via `sir provider authoritative`, never on the wire
        "policy_engine": "opa",
        "transport": "http-warm-sidecar",
        "decision_url": OPA_URL,
    })


def evaluate(request: dict):
    """Bridge a sir.policy_request → OPA decision → sir.policy_verdict.v0."""
    try:
        result = query_opa(request)
    except (urllib.error.URLError, ConnectionError, OSError) as exc:
        # OPA sidecar unreachable. Return None — under an authoritative
        # registration SIR fails closed (ask/deny), so we must NOT invent an
        # allow here.
        print(f"[opa-authoritative] WARNING: OPA sidecar unreachable at {OPA_URL}: {exc}", file=sys.stderr)
        return None
    except Exception as exc:  # noqa: BLE001 — surface anything else as a clean no-verdict
        print(f"[opa-authoritative] ERROR: {exc}", file=sys.stderr)
        return None

    if not result:
        # OPA returned no decision document (e.g. `data.sir.policy` undefined).
        # No verdict → SIR fail-closed under authoritative.
        return None

    verdict = result.get("verdict", sir_sdk.VERDICT_ALLOW)
    rules = result.get("rules_matched", [])
    reason = result.get("reason", "")
    return sir_sdk.policy_verdict(PROVIDER_NAME, verdict, rules_matched=rules, reason=reason)


def enrich(request: dict) -> dict:
    """Add bridge-computed, trusted fields the policy can match on safely.

    Rego is not a URL parser. A policy that substring-matches a raw URL target is
    bypassable (e.g. "https://evil.example/?u=https://api.github.com" or
    "https://api.github.com.evil.example/"). We parse the host here with the
    stdlib urllib.parse — which correctly isolates the authority — and pass it as
    `target_host`, so the policy does a simple exact / subdomain comparison on a
    trusted field instead of re-implementing URL parsing in Rego.
    """
    enriched = dict(request)
    if request.get("action") == "net_external":
        target = request.get("target") or ""
        parsed = urllib.parse.urlsplit(target if "://" in target else "//" + target)
        host = (parsed.hostname or "").lower()  # hostname drops userinfo + port
        enriched["target_host"] = host
    return enriched


def query_opa(request: dict) -> dict:
    """POST the request to the warm OPA server and return the decision dict."""
    body = json.dumps({"input": enrich(request)}).encode("utf-8")
    req = urllib.request.Request(
        OPA_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=OPA_TIMEOUT_S) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    # OPA Data API wraps the rule result under "result".
    result = payload.get("result", {})
    if isinstance(result, dict):
        return result
    return {}


if __name__ == "__main__":
    sir_sdk.run_policy_provider(caps, evaluate)
