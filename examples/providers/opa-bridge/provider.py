#!/usr/bin/env python3
"""
OPA (Open Policy Agent) bridge for SIR.

This provider bridges SIR policy requests to OPA's eval API. Any Rego policy
file in this directory is loaded and evaluated for every SIR action.

How it works:
  1. SIR sends a sir.policy_request.v0 to this provider's stdin.
  2. This bridge calls `opa eval` with the request as `input`.
  3. OPA evaluates your Rego policy and returns a verdict.
  4. This bridge wraps the verdict in sir.policy_verdict.v0 and writes to stdout.

Prerequisites:
  - `opa` binary on PATH  (https://www.openpolicyagent.org/docs/latest/#1-download-opa)
  - Your policy file: policy.rego (or set POLICY_FILE env var)

Quick start:
  sir provider install ./examples/providers/opa-bridge/provider.yaml
  sir provider use opa-bridge

Tuning:
  Edit policy.rego — OPA re-loads it on every evaluation (no restart needed).
  Set POLICY_FILE=path/to/your-policy.rego to use a different file.
  Set OPA_BUNDLE_PATH to load a full OPA bundle directory.
"""
import json
import os
import subprocess
import sys

import sir_sdk

PROVIDER_NAME = "opa-bridge"
PROVIDER_VERSION = "0.1.0"

# Policy file path — override with POLICY_FILE env var.
POLICY_FILE = os.environ.get(
    "POLICY_FILE",
    os.path.join(os.path.dirname(__file__), "policy.rego"),
)
# OPA query to evaluate. Returns {verdict, rules_matched, reason}.
OPA_QUERY = "data.sir.policy"
OPA_BUNDLE = os.environ.get("OPA_BUNDLE_PATH", "")


def caps():
    return sir_sdk.capabilities(PROVIDER_NAME, sir_sdk.KIND_POLICY, {
        "verdict_types": [sir_sdk.VERDICT_ALLOW, sir_sdk.VERDICT_ASK, sir_sdk.VERDICT_DENY],
        "is_advisory": True,
        "policy_engine": "opa",
        "policy_file": POLICY_FILE,
    })


def evaluate(request: dict):
    """Bridge a sir.policy_request.v0 to OPA and return a sir.policy_verdict.v0."""
    try:
        result = query_opa(request)
    except FileNotFoundError:
        # OPA not installed — fail open (no verdict, SIR uses native floors).
        print(
            f"[opa-bridge] WARNING: 'opa' binary not found. "
            f"Install from https://www.openpolicyagent.org/",
            file=sys.stderr,
        )
        return None
    except subprocess.TimeoutExpired:
        print("[opa-bridge] WARNING: OPA eval timed out", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[opa-bridge] ERROR: {exc}", file=sys.stderr)
        return None

    verdict = result.get("verdict", sir_sdk.VERDICT_ALLOW)
    rules   = result.get("rules_matched", [])
    reason  = result.get("reason", "")

    return sir_sdk.policy_verdict(PROVIDER_NAME, verdict, rules_matched=rules, reason=reason)


def query_opa(request: dict) -> dict:
    """Run `opa eval` and return the parsed result dict."""
    # OPA receives the full sir.policy_request.v0 as input.
    # Your Rego policy accesses fields via input.action, input.taint, etc.
    opa_input = json.dumps(request)

    cmd = ["opa", "eval", "--format", "raw", "--stdin-input", OPA_QUERY]
    if OPA_BUNDLE:
        cmd += ["-b", OPA_BUNDLE]
    else:
        cmd += ["-d", POLICY_FILE]

    proc = subprocess.run(
        cmd,
        input=opa_input,
        capture_output=True,
        text=True,
        timeout=0.15,  # 150ms — stay within sir's 200ms policy provider budget
    )

    if proc.returncode != 0:
        raise RuntimeError(f"opa eval failed: {proc.stderr.strip()}")

    raw = proc.stdout.strip()
    if not raw:
        return {}

    parsed = json.loads(raw)
    # OPA raw format returns the value directly for a simple expression.
    if isinstance(parsed, dict):
        return parsed
    return {}


sir_sdk.run_policy_provider(caps, evaluate)
