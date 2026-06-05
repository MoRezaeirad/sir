#!/usr/bin/env python3
"""
Cedar (cedar-policy) bridge for SIR — AUTHORITATIVE variant.

Wired as an AUTHORITATIVE policy_provider, this provider's Cedar decision
REPLACES SIR's native decision: it can GRANT actions native would gate, RESTRICT
actions native would allow, and (because authoritative mode turns the native
floors off) RE-IMPLEMENT the exfiltration wall in Cedar.

How it works:
  1. SIR sends a sir.policy_request (v0 fields + v1 session/integrity signals)
     on stdin, one JSON object per line.
  2. This bridge maps it into Cedar's principal/action/resource/context model and
     runs `cedar authorize --verbose`.
  3. Cedar returns ALLOW (exit 0) or DENY (exit 2) plus the matched policy @ids.
  4. The bridge maps that to a SIR verdict and writes sir.policy_verdict.v0.

The Permit/Forbid → allow/ask/deny problem
-------------------------------------------
Cedar has only Permit and Forbid — no "ask". SIR needs three verdicts. The
convention here: a Forbid policy whose @id starts with "ask:" means ASK, not
DENY. The bridge reads the matched @id from `--verbose` output and maps:
    ALLOW (exit 0)                       -> "allow"
    DENY  + matched @id starts "ask:"    -> "ask"
    DENY  + any other matched @id        -> "deny"
Cedar's own semantics (any forbid overrides any permit) give most-restrictive
for free; the only nuance is that a real "deny" forbid must out-rank an "ask:"
forbid — handled below by preferring deny when both match.

Prereqs:
  cargo install cedar-policy-cli      # provides the `cedar` binary (v4.x)

Wire it (from the repo root):
  PYTHONPATH=sdk/python bin/sir provider install examples/providers/cedar-authoritative/provider.yaml
  bin/sir provider use cedar-authoritative
  bin/sir provider authoritative cedar-authoritative --on-failure deny

Env:
  CEDAR_BIN        — cedar binary (default "cedar")
  CEDAR_POLICIES   — policy file (default policies/sir.cedar)
"""
import json
import os
import subprocess
import sys
import tempfile

import sir_sdk

PROVIDER_NAME = "cedar-authoritative"
PROVIDER_VERSION = "0.1.0"

CEDAR_BIN = os.environ.get("CEDAR_BIN", "cedar")
_HERE = os.path.dirname(os.path.abspath(__file__))
CEDAR_POLICIES = os.environ.get("CEDAR_POLICIES", os.path.join(_HERE, "policies", "sir.cedar"))
CEDAR_TIMEOUT_S = float(os.environ.get("CEDAR_TIMEOUT_S", "0.8"))  # under SIR's 1s authoritative budget


def caps():
    return sir_sdk.capabilities(PROVIDER_NAME, sir_sdk.KIND_POLICY, {
        "verdict_types": [sir_sdk.VERDICT_ALLOW, sir_sdk.VERDICT_ASK, sir_sdk.VERDICT_DENY],
        "is_advisory": True,  # authority is the operator's act, not a wire claim
        "policy_engine": "cedar",
        "policy_file": CEDAR_POLICIES,
    })


def evaluate(request: dict):
    try:
        verdict, rules, reason = query_cedar(request)
    except FileNotFoundError:
        # cedar binary not installed — under authoritative, SIR fails closed.
        print("[cedar-authoritative] WARNING: `cedar` binary not found (cargo install cedar-policy-cli)", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("[cedar-authoritative] WARNING: cedar authorize timed out", file=sys.stderr)
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"[cedar-authoritative] ERROR: {exc}", file=sys.stderr)
        return None

    return sir_sdk.policy_verdict(PROVIDER_NAME, verdict, rules_matched=rules, reason=reason)


def map_to_cedar(request: dict):
    """sir.policy_request → Cedar (principal, action, resource, context)."""
    actor = request.get("resolved_actor") or "unknown"
    action = request.get("action") or "unknown"
    target = request.get("target") or "unknown"

    principal = f'SIR::Actor::"{actor}"'
    cedar_action = f'SIR::Action::"{_esc(action)}"'
    resource = f'SIR::Target::"{_esc(target)}"'

    # Context carries everything a policy keys on — incl. the v1 session signals
    # that make the integrity-floor re-implementation possible.
    context = {
        "taint": request.get("taint", []),
        "attribution_confidence": request.get("attribution_confidence", "unknown"),
        "mode": request.get("mode", ""),
        "session_secret": bool(request.get("session_secret", False)),
        "session_was_secret": bool(request.get("session_was_secret", False)),
        "session_untrusted_read": bool(request.get("session_untrusted_read", False)),
        "session_untrusted_this_turn": bool(request.get("session_untrusted_this_turn", False)),
        # Pre-computed string helpers (Cedar string ops are limited; do the
        # substring matching in the bridge and pass booleans the policy can read).
        "target_is_credential": _is_credential_path(target),
        "target_lower": target.lower(),
    }
    return principal, cedar_action, resource, context


def query_cedar(request: dict):
    principal, action, resource, context = map_to_cedar(request)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as cf:
        json.dump(context, cf)
        ctx_path = cf.name
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as ef:
        ef.write("[]")  # no entity hierarchy needed for this policy set
        ent_path = ef.name
    try:
        proc = subprocess.run(
            [
                CEDAR_BIN, "authorize", "--verbose",
                "--policies", CEDAR_POLICIES,
                "--entities", ent_path,
                "--principal", principal,
                "--action", action,
                "--resource", resource,
                "--context", ctx_path,
            ],
            capture_output=True, text=True, timeout=CEDAR_TIMEOUT_S,
        )
    finally:
        os.unlink(ctx_path)
        os.unlink(ent_path)

    out = (proc.stdout or "") + (proc.stderr or "")

    # cedar-policy-cli exit codes (CedarExitCode): 0 = AuthorizeAllow,
    # 2 = AuthorizeDeny, 1 = Failure, 3 = ValidationFailure. ONLY 0 and 2 are
    # authorization answers; 1/3/anything-else mean the CLI could not decide
    # (malformed policy, bad context, incompatible CLI version). We must NOT map
    # those to DENY — under an AUTHORITATIVE registration a misleading silent deny
    # would mask a broken provider. Raise instead, so evaluate() returns no verdict
    # and SIR applies its fail-closed `--on-failure` behavior (ask/deny by config).
    if proc.returncode not in (0, 2):
        raise RuntimeError(
            f"cedar exited {proc.returncode} (provider failure, not an authorization "
            f"decision): {out.strip()[:200]}"
        )

    matched = _matched_policy_ids(out)

    # ALLOW: exit 0.
    if proc.returncode == 0:
        return sir_sdk.VERDICT_ALLOW, matched, ""

    # DENY (exit 2). Distinguish a real deny from an "ask:" forbid. A real deny
    # out-ranks an ask (most-restrictive): if ANY matched id is not an ask, it's
    # a deny.
    real_deny_ids = [m for m in matched if not m.startswith("ask:")]
    ask_ids = [m for m in matched if m.startswith("ask:")]
    if real_deny_ids:
        return sir_sdk.VERDICT_DENY, real_deny_ids, "Denied by Cedar policy."
    if ask_ids:
        return sir_sdk.VERDICT_ASK, [i[len("ask:"):] for i in ask_ids], "Approval required by Cedar policy."
    # DENY with no identifiable policy (e.g. no permit matched) → deny.
    return sir_sdk.VERDICT_DENY, matched, "Denied by Cedar policy (no permit matched)."


def _matched_policy_ids(verbose_output: str) -> list:
    """Parse `cedar authorize --verbose` for the matched policy @ids.

    Format:
        DENY

        note: this decision was due to the following policies:
          deny-agent-cred
    """
    ids = []
    capture = False
    for line in verbose_output.splitlines():
        s = line.strip()
        if s.startswith("note:") and "following policies" in s:
            capture = True
            continue
        if capture:
            if not s:
                break
            ids.append(s)
    return ids


_CRED_PATTERNS = (".env", ".aws", ".ssh", "credentials", "id_rsa", ".pem", "secrets", ".npmrc", ".git-credentials")


def _is_credential_path(path: str) -> bool:
    p = (path or "").lower()
    return any(pat in p for pat in _CRED_PATTERNS)


def _esc(s: str) -> str:
    return (s or "").replace("\\", "\\\\").replace('"', '\\"')


if __name__ == "__main__":
    sir_sdk.run_policy_provider(caps, evaluate)
