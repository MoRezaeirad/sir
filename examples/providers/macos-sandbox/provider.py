#!/usr/bin/env python3
"""
macOS Sandbox effect provider — REAL OS-level containment via Seatbelt.

A SECOND real enforcement mechanism, independent of Docker. On a CONTAIN effect
this provider does not simulate: it runs the requested command under
`sandbox-exec` with a deny-network Seatbelt profile and reports what was actually
contained. A network-egress command inside the profile genuinely cannot resolve
or connect — that is demonstrated, not declared.

It backs `mediated` mode the way the devcontainer backs `contained`: SIR launches
and proxies the process under a restrictive profile (the mediation premise),
and the profile is the boundary. enforcement: real (see provider.yaml), backed
by a capture proof — `sir provider verify-containment` actually runs a sandboxed
egress and confirms the kernel blocked it before the kernel scores `enforces`.
"""
import json
import os
import shutil
import subprocess
import sys

import sir_sdk

PROVIDER_NAME = "sir-macos-sandbox"
PROVIDER_VERSION = "0.1.0"

# Seatbelt profile: allow everything EXCEPT network. This is the smallest profile
# that demonstrates real, selective containment — a network egress is blocked
# while ordinary computation still runs. Override the whole profile with
# SIR_SANDBOX_PROFILE if you need a stricter jail.
DENY_NETWORK_PROFILE = os.environ.get(
    "SIR_SANDBOX_PROFILE",
    "(version 1)\n(allow default)\n(deny network*)\n",
)

# Network markers that prove egress was blocked inside the sandbox.
_BLOCKED_MARKERS = (
    "could not resolve", "couldn't resolve", "name or service not known",
    "operation not permitted", "network is unreachable", "could not connect",
    "name does not resolve", "temporary failure in name resolution",
    "connection refused", "no route to host", "bad address",
)


def _sandbox_available() -> bool:
    return shutil.which("sandbox-exec") is not None and sys.platform == "darwin"


def _run_contained(command: str, timeout_s: float = 8.0) -> dict:
    """Run `command` under sandbox-exec with the deny-network profile.

    Returns a structured result describing what was actually contained:
    exit_code, stdout/stderr tails, and whether network egress was blocked.
    """
    cmd = ["sandbox-exec", "-p", DENY_NETWORK_PROFILE, "/bin/sh", "-c", command]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return {"ran": False, "reason": "sandboxed execution timed out", "sandbox": "deny-network"}
    except OSError as e:
        return {"ran": False, "reason": f"sandbox-exec failed: {e}", "sandbox": "deny-network"}

    combined = (proc.stdout + proc.stderr).lower()
    network_blocked = any(marker in combined for marker in _BLOCKED_MARKERS)
    return {
        "ran": True,
        "sandbox": "deny-network",
        "exit_code": proc.returncode,
        "network_blocked": network_blocked,
        "stdout_tail": proc.stdout[-200:],
        "stderr_tail": proc.stderr[-200:],
    }


def caps():
    available = _sandbox_available()
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_EFFECT,
        {
            # contain is only TRUE when we can actually do it right now.
            "contain": available,
            "block": False,
            "record": True,
            "sandbox_exec_available": available,
            "platform": sys.platform,
            "enforcement": "real" if available else "unavailable",
        },
    )


def handle_effect(req):
    effect_type = req.get("type", "")
    effect_id = req.get("effect_id", "")
    target = req.get("target", {}) or {}

    if effect_type == sir_sdk.EFFECT_RECORD:
        return sir_sdk.effect_applied(effect_id, "recorded by macos-sandbox provider")

    if effect_type in (sir_sdk.EFFECT_CONTAIN, sir_sdk.EFFECT_BLOCK):
        if not _sandbox_available():
            return sir_sdk.effect_unavailable(
                effect_id, "sandbox-exec is only available on macOS; cannot contain")

        # The command to contain. Prefer an explicit command; fall back to the
        # display target. With nothing executable to contain, demonstrate the
        # boundary by probing network egress from inside the sandbox.
        command = target.get("command") or target.get("display") or \
            "/usr/bin/curl -sS -m 3 -o /dev/null http://example.com"

        result = _run_contained(command)
        if not result.get("ran"):
            return sir_sdk.effect_failed(effect_id, result.get("reason", "containment failed to run"))

        applied = sir_sdk.effect_applied(
            effect_id,
            f"macos-sandbox: ran under deny-network Seatbelt; network_blocked={result.get('network_blocked')}",
        )
        applied["metadata"] = {
            "contained": True,
            "sandbox": "deny-network",
            "exit_code": result.get("exit_code"),
            "network_blocked": result.get("network_blocked"),
            "command": command,
        }
        return applied

    return sir_sdk.effect_not_supported(
        effect_id, f"macos-sandbox provider does not support effect type: {effect_type}")


# A lightweight self-probe used by `sir provider verify-containment`. On
# {"op":"verify_containment"} it attempts a real sandboxed egress and reports
# whether the network boundary held — proving enforcement is real, not declared.
def verify_containment():
    if not _sandbox_available():
        return {"op": "verify_containment", "verified": False,
                "reason": "sandbox-exec unavailable (non-macOS)"}
    result = _run_contained("/usr/bin/curl -sS -m 3 -o /dev/null http://example.com")
    verified = bool(result.get("ran") and result.get("network_blocked"))
    return {
        "op": "verify_containment",
        "verified": verified,
        "sandbox": "deny-network",
        "evidence": result,
    }


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("op") == "capabilities":
            print(json.dumps(caps()), flush=True)
        elif msg.get("op") == "verify_containment":
            print(json.dumps(verify_containment()), flush=True)
        elif msg.get("schema_version") == sir_sdk.SCHEMA_EFFECT_REQ_V0:
            print(json.dumps(handle_effect(msg)), flush=True)


if __name__ == "__main__":
    main()
