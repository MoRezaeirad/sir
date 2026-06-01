#!/usr/bin/env python3
"""
DevContainer effect provider — REAL OS-level containment via Docker.

On a CONTAIN effect this provider does not simulate: it runs the requested
command inside a locked-down container (`docker run --network=none --read-only
--memory --pids-limit --security-opt no-new-privileges`) and reports what was
actually contained. A network-egress command inside a --network=none container
genuinely cannot reach the network — that is demonstrated, not declared.

enforcement: real (see provider.yaml). Backed by a capture proof —
`sir provider verify-containment` actually runs a contained egress and confirms
the container blocked it before the kernel is allowed to score `enforces`.
"""
import json
import os
import shutil
import subprocess
import sys

import sir_sdk

PROVIDER_NAME = "sir-devcontainer"
PROVIDER_VERSION = "0.2.0"

# Minimal image used for containment. alpine is tiny and ubiquitous; override
# with SIR_DEVCONTAINER_IMAGE. The image is pulled once (needs network); the
# contained execution itself runs with --network=none.
CONTAIN_IMAGE = os.environ.get("SIR_DEVCONTAINER_IMAGE", "alpine:latest")

# Hardened docker run flags for the contained execution. No network, read-only
# root, capped memory and pids, no privilege escalation, all caps dropped.
HARDENED_FLAGS = [
    "--rm",
    "--network=none",
    "--read-only",
    "--memory=128m",
    "--pids-limit=64",
    "--security-opt", "no-new-privileges",
    "--cap-drop=ALL",
]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=4)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False


def _image_present(image: str) -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", image],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def caps():
    docker_ok = _docker_available()
    image_ok = docker_ok and _image_present(CONTAIN_IMAGE)
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_EFFECT,
        {
            # contain is only TRUE when we can actually do it right now.
            "contain": image_ok,
            "block": False,
            "record": True,
            "docker_available": docker_ok,
            "image": CONTAIN_IMAGE,
            "image_present": image_ok,
            "enforcement": "real" if image_ok else "unavailable",
        },
    )


def _run_contained(command: str, timeout_s: float = 8.0) -> dict:
    """Run `command` inside a hardened, network-isolated container.

    Returns a structured result describing what was actually contained:
    exit_code, stdout/stderr tails, and whether network egress was blocked.
    """
    cmd = ["docker", "run", *HARDENED_FLAGS, CONTAIN_IMAGE, "sh", "-c", command]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return {"ran": False, "reason": "contained execution timed out", "network": "none"}
    except OSError as e:
        return {"ran": False, "reason": f"docker run failed: {e}", "network": "none"}

    combined = (proc.stdout + proc.stderr).lower()
    # A network attempt inside --network=none fails to resolve / connect.
    network_blocked = any(
        marker in combined
        for marker in ("bad address", "could not resolve", "network is unreachable",
                       "name does not resolve", "temporary failure in name resolution",
                       "connection refused", "no route to host")
    )
    return {
        "ran": True,
        "network": "none",
        "exit_code": proc.returncode,
        "network_blocked": network_blocked,
        "stdout_tail": proc.stdout[-200:],
        "stderr_tail": proc.stderr[-200:],
    }


def handle_effect(req):
    effect_type = req.get("type", "")
    effect_id = req.get("effect_id", "")
    target = req.get("target", {}) or {}

    if effect_type == sir_sdk.EFFECT_RECORD:
        return sir_sdk.effect_applied(effect_id, "recorded by devcontainer provider")

    if effect_type in (sir_sdk.EFFECT_CONTAIN, sir_sdk.EFFECT_BLOCK):
        if not _docker_available():
            return sir_sdk.effect_unavailable(
                effect_id, "docker daemon is not available; cannot contain")
        if not _image_present(CONTAIN_IMAGE):
            return sir_sdk.effect_unavailable(
                effect_id,
                f"containment image {CONTAIN_IMAGE} not present; run: docker pull {CONTAIN_IMAGE}")

        # The command to contain. Prefer an explicit command; fall back to the
        # display target. If there is nothing executable to contain, we still
        # demonstrate the boundary by probing network egress from inside the jail.
        command = target.get("command") or target.get("display") or "wget -T 2 -q -O- http://sir.invalid"

        result = _run_contained(command)
        if not result.get("ran"):
            return sir_sdk.effect_failed(effect_id, result.get("reason", "containment failed to run"))

        applied = sir_sdk.effect_applied(
            effect_id,
            f"devcontainer: ran in --network=none jail; network_blocked={result.get('network_blocked')}",
        )
        # Attach structured containment evidence (consumed by verify-containment).
        applied["metadata"] = {
            "contained": True,
            "network": "none",
            "image": CONTAIN_IMAGE,
            "exit_code": result.get("exit_code"),
            "network_blocked": result.get("network_blocked"),
            "command": command,
        }
        return applied

    return sir_sdk.effect_not_supported(
        effect_id, f"devcontainer provider does not support effect type: {effect_type}")


# A lightweight self-probe used by `sir provider verify-containment`. When the
# provider receives {"op":"verify_containment"} it attempts a real contained
# egress and reports whether the network boundary held — proving enforcement is
# real, not declared.
def verify_containment():
    if not _docker_available():
        return {"op": "verify_containment", "verified": False, "reason": "docker unavailable"}
    if not _image_present(CONTAIN_IMAGE):
        return {"op": "verify_containment", "verified": False,
                "reason": f"image {CONTAIN_IMAGE} not present"}
    result = _run_contained("wget -T 3 -q -O- http://example.com")
    verified = bool(result.get("ran") and result.get("network_blocked"))
    return {
        "op": "verify_containment",
        "verified": verified,
        "network": "none",
        "image": CONTAIN_IMAGE,
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
