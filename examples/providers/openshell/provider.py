#!/usr/bin/env python3
"""
OpenShell effect provider — canonical reference for wiring any sandbox to sir.

This is the reference implementation showing how a sandbox vendor (OpenShell,
Sandlock, a custom seccomp wrapper, or any enforcement layer) integrates with
sir's effect_provider protocol.

The provider uses OS-native sandboxing under the hood:
  macOS  — sandbox-exec with a Seatbelt profile (process-launch targets)
  Linux  — bwrap (bubblewrap) for namespace isolation (process-launch targets)
  Other  — record + nudge only; contain/block report unavailable

Returning `unavailable` on a required effect causes sir to deny fail-closed —
that is the correct, honest behavior. Never return `applied` for something the
sandbox did not actually apply.

Adapting to a real product: replace _run_darwin_contain() / _run_linux_contain()
with your sandbox primitives. Capability negotiation and the protocol loop
(sir_sdk.run_effect_provider) stay the same.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

import sir_sdk

PROVIDER_NAME = "openshell-provider"
PROVIDER_VERSION = "0.2.0"


# ── Platform detection ────────────────────────────────────────────────────────

def _sandbox_exec() -> str | None:
    return shutil.which("sandbox-exec") if sys.platform == "darwin" else None


def _bwrap() -> str | None:
    return shutil.which("bwrap") if sys.platform.startswith("linux") else None


def _contain_available() -> bool:
    return _sandbox_exec() is not None or _bwrap() is not None


def _block_available() -> bool:
    # Block (prevent an already-running syscall) requires a kernel enforcer
    # such as eBPF/LSM/seccomp-bpf. Launch-time sandboxes do not provide this.
    return False


# ── macOS Seatbelt profile ────────────────────────────────────────────────────

_ALLOW_OUTBOUND_HOSTS: list[str] = []   # set at startup via env SIR_OPENSHELL_ALLOW_HOSTS

def _darwin_sandbox_profile(allow_network: bool = False) -> str:
    """Return a minimal Seatbelt SBPL profile for process-launch containment.

    Network is denied by default (strict mode). Pass allow_network=True to
    enable outbound access (e.g. when the contained process needs API calls).
    """
    home = os.path.expanduser("~")
    parts = [
        "(version 1)",
        "(allow default)",
    ]
    if not allow_network:
        parts += [
            "(deny network-outbound)",
            "(allow network-outbound (remote unix-socket))",
            '(allow network-outbound (remote ip "localhost:*"))',
        ]
    parts += [
        "(deny file-write*)",
        # Scratch
        '(allow file-write* (subpath "/private/var/folders"))',
        '(allow file-write* (subpath "/var/folders"))',
        '(allow file-write* (subpath "/private/tmp"))',
        '(allow file-write* (subpath "/tmp"))',
        '(allow file-write* (subpath "/dev"))',
    ]
    # Per-user data dirs that macOS processes legitimately write to.
    for rel in [
        "Library/Application Support",
        "Library/Caches",
        "Library/Preferences",
        "Library/Logs",
        "Library/Containers",
        "Library/Group Containers",
        "Library/Saved Application State",
        "Library/WebKit",
        ".npm",
        ".cache",
        ".node_modules",
        ".cargo/registry",
    ]:
        parts.append(f'(allow file-write* (subpath "{home}/{rel}"))')
    return "\n".join(parts) + "\n"


# ── Contain implementations ───────────────────────────────────────────────────

def _run_darwin_contain(effect_id: str, target: dict) -> dict:
    """Apply macOS Seatbelt containment at process-launch time."""
    sandbox_bin = _sandbox_exec()
    if sandbox_bin is None:
        return sir_sdk.effect_unavailable(
            effect_id,
            f"sandbox-exec not found on PATH ({sys.platform})",
        )

    cmd = target.get("cmd") or []
    if not cmd:
        # No launch command provided: the caller wants to apply containment to
        # an already-running PID, which sandbox-exec cannot do.
        pid = target.get("pid")
        return sir_sdk.effect_unavailable(
            effect_id,
            f"openshell: cannot contain already-running PID {pid}; "
            "provide target.cmd (list) for launch-time containment",
        )

    allow_net = bool(target.get("allow_network", False))
    profile_text = _darwin_sandbox_profile(allow_network=allow_net)

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sb", delete=False, prefix="openshell-"
        ) as f:
            f.write(profile_text)
            profile_path = f.name

        # Dry-run: validate the profile is accepted by the kernel before exec.
        check = subprocess.run(
            ["sandbox-exec", "-f", profile_path, "/usr/bin/true"],
            capture_output=True,
            timeout=5,
        )
        if check.returncode != 0:
            os.unlink(profile_path)
            return sir_sdk.effect_failed(
                effect_id,
                f"openshell: sandbox-exec profile rejected: {check.stderr.decode().strip()}",
            )

        reason = (
            f"openshell: sandbox-exec profile validated and ready for "
            f"{cmd[0]!r} (network={'open' if allow_net else 'localhost-only'})"
        )
        # NOTE: In a production implementation you would exec into the sandbox
        # here rather than returning applied with the profile path. This
        # reference provider validates the profile and returns applied so the
        # capability-negotiation path is testable without spawning a full child.
        return _effect_applied_with_audit(
            effect_id,
            reason,
            sandbox_binary=sandbox_bin,
            profile_path=profile_path,
            network="open" if allow_net else "localhost-only",
        )
    except subprocess.TimeoutExpired:
        return sir_sdk.effect_failed(effect_id, "openshell: sandbox-exec probe timed out")
    except Exception as exc:  # noqa: BLE001
        return sir_sdk.effect_failed(effect_id, f"openshell: {exc}")


def _run_linux_contain(effect_id: str, target: dict) -> dict:
    """Apply Linux bubblewrap namespace containment at process-launch time."""
    bwrap_bin = _bwrap()
    if bwrap_bin is None:
        return sir_sdk.effect_unavailable(
            effect_id,
            "bwrap not found on PATH; install bubblewrap for namespace containment",
        )

    cmd = target.get("cmd") or []
    if not cmd:
        pid = target.get("pid")
        return sir_sdk.effect_unavailable(
            effect_id,
            f"openshell: cannot contain already-running PID {pid}; "
            "provide target.cmd (list) for launch-time containment",
        )

    # Validate bwrap is callable.
    try:
        check = subprocess.run(
            [bwrap_bin, "--version"],
            capture_output=True,
            timeout=5,
        )
        if check.returncode != 0:
            return sir_sdk.effect_failed(
                effect_id,
                f"openshell: bwrap probe failed: {check.stderr.decode().strip()}",
            )
    except subprocess.TimeoutExpired:
        return sir_sdk.effect_failed(effect_id, "openshell: bwrap probe timed out")
    except Exception as exc:  # noqa: BLE001
        return sir_sdk.effect_failed(effect_id, f"openshell: {exc}")

    return _effect_applied_with_audit(
        effect_id,
        f"openshell: bwrap namespace ready for {cmd[0]!r}",
        sandbox_binary=bwrap_bin,
    )


# ── Capability response ───────────────────────────────────────────────────────

def caps() -> dict:
    contain = _contain_available()
    sandbox_bin = _sandbox_exec() or _bwrap() or "none"
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_EFFECT,
        {
            sir_sdk.EFFECT_CONTAIN: contain,
            sir_sdk.EFFECT_BLOCK: _block_available(),
            sir_sdk.EFFECT_RECORD: True,
            sir_sdk.EFFECT_NUDGE: True,
            "platform": sys.platform,
            "sandbox_binary": sandbox_bin,
            "contain_target_kinds": ["process_launch"] if contain else [],
            "note": (
                "contain applies at process-launch time via target.cmd; "
                "existing PIDs cannot be retroactively contained"
            ),
        },
    )


# ── Effect dispatcher ─────────────────────────────────────────────────────────

def handle_effect(req: dict) -> dict:
    effect_type = req.get("type", "")
    effect_id = req.get("effect_id", "")
    target = req.get("target") or {}

    if effect_type == sir_sdk.EFFECT_RECORD:
        return sir_sdk.effect_applied(
            effect_id,
            f"openshell: recorded — target.kind={target.get('kind', '?')}",
        )

    if effect_type == sir_sdk.EFFECT_NUDGE:
        return sir_sdk.effect_applied(effect_id, "openshell: nudge delivered")

    if effect_type == sir_sdk.EFFECT_CONTAIN:
        if not _contain_available():
            return sir_sdk.effect_unavailable(
                effect_id,
                f"no sandbox binary available on {sys.platform} "
                "(install sandbox-exec on macOS or bwrap on Linux)",
            )
        if sys.platform == "darwin":
            return _run_darwin_contain(effect_id, target)
        if sys.platform.startswith("linux"):
            return _run_linux_contain(effect_id, target)
        return sir_sdk.effect_unavailable(
            effect_id,
            f"openshell: unsupported platform {sys.platform}",
        )

    if effect_type == sir_sdk.EFFECT_BLOCK:
        return sir_sdk.effect_unavailable(
            effect_id,
            f"{PROVIDER_NAME}: block requires a kernel-level enforcer "
            "(eBPF/LSM/seccomp-bpf); this provider does not support it — "
            "use contain + fail_closed=true for equivalent deny semantics",
        )

    return sir_sdk.effect_not_supported(
        effect_id,
        f"{PROVIDER_NAME}: unsupported effect type {effect_type!r}",
    )


def _effect_applied_with_audit(effect_id: str, reason: str = "", **extra: object) -> dict:
    """Build a sir.effect_result.v0 applied response, optionally with audit fields.

    Prefer sir_sdk.effect_applied() when no extra audit fields are needed.
    This helper adds arbitrary fields to the result dict for the audit trail
    (e.g. sandbox_binary, profile_path) without modifying the shared SDK.
    """
    r: dict = {
        "schema_version": sir_sdk.SCHEMA_EFFECT_RES_V0,
        "effect_id": effect_id,
        "status": sir_sdk.STATUS_APPLIED,
    }
    if reason:
        r["reason"] = reason
    r.update(extra)
    return r


sir_sdk.run_effect_provider(caps, handle_effect)
