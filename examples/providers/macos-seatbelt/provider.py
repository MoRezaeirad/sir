#!/usr/bin/env python3
"""
macOS Seatbelt (sandbox-exec) effect provider.

Honestly reports whether sandbox-exec containment is available on this platform.
Application is stubbed — the goal is capability negotiation and honest
reporting, not running a full OS sandbox in an example provider.

PRD §15: "Do not initially build: full cross-platform OS enforcement."
"""
import shutil
import sys
import sir_sdk

PROVIDER_NAME = "sir-macos-seatbelt"
PROVIDER_VERSION = "0.1.0"


def _seatbelt_available() -> bool:
    return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None


def caps():
    available = _seatbelt_available()
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_EFFECT,
        {
            "contain": available,
            "block": False,   # sandbox-exec cannot block an already-running PID's network
            "record": True,
            "platform": sys.platform,
            "sandbox_exec_found": available,
            "note": "contain applies to process-launch targets only; existing PIDs are unsupported",
        },
    )


def handle_effect(req):
    effect_type = req.get("type", "")
    effect_id = req.get("effect_id", "")
    target = req.get("target") or {}

    if effect_type == sir_sdk.EFFECT_RECORD:
        return sir_sdk.effect_applied(effect_id, "recorded by macos-seatbelt provider")

    if effect_type == sir_sdk.EFFECT_CONTAIN:
        if not _seatbelt_available():
            return sir_sdk.effect_unavailable(
                effect_id,
                f"sandbox-exec is not available on this platform ({sys.platform})",
            )
        target_kind = target.get("kind", "")
        if target_kind == "process":
            # sandbox-exec constrains process launch, not existing PIDs.
            return sir_sdk.effect_unavailable(
                effect_id,
                "macos-seatbelt cannot contain an already-running process; "
                "use target.kind=process_launch for launch-time containment",
            )
        # process_launch target: in a real implementation this would call
        # sandbox-exec with the appropriate profile. Stubbed here per PRD §15.
        return sir_sdk.effect_applied(
            effect_id,
            "macos-seatbelt: sandbox-exec would be applied at process launch (stub)",
        )

    return sir_sdk.effect_not_supported(
        effect_id,
        f"macos-seatbelt does not support effect type: {effect_type}",
    )


sir_sdk.run_effect_provider(caps, handle_effect)
