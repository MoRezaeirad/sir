#!/usr/bin/env python3
"""
test-block-effect: CAPABILITY PLUMBING ONLY — NOT REAL OS ENFORCEMENT.

Purpose: exercise the capability-present path in the control plane.
Claims block=true so the kernel sees a capable provider and classifies
enforceability as 'enforces'. Does NOT enforce anything at the OS level.
The block effect returns 'applied' immediately without touching any process,
sandbox, or kernel primitive.

This stub proves the capability wiring works end-to-end. It is NOT the
destination. The first real enforcement provider is devcontainer (Docker
isolation), then macOS Seatbelt / Linux Sandlock for bare-metal enforcement.

Do not use in production. See examples/providers/noop-effect for the
honest record/nudge-only provider, and examples/providers/devcontainer for
the first real containment provider.

See docs/providers.md for the enforcement roadmap.
"""
import sir_sdk

PROVIDER_NAME = "test-block-effect"
PROVIDER_VERSION = "0.1.0"


def caps():
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_EFFECT,
        {
            sir_sdk.EFFECT_BLOCK: True,
            sir_sdk.EFFECT_RECORD: True,
            sir_sdk.EFFECT_CONTAIN: False,
        },
    )


def handle_effect(req):
    effect_type = req.get("type", "")
    if effect_type == sir_sdk.EFFECT_BLOCK:
        return sir_sdk.effect_applied(
            req["effect_id"],
            "test-block-effect: acknowledged (no real OS enforcement)",
        )
    if effect_type == sir_sdk.EFFECT_RECORD:
        return sir_sdk.effect_applied(req["effect_id"])
    return sir_sdk.effect_unavailable(
        req["effect_id"],
        f"test-block-effect does not support {effect_type}",
    )


sir_sdk.run_effect_provider(caps, handle_effect)
