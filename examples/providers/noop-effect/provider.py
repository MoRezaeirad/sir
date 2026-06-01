#!/usr/bin/env python3
"""No-op effect provider — records and nudges only; no containment."""
import sir_sdk


def caps():
    return sir_sdk.capabilities(
        "noop-effect-provider",
        sir_sdk.KIND_EFFECT,
        {
            sir_sdk.EFFECT_RECORD: True,
            sir_sdk.EFFECT_NUDGE: True,
            sir_sdk.EFFECT_CONTAIN: False,
            sir_sdk.EFFECT_BLOCK: False,
        },
    )


def handle_effect(req):
    effect_type = req.get("type", "")
    if effect_type in (sir_sdk.EFFECT_RECORD, sir_sdk.EFFECT_NUDGE):
        return sir_sdk.effect_applied(req["effect_id"])
    return sir_sdk.effect_unavailable(
        req["effect_id"],
        f"noop-effect-provider does not support {effect_type}",
    )


sir_sdk.run_effect_provider(caps, handle_effect)
