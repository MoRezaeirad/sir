#!/usr/bin/env python3
"""
Sandbox effect provider stub — replace with a real sandbox integration.

Handles: contain, block, record. Returns applied for all supported effects
so the harness can test the full contain→apply→ledger path against a stub.
"""
import sir_sdk

SUPPORTED = {sir_sdk.EFFECT_CONTAIN, sir_sdk.EFFECT_BLOCK, sir_sdk.EFFECT_RECORD}


def caps():
    return sir_sdk.capabilities(
        "sandbox-provider-stub",
        sir_sdk.KIND_EFFECT,
        {
            sir_sdk.EFFECT_CONTAIN: True,
            sir_sdk.EFFECT_BLOCK: True,
            sir_sdk.EFFECT_RECORD: True,
        },
    )


def handle_effect(req):
    effect_type = req.get("type", "")
    if effect_type in SUPPORTED:
        return sir_sdk.effect_applied(
            req["effect_id"],
            reason="stub applied; replace with real sandbox provider",
        )
    return sir_sdk.effect_unavailable(
        req["effect_id"],
        f"sandbox-provider-stub does not support {effect_type}",
    )


sir_sdk.run_effect_provider(caps, handle_effect)
