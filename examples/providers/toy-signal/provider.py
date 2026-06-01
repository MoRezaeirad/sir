#!/usr/bin/env python3
"""Toy signal provider — minimal example that emits fixture-driven signals."""
import sir_sdk

PROVIDER_NAME = "toy-signal-provider"
PROVIDER_VERSION = "0.1.0"


def caps():
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_SIGNAL,
        {
            "signal_reliability": [sir_sdk.RELIABILITY_DECLARED_INTENT],
            "timing": [sir_sdk.TIMING_PRE_EXEC],
        },
    )


def emit(event: dict):
    # Echo the event back as a minimal sir.signal.v0 for harness testing.
    signal_id = event.get("signal_id", "toy-sig-001")
    signal_time = event.get("signal_time", "1970-01-01T00:00:00Z")
    action_claim = event.get("action_claim") or {"type": "unknown"}
    return sir_sdk.make_signal(
        signal_id=signal_id,
        signal_time=signal_time,
        source_kind="toy",
        reliability=sir_sdk.RELIABILITY_DECLARED_INTENT,
        timing=sir_sdk.TIMING_PRE_EXEC,
        action_claim=action_claim,
        provider_name=PROVIDER_NAME,
        provider_version=PROVIDER_VERSION,
    )


sir_sdk.run_signal_provider(caps, emit)
