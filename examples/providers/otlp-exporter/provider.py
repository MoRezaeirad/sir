#!/usr/bin/env python3
"""
OTLP export provider (Phase 8 observability).

Exports SIR decisions as OpenTelemetry-shaped JSON over HTTP/stdout.
Uses only Python stdlib — no opentelemetry-sdk dep required.

This provider satisfies PRD §8 (OTLP support) without violating the
Go stdlib-only non-negotiable: the OTLP transport runs in this Python
subprocess, not in the Go core.

For real OTLP: point OTLP_ENDPOINT to your collector (Jaeger, Tempo, etc.)
Default: stdout JSONL in OTLP-compatible format.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
import sir_sdk

PROVIDER_NAME = "sir-otlp-exporter"
PROVIDER_VERSION = "0.1.0"
OTLP_ENDPOINT = os.environ.get("OTLP_ENDPOINT", "")


def _to_otlp_span(payload: dict) -> dict:
    """Convert a SIR decision to OTLP-shaped JSON (simplified ResourceSpan)."""
    ts_ns = int(time.time() * 1e9)
    return {
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "sir"}},
                    {"key": "sir.version", "value": {"stringValue": "2"}},
                ]
            },
            "scopeSpans": [{
                "scope": {"name": "sir.kernel", "version": PROVIDER_VERSION},
                "spans": [{
                    "traceId": payload.get("decision_id", ""),
                    "spanId": payload.get("decision_id", "")[:16],
                    "name": f"sir.decision.{payload.get('verdict', 'unknown')}",
                    "startTimeUnixNano": str(ts_ns),
                    "endTimeUnixNano": str(ts_ns),
                    "attributes": [
                        {"key": "sir.verdict", "value": {"stringValue": payload.get("verdict", "")}},
                        {"key": "sir.mode", "value": {"stringValue": payload.get("mode", "")}},
                        {"key": "sir.enforceability", "value": {"stringValue": payload.get("enforceability", "")}},
                        {"key": "sir.attribution", "value": {"stringValue": payload.get("attribution", "")}},
                        {"key": "sir.action_type", "value": {"stringValue": payload.get("action_type", "")}},
                        {"key": "sir.sensitivity", "value": {"stringValue": payload.get("sensitivity", "")}},
                    ],
                    "status": {"code": 2 if payload.get("verdict") == "deny" else 1},
                }]
            }]
        }]
    }


def caps():
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_EXPORT,
        {
            "export": True,
            "format": "otlp-json",
            "otlp": True,
            "endpoint_env": "OTLP_ENDPOINT",
            "redacted_by_default": True,
            "fallback": "stdout-jsonl",
        },
    )


def handle_effect(req):
    effect_type = req.get("type", "")
    effect_id = req.get("effect_id", "")
    target = req.get("target") or {}

    if effect_type != sir_sdk.EFFECT_EXPORT:
        return sir_sdk.effect_not_supported(effect_id, f"otlp-exporter only supports export, not {effect_type}")

    payload = target.get("payload", {})
    otlp_body = _to_otlp_span(payload)
    otlp_json = json.dumps(otlp_body)

    if OTLP_ENDPOINT:
        try:
            req_obj = urllib.request.Request(
                OTLP_ENDPOINT + "/v1/traces",
                data=otlp_json.encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req_obj, timeout=3)
            return sir_sdk.effect_applied(effect_id, f"exported to OTLP endpoint: {OTLP_ENDPOINT}")
        except urllib.error.URLError as e:
            return sir_sdk.effect_failed(effect_id, f"OTLP export failed: {e}")
    else:
        # Fallback: write to stderr (stdout is the stdio-JSON protocol channel).
        # Set OTLP_ENDPOINT to route to a real collector.
        print(otlp_json, file=sys.stderr, flush=True)
        return sir_sdk.effect_applied(effect_id, "exported to stderr (set OTLP_ENDPOINT for remote export)")


sir_sdk.run_effect_provider(caps, handle_effect)
