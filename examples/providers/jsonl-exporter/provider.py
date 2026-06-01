#!/usr/bin/env python3
"""
JSONL export provider (Phase 8 observability).

Exports redacted decisions and signals to a JSONL file. Redacted by default:
no raw secret values, only display paths, sensitivity labels, and decision
metadata are written. This satisfies PRD §7 (non-negotiable #7).

Effect request format (export_request):
  {"schema_version": "sir.effect_request.v0", "effect_id": "...", "type": "export",
   "target": {"payload": {...}, "output_path": "/path/to/output.jsonl"}}

Also accepts signal-style events for streaming export:
  {"event_type": "decision", "decision": {...}}
"""
import json
import os
import re
import sys
import sir_sdk

PROVIDER_NAME = "sir-jsonl-exporter"
PROVIDER_VERSION = "0.1.0"

# Patterns that suggest a raw secret value (never ledger these)
_SECRET_PATTERNS = [
    re.compile(r'[A-Za-z0-9+/]{40,}'),           # base64-like long string
    re.compile(r'(sk|pk|api|token|secret)[_-]', re.I),  # known key prefixes
    re.compile(r'AKIA[0-9A-Z]{16}'),               # AWS access key
    re.compile(r'ghp_[A-Za-z0-9]{36}'),            # GitHub PAT
]


def _redact(obj, depth=0):
    """Recursively redact values that look like raw secrets. Paths/labels are kept."""
    if depth > 10:
        return obj
    if isinstance(obj, str):
        for pattern in _SECRET_PATTERNS:
            if pattern.search(obj):
                return "[REDACTED]"
        return obj
    if isinstance(obj, dict):
        return {k: _redact(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(item, depth + 1) for item in obj]
    return obj


def _write_jsonl(path: str, record: dict) -> bool:
    try:
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
        return True
    except OSError as e:
        print(f"[jsonl-exporter] write error: {e}", file=sys.stderr)
        return False


def caps():
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_EXPORT,
        {
            "export": True,
            "format": "jsonl",
            "redacted_by_default": True,
            "otlp": False,
        },
    )


def handle_effect(req):
    effect_type = req.get("type", "")
    effect_id = req.get("effect_id", "")
    target = req.get("target") or {}

    if effect_type != sir_sdk.EFFECT_EXPORT:
        return sir_sdk.effect_not_supported(effect_id, f"jsonl-exporter only supports export, not {effect_type}")

    payload = _redact(target.get("payload", {}))
    output_path = target.get("output_path", "~/.sir/v2/export.jsonl")
    output_path = os.path.expanduser(output_path)

    if _write_jsonl(output_path, payload):
        return sir_sdk.effect_applied(effect_id, f"exported to {output_path}")
    return sir_sdk.effect_failed(effect_id, f"failed to write {output_path}")


sir_sdk.run_effect_provider(caps, handle_effect)
