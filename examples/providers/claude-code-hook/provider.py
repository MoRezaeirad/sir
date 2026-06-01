#!/usr/bin/env python3
"""
Claude Code hook signal provider.

Converts Claude Code PreToolUse hook payloads into sir.signal.v0 signals
(declared_intent, pre_exec). Only PreToolUse is handled — PostToolUse would
require observed_runtime/post_exec and a separate provider declaration.

Native event format (the raw Claude hook JSON on stdin):
  {"session_id": "...", "hook_event_name": "PreToolUse", "tool_name": "Bash",
   "tool_input": {"command": "..."}, "tool_use_id": "...", "cwd": "...", ...}
"""
import hashlib
import sir_sdk

PROVIDER_NAME = "sir-claude-code-hook"
PROVIDER_VERSION = "0.1.0"

# Tool → action type mapping
_TOOL_ACTION = {
    "Bash": "shell_exec",
    "Read": "file_read",
    "Write": "file_write",
    "Edit": "file_write",
    "MultiEdit": "file_write",
    "WebFetch": "network_fetch",
    "WebSearch": "network_search",
}

# Sensitivity patterns (same minimal set as shell-wrapper)
_CRED_PATTERNS = (".env", "credentials", ".aws/", ".ssh/", ".pem", ".key", "id_rsa", "id_ed25519")
_NET_PATTERNS = ("curl ", "wget ", "http://", "https://", "ssh ")


def _classify(tool_name: str, tool_input: dict) -> str:
    display = _tool_display(tool_name, tool_input).lower()
    if any(p in display for p in _CRED_PATTERNS):
        return "credential"
    if any(p in display for p in _NET_PATTERNS):
        return "external_network"
    return "low"


def _tool_display(tool_name: str, tool_input: dict) -> str:
    if tool_name == "Bash":
        return tool_input.get("command", "")
    if tool_name in ("Read", "Write", "Edit", "MultiEdit"):
        return tool_input.get("file_path", tool_input.get("path", ""))
    if tool_name in ("WebFetch", "WebSearch"):
        return tool_input.get("url", tool_input.get("query", ""))
    return str(tool_input)


def caps():
    return sir_sdk.capabilities(
        PROVIDER_NAME,
        sir_sdk.KIND_SIGNAL,
        {
            "signal_reliability": [sir_sdk.RELIABILITY_DECLARED_INTENT],
            "timing": [sir_sdk.TIMING_PRE_EXEC],
            "supported_hook_events": ["PreToolUse"],
        },
    )


def emit(event: dict):
    hook_event = event.get("hook_event_name", "")
    if hook_event != "PreToolUse":
        return None

    tool_name = event.get("tool_name", "unknown")
    tool_input = event.get("tool_input") or {}
    session_id = event.get("session_id", "")
    tool_use_id = event.get("tool_use_id", "")
    signal_time = event.get("signal_time", "1970-01-01T00:00:00Z")

    raw_id = f"{session_id}:{tool_use_id}:{tool_name}"
    signal_id = "hook-" + hashlib.sha256(raw_id.encode()).hexdigest()[:12]

    display = _tool_display(tool_name, tool_input)
    action_type = _TOOL_ACTION.get(tool_name, "tool_use")

    action_claim: dict = {
        "type": action_type,
        "tool_name": tool_name,
        "target": {
            "display": display,
            "sensitivity": _classify(tool_name, tool_input),
        },
    }

    session = {}
    if session_id:
        session["session_id"] = session_id
    if tool_use_id:
        session["span_id"] = tool_use_id

    return sir_sdk.make_signal(
        signal_id=signal_id,
        signal_time=signal_time,
        source_kind="claude_hook",
        reliability=sir_sdk.RELIABILITY_DECLARED_INTENT,
        timing=sir_sdk.TIMING_PRE_EXEC,
        action_claim=action_claim,
        provider_name=PROVIDER_NAME,
        provider_version=PROVIDER_VERSION,
        session=session or None,
        actor_claim={"kind": "ai_coding_agent", "name": "claude-code"},
    )


sir_sdk.run_signal_provider(caps, emit)
