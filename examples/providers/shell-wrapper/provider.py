#!/usr/bin/env python3
"""
Shell wrapper signal provider.

Converts shell preexec events into sir.signal.v0 signals (declared_intent, pre_exec).

Native event format (feed on stdin):
  {"command": "curl https://...", "pid": 1234, "session_id": "...", "cwd": "/path/to/repo"}

All fields except "command" are optional.
"""
import hashlib
import sir_sdk

PROVIDER_NAME = "sir-shell-wrapper"
PROVIDER_VERSION = "0.1.0"

# Minimal sensitivity classifier — three patterns, inline, no imports.
_CRED_PATTERNS = (".env", "credentials", ".aws/", ".ssh/", ".pem", ".key", "id_rsa", "id_ed25519")
_NET_PATTERNS = ("curl ", "wget ", " ssh ", " scp ", " rsync ", "nc ", "ncat ", "socat ")


def _classify(command: str) -> str:
    cmd_lower = command.lower()
    if any(p in cmd_lower for p in _CRED_PATTERNS):
        return "credential"
    if any(p in cmd_lower for p in _NET_PATTERNS):
        return "external_network"
    return "low"


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
    command = event.get("command", "")
    if not command:
        return None

    pid = event.get("pid", 0)
    session_id = event.get("session_id", "")
    cwd = event.get("cwd", "")

    # Deterministic signal ID: hash of command+pid for reproducible test output.
    raw_id = f"{command}:{pid}"
    signal_id = "shell-" + hashlib.sha256(raw_id.encode()).hexdigest()[:12]
    signal_time = event.get("signal_time", "1970-01-01T00:00:00Z")

    session = {}
    if session_id:
        session["session_id"] = session_id

    actor_claim = {"kind": "shell", "pid": pid} if pid else {"kind": "shell"}
    if cwd:
        actor_claim["cwd"] = cwd

    return sir_sdk.make_signal(
        signal_id=signal_id,
        signal_time=signal_time,
        source_kind="shell_wrapper",
        reliability=sir_sdk.RELIABILITY_DECLARED_INTENT,
        timing=sir_sdk.TIMING_PRE_EXEC,
        action_claim={
            "type": "shell_exec",
            "target": {
                "display": command,
                "sensitivity": _classify(command),
            },
        },
        provider_name=PROVIDER_NAME,
        provider_version=PROVIDER_VERSION,
        session=session or None,
        actor_claim=actor_claim,
    )


sir_sdk.run_signal_provider(caps, emit)
