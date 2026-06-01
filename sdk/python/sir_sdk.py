"""
SIR Provider SDK — zero dependencies, single-file vendorable.

Policy provider quick-start:

    import sir_sdk

    PROVIDER = "my-opa-bridge"

    def caps():
        return sir_sdk.capabilities(PROVIDER, sir_sdk.KIND_POLICY, {
            "verdict_types": ["allow", "ask", "deny"],
            "is_advisory": True,
        })

    def evaluate(request):
        action = request.get("action")
        taint  = request.get("taint", [])
        actor  = request.get("resolved_actor", "unknown")

        if "credential_access" in taint and action == "push_origin":
            return sir_sdk.policy_verdict(PROVIDER, "ask",
                rules_matched=["was-secret-push-origin"],
                reason="session previously held credentials; re-approve push")

        return sir_sdk.policy_verdict(PROVIDER, "allow")

    sir_sdk.run_policy_provider(caps, evaluate)

The request dict your evaluate() function receives is sir.policy_request.v0 —
see schemas/sir.policy_request.v0.schema.json for all fields.

Providers can either import this from PYTHONPATH (set by `sir provider test`)
or vendor a copy alongside their provider.py.

Usage (signal provider):

    import sir_sdk

    def my_caps():
        return sir_sdk.capabilities("my-provider", sir_sdk.KIND_SIGNAL, {
            "signal_reliability": [sir_sdk.RELIABILITY_DECLARED_INTENT],
            "timing": [sir_sdk.TIMING_PRE_EXEC],
        })

    sir_sdk.run_signal_provider(my_caps)

Usage (effect provider):

    import sir_sdk

    def my_caps():
        return sir_sdk.capabilities("my-provider", sir_sdk.KIND_EFFECT, {
            "contain": True, "block": True,
        })

    def my_effect(req):
        if req["type"] == sir_sdk.EFFECT_CONTAIN:
            return sir_sdk.effect_applied(req["effect_id"])
        return sir_sdk.effect_unavailable(req["effect_id"], "unsupported")

    sir_sdk.run_effect_provider(my_caps, my_effect)
"""
from __future__ import annotations

import json
import sys
from typing import Any, Callable, Dict, Optional

# -- Schema version constants (match schemas/*.schema.json exactly) ----------

SCHEMA_SIGNAL_V0          = "sir.signal.v0"
SCHEMA_CAPABILITIES_V0    = "sir.capabilities.v0"
SCHEMA_EFFECT_REQ_V0      = "sir.effect_request.v0"
SCHEMA_EFFECT_RES_V0      = "sir.effect_result.v0"
SCHEMA_PROVIDER_V0        = "sir.provider.v0"
SCHEMA_POLICY_REQUEST_V0   = "sir.policy_request.v0"
SCHEMA_POLICY_VERDICT_V0   = "sir.policy_verdict.v0"
SCHEMA_ADVISORY_REQUEST_V0 = "sir.advisory_request.v0"
SCHEMA_ADVISORY_SIGNAL_V0  = "sir.advisory_signal.v0"

# -- Verdict enum (sir.policy_verdict.v0) ------------------------------------

VERDICT_ALLOW = "allow"
VERDICT_ASK   = "ask"
VERDICT_DENY  = "deny"

# -- Risk level enum (sir.advisory_signal.v0) --------------------------------

RISK_LOW      = "low"
RISK_MEDIUM   = "medium"
RISK_HIGH     = "high"
RISK_CRITICAL = "critical"

# -- Reliability enum (sir.signal.v0) ----------------------------------------

RELIABILITY_DECLARED_INTENT   = "declared_intent"
RELIABILITY_MEDIATED_ACTION   = "mediated_action"
RELIABILITY_OBSERVED_RUNTIME  = "observed_runtime"
RELIABILITY_ENFORCED_BOUNDARY = "enforced_boundary"
RELIABILITY_ADVISORY_SIGNAL   = "advisory_signal"
RELIABILITY_USER_DECISION     = "user_decision"
RELIABILITY_ADMIN_POLICY      = "admin_policy"

# -- Timing enum (sir.signal.v0) ---------------------------------------------

TIMING_PRE_EXEC    = "pre_exec"
TIMING_DURING_EXEC = "during_exec"
TIMING_POST_EXEC   = "post_exec"
TIMING_UNKNOWN     = "unknown"

# -- Effect type enum (sir.effect_request.v0) --------------------------------

EFFECT_RECORD            = "record"
EFFECT_NUDGE             = "nudge"
EFFECT_REDACT            = "redact"
EFFECT_PROMPT            = "prompt"
EFFECT_BLOCK             = "block"
EFFECT_CONTAIN           = "contain"
EFFECT_EXPORT            = "export"
EFFECT_KILL_PROCESS      = "kill_process"
EFFECT_REQUEST_EXCEPTION = "request_exception"

# -- Effect status enum (sir.effect_result.v0) --------------------------------

STATUS_APPLIED       = "applied"
STATUS_UNAVAILABLE   = "unavailable"
STATUS_FAILED        = "failed"
STATUS_NOT_SUPPORTED = "not_supported"

# -- Provider kind enum (sir.provider.v0, sir.capabilities.v0) ---------------

KIND_SIGNAL   = "signal_provider"
KIND_EFFECT   = "effect_provider"
KIND_POLICY   = "policy_provider"
KIND_ADVISORY = "advisory_provider"
KIND_EXPORT   = "export_provider"

# -- Builder helpers ----------------------------------------------------------

def capabilities(provider: str, kind: str, caps: Dict[str, Any]) -> Dict[str, Any]:
    """Build a sir.capabilities.v0 response dict."""
    return {
        "schema_version": SCHEMA_CAPABILITIES_V0,
        "provider": provider,
        "kind": kind,
        "capabilities": caps,
    }


def effect_applied(effect_id: str, reason: str = "") -> Dict[str, Any]:
    """Build a sir.effect_result.v0 response with status=applied."""
    r: Dict[str, Any] = {
        "schema_version": SCHEMA_EFFECT_RES_V0,
        "effect_id": effect_id,
        "status": STATUS_APPLIED,
    }
    if reason:
        r["reason"] = reason
    return r


def effect_unavailable(effect_id: str, reason: str) -> Dict[str, Any]:
    """Build a sir.effect_result.v0 response with status=unavailable."""
    return {
        "schema_version": SCHEMA_EFFECT_RES_V0,
        "effect_id": effect_id,
        "status": STATUS_UNAVAILABLE,
        "reason": reason,
    }


def effect_not_supported(effect_id: str, reason: str) -> Dict[str, Any]:
    """Build a sir.effect_result.v0 response with status=not_supported."""
    return {
        "schema_version": SCHEMA_EFFECT_RES_V0,
        "effect_id": effect_id,
        "status": STATUS_NOT_SUPPORTED,
        "reason": reason,
    }


def effect_failed(effect_id: str, reason: str) -> Dict[str, Any]:
    """Build a sir.effect_result.v0 response with status=failed."""
    return {
        "schema_version": SCHEMA_EFFECT_RES_V0,
        "effect_id": effect_id,
        "status": STATUS_FAILED,
        "reason": reason,
    }


# -- Policy verdict builder ---------------------------------------------------

def policy_verdict(
    provider: str,
    verdict: str,
    rules_matched: Optional[list] = None,
    reason: str = "",
) -> Dict[str, Any]:
    """Build a sir.policy_verdict.v0 response dict.

    Args:
        provider:      Your provider name (matches name in provider.yaml).
        verdict:       One of VERDICT_ALLOW, VERDICT_ASK, VERDICT_DENY.
        rules_matched: List of rule IDs that fired (for traceability in sir log).
        reason:        Human-readable explanation shown in sir why output.

    Returns a dict ready to be JSON-serialized and written to stdout.

    Example:
        return sir_sdk.policy_verdict(
            "my-opa-bridge", VERDICT_ASK,
            rules_matched=["was-secret-push"],
            reason="session held credentials; re-approve push",
        )
    """
    v: Dict[str, Any] = {
        "schema_version": SCHEMA_POLICY_VERDICT_V0,
        "provider": provider,
        "verdict": verdict,
        "is_advisory": True,  # always True — policy providers are advisory only
    }
    if rules_matched:
        v["rules_matched"] = list(rules_matched)
    if reason:
        v["reason"] = reason
    return v


# -- Advisory signal builder --------------------------------------------------

def advisory_signal(
    provider: str,
    risk_level: str,
    reason: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a sir.advisory_signal.v0 response dict.

    Args:
        provider:    Your provider name (matches name in provider.yaml).
        risk_level:  One of RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL.
                     Advisory providers can raise risk but NEVER lower it (PRD §10.6-7).
        reason:      Human-readable explanation shown in sir why output.
        metadata:    Optional dict with provider-specific context.

    Returns a dict ready to be JSON-serialized and written to stdout.

    Example:
        if "sudo" in command:
            return sir_sdk.advisory_signal(PROVIDER_NAME, RISK_HIGH,
                reason="sudo escalation detected")
        return sir_sdk.advisory_signal(PROVIDER_NAME, RISK_LOW)
    """
    sig: Dict[str, Any] = {
        "schema_version": SCHEMA_ADVISORY_SIGNAL_V0,
        "provider": provider,
        "risk_level": risk_level,
        "is_advisory": True,
    }
    if reason:
        sig["reason"] = reason
    if metadata:
        sig["metadata"] = metadata
    return sig


# -- Signal builder -----------------------------------------------------------

def make_signal(
    signal_id: str,
    signal_time: str,
    source_kind: str,
    reliability: str,
    timing: str,
    action_claim: Dict[str, Any],
    provider_name: str = "",
    provider_version: str = "",
    session: Optional[Dict[str, Any]] = None,
    actor_claim: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a sir.signal.v0 dict from typed fields."""
    src: Dict[str, Any] = {
        "kind": source_kind,
        "reliability": reliability,
        "timing": timing,
    }
    if provider_name:
        src["provider"] = provider_name
    if provider_version:
        src["provider_version"] = provider_version

    sig: Dict[str, Any] = {
        "schema_version": SCHEMA_SIGNAL_V0,
        "signal_id": signal_id,
        "signal_time": signal_time,
        "source": src,
        "action_claim": action_claim,
    }
    if session:
        sig["session"] = session
    if actor_claim:
        sig["actor_claim"] = actor_claim
    return sig


# -- Provider runner ----------------------------------------------------------

CapabilitiesFunc = Callable[[], Dict[str, Any]]
EffectFunc = Callable[[Dict[str, Any]], Dict[str, Any]]
EmitFunc = Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]


def run_signal_provider(caps: CapabilitiesFunc, emit: Optional[EmitFunc] = None) -> None:
    """Run the stdio-JSON loop for a signal_provider.

    Protocol:
      {"op": "capabilities"} → respond with capabilities.
      Any other JSON object → treat as a native source event; call emit(event)
                              and write the returned sir.signal.v0 to stdout.
                              If emit returns None the event is silently dropped.
    """
    _run_loop_signal(sys.stdin, sys.stdout, caps, emit)


def run_effect_provider(caps: CapabilitiesFunc, handle_effect: EffectFunc) -> None:
    """Run the stdio-JSON loop for an effect_provider."""
    _run_loop_effect(sys.stdin, sys.stdout, caps, handle_effect)


AdvisoryFunc = Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]


def run_advisory_provider(caps: CapabilitiesFunc, assess: AdvisoryFunc) -> None:
    """Run the stdio-JSON loop for an advisory_provider.

    Protocol:
      {"op": "capabilities"}          → respond with capabilities dict.
      {"op": "assess", ...fields}     → call assess(request) and write
                                        sir.advisory_signal.v0 to stdout.
                                        Return None to emit no signal (low risk assumed).

    The assess function receives a sir.advisory_request.v0 dict:
      action              — verb: "push_origin", "read_ref", "net_external", ...
      target              — file path, remote name, URL, command
      resolved_actor      — "ai_coding_agent" | "human_developer" | "unknown"
      attribution_confidence — "high" | "medium" | "low" | "unknown"
      taint               — ["credential_access", "untrusted_content", ...]
      enforceability      — "enforces" | "detects" | "blind"
      mode                — "guard" | "observe" | ...

    Use sir_sdk.advisory_signal() to build the return value.

    Advisory providers can RAISE risk but NEVER lower deterministic risk (PRD §10.6-7).
    A high-risk signal escalates allow → ask. It cannot change deny → allow.

    Example:
        def assess(req):
            cmd = req.get("target", "")
            if "rm -rf" in cmd or "sudo" in cmd:
                return sir_sdk.advisory_signal(
                    PROVIDER_NAME, sir_sdk.RISK_HIGH,
                    reason="high-risk shell pattern detected",
                )
            return sir_sdk.advisory_signal(PROVIDER_NAME, sir_sdk.RISK_LOW)

        sir_sdk.run_advisory_provider(caps, assess)
    """
    _run_loop_advisory(sys.stdin, sys.stdout, caps, assess)


PolicyFunc = Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]


def run_policy_provider(caps: CapabilitiesFunc, evaluate: PolicyFunc) -> None:
    """Run the stdio-JSON loop for a policy_provider.

    Protocol:
      {"op": "capabilities"}          → respond with capabilities dict.
      {"op": "evaluate", ...fields}   → call evaluate(request) and write
                                        sir.policy_verdict.v0 to stdout.
                                        Return None to emit no verdict (allow by default).

    The evaluate function receives a sir.policy_request.v0 dict with these fields
    (see schemas/sir.policy_request.v0.schema.json for full spec):
      action              — verb: "push_origin", "read_ref", "net_external", ...
      target              — file path, remote name, URL, command
      resolved_actor      — "ai_coding_agent" | "human_developer" | "unknown"
      attribution_confidence — "high" | "medium" | "low" | "unknown"
      taint               — ["credential_access", "untrusted_content", ...]
      enforceability      — "enforces" | "detects" | "blind"
      mode                — "guard" | "observe" | ...

    Use sir_sdk.policy_verdict() to build the return value.

    Example:
        def evaluate(req):
            if "credential_access" in req.get("taint", []):
                return sir_sdk.policy_verdict(
                    PROVIDER_NAME, sir_sdk.VERDICT_ASK,
                    rules_matched=["tainted-session-push"],
                )
            return None  # allow

        sir_sdk.run_policy_provider(caps, evaluate)
    """
    _run_loop_policy(sys.stdin, sys.stdout, caps, evaluate)


def _run_loop_signal(inp: Any, out: Any, caps: CapabilitiesFunc, emit: Optional[EmitFunc]) -> None:
    for raw in inp:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if msg.get("op") == "capabilities":
            print(json.dumps(caps()), file=out, flush=True)
        elif emit is not None:
            signal = emit(msg)
            if signal is not None:
                print(json.dumps(signal), file=out, flush=True)


def _run_loop_advisory(inp: Any, out: Any, caps: CapabilitiesFunc, assess: AdvisoryFunc) -> None:
    for raw in inp:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if msg.get("op") == "capabilities":
            print(json.dumps(caps()), file=out, flush=True)
        elif msg.get("op") == "assess":
            signal = assess(msg)
            if signal is not None:
                print(json.dumps(signal), file=out, flush=True)


def _run_loop_policy(inp: Any, out: Any, caps: CapabilitiesFunc, evaluate: PolicyFunc) -> None:
    for raw in inp:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if msg.get("op") == "capabilities":
            print(json.dumps(caps()), file=out, flush=True)
        elif msg.get("op") == "evaluate":
            verdict = evaluate(msg)
            if verdict is not None:
                print(json.dumps(verdict), file=out, flush=True)


def _run_loop_effect(inp: Any, out: Any, caps: CapabilitiesFunc, handle_effect: EffectFunc) -> None:
    for raw in inp:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if msg.get("op") == "capabilities":
            print(json.dumps(caps()), file=out, flush=True)
        elif msg.get("schema_version") == SCHEMA_EFFECT_REQ_V0:
            result = handle_effect(msg)
            print(json.dumps(result), file=out, flush=True)
