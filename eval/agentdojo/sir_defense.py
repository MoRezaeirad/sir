"""sir_defense — an AgentDojo pipeline element that mediates tool calls through sir.

Integration point
-----------------
AgentDojo composes a defense as a `BasePipelineElement` inside the tool-execution
loop. We insert `SirToolMediator` *before* `ToolsExecutor` so it sees each tool
call the model wants to make. For every pending call it asks sir (via SirBridge +
tool_mapping) for a verdict:

  - allow            -> leave the call in place; ToolsExecutor runs it.
  - ask / deny       -> strip the call and inject a tool result saying sir blocked
                        it, so the *injected* action never executes. The agent
                        sees the block and can continue its legitimate task.

This mirrors how sir behaves in a live Claude Code session (a deny/ask gate at
PreToolUse), so AgentDojo's targeted-ASR metric measures sir's real effect.

`make_sir_pipeline()` wires a standard AgentDojo pipeline with the mediator in
the loop. The AgentDojo public API has shifted across 0.1.x releases, so imports
are done lazily and a clear error is raised if the installed version's surface
differs — the mediator logic itself is version-independent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from sir_bridge import SirBridge, build_sir
from tool_mapping import Effect, map_call_for_suite


def _lazy_agentdojo():
    try:
        from agentdojo.agent_pipeline import (  # type: ignore
            AgentPipeline,
            BasePipelineElement,
            InitQuery,
            SystemMessage,
            ToolsExecutionLoop,
            ToolsExecutor,
        )
        from agentdojo.functions_runtime import FunctionsRuntime  # type: ignore

        return {
            "AgentPipeline": AgentPipeline,
            "BasePipelineElement": BasePipelineElement,
            "InitQuery": InitQuery,
            "SystemMessage": SystemMessage,
            "ToolsExecutionLoop": ToolsExecutionLoop,
            "ToolsExecutor": ToolsExecutor,
            "FunctionsRuntime": FunctionsRuntime,
        }
    except ImportError as e:  # pragma: no cover - depends on optional dep
        raise ImportError(
            "agentdojo is not installed or its API moved. "
            "`pip install -r eval/agentdojo/requirements.txt`. "
            "If the API surface changed, adjust the imports in _lazy_agentdojo(). "
            f"Original error: {e}"
        ) from e


@dataclass
class MediationStats:
    """Per-run tally so the runner can compute over-block / block rates."""

    allowed: int = 0
    asked: int = 0
    denied: int = 0
    by_effect: dict[str, dict[str, int]] = field(default_factory=dict)

    def record(self, effect: str, decision: str) -> None:
        if decision == "allow":
            self.allowed += 1
        elif decision == "ask":
            self.asked += 1
        else:
            self.denied += 1
        bucket = self.by_effect.setdefault(effect, {"allow": 0, "ask": 0, "deny": 0})
        bucket[decision] = bucket.get(decision, 0) + 1


def make_mediator_class():
    """Build SirToolMediator bound to the installed AgentDojo BasePipelineElement."""
    ad = _lazy_agentdojo()
    Base = ad["BasePipelineElement"]

    class SirToolMediator(Base):  # type: ignore[misc, valid-type]
        def __init__(self, bridge: SirBridge, suite: str, stats: MediationStats):
            self.bridge = bridge
            self.suite = suite
            self.stats = stats

        def query(self, query, runtime, env=None, messages=(), extra_args=None):  # noqa: ANN001
            extra_args = dict(extra_args or {})
            messages = list(messages)
            if not messages:
                return query, runtime, env, messages, extra_args

            last = messages[-1]
            tool_calls = _get_tool_calls(last)
            if not tool_calls:
                return query, runtime, env, messages, extra_args

            kept = []
            blocked_results = []
            for call in tool_calls:
                name = _call_name(call)
                args = _call_args(call)
                sc = map_call_for_suite(self.suite, name, args)
                verdict = self.bridge.evaluate(sc.tool_name, sc.tool_input)
                self.stats.record(sc.effect.value, verdict.decision)
                if verdict.decision == "allow":
                    kept.append(call)
                    # A content read that sir allowed still INGESTED untrusted
                    # data: arm the turn-scoped integrity gate so a later
                    # same-turn exfil is blocked. This is the path that makes the
                    # session_untrusted_this_turn gate observable to AgentDojo.
                    if sc.effect is Effect.UNTRUSTED_READ:
                        self.bridge.ingest_untrusted()
                else:
                    blocked_results.append(
                        _make_tool_result(
                            call,
                            f"[sir blocked: {verdict.decision}] {verdict.reason.splitlines()[0] if verdict.reason else ''}",
                        )
                    )

            messages[-1] = _replace_tool_calls(last, kept)
            messages.extend(blocked_results)
            return query, runtime, env, messages, extra_args

    return SirToolMediator


def make_sir_pipeline(base_llm, suite: str, *, system_prompt: str = "", max_iters: int = 15):
    """Compose a standard AgentDojo pipeline with sir mediation in the loop.

    base_llm: an AgentDojo pipeline element that calls the model (e.g.
              OpenAILLM / AnthropicLLM). The caller constructs it so this module
              stays provider-agnostic.
    Returns (pipeline, stats) — read `stats` after running for block/over-block.
    """
    ad = _lazy_agentdojo()
    bridge = SirBridge(sir_bin=build_sir())
    stats = MediationStats()
    Mediator = make_mediator_class()

    elements = []
    if system_prompt:
        elements.append(ad["SystemMessage"](system_prompt))
    elements.append(ad["InitQuery"]())
    elements.append(base_llm)
    loop = ad["ToolsExecutionLoop"](
        [Mediator(bridge, suite, stats), ad["ToolsExecutor"](), base_llm],
        max_iters=max_iters,
    )
    elements.append(loop)
    pipeline = ad["AgentPipeline"](elements)
    pipeline._sir_bridge = bridge  # expose for per-task reset
    return pipeline, stats


# --- message-shape adapters (kept tolerant across AgentDojo versions) ---

def _get_tool_calls(msg: Any) -> list[Any]:
    if isinstance(msg, dict):
        return list(msg.get("tool_calls") or [])
    return list(getattr(msg, "tool_calls", None) or [])


def _call_name(call: Any) -> str:
    if isinstance(call, dict):
        return call.get("function") or call.get("name") or ""
    return getattr(call, "function", None) or getattr(call, "name", "") or ""


def _call_args(call: Any) -> dict[str, Any]:
    if isinstance(call, dict):
        args = call.get("args") or call.get("arguments") or {}
    else:
        args = getattr(call, "args", None) or getattr(call, "arguments", None) or {}
    return dict(args) if isinstance(args, dict) else {"_": str(args)}


def _replace_tool_calls(msg: Any, kept: list[Any]) -> Any:
    if isinstance(msg, dict):
        out = dict(msg)
        out["tool_calls"] = kept
        return out
    try:
        import dataclasses

        if dataclasses.is_dataclass(msg):
            return dataclasses.replace(msg, tool_calls=kept)
    except Exception:
        pass
    try:
        msg.tool_calls = kept  # pydantic/attrs fallback
    except Exception:
        pass
    return msg


def _make_tool_result(call: Any, content: str) -> Any:
    """Synthesize a tool-result message for a blocked call. Shape is intentionally
    minimal/dict-based; AgentDojo's executor reads role + content + a call id."""
    cid = None
    if isinstance(call, dict):
        cid = call.get("id")
    else:
        cid = getattr(call, "id", None)
    return {
        "role": "tool",
        "tool_call_id": cid,
        "content": content,
        "error": content,
    }
