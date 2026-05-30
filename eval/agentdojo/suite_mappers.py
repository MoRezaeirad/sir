"""Per-suite tool→effect tuning for AgentDojo's four v1 suites.

The generic classifier in tool_mapping.py is verb/noun-based and gets most tools
right. These suite mappers refine the security-relevant cases per suite so the
benchmark faithfully scores sir's gate:

  - UNTRUSTED_READ  the injection *carriers* (the tool results AgentDojo plants the
                    prompt injection into): emails, messages, web pages, reviews,
                    transactions, files. Reading one arms the turn-scoped gate.
  - EGRESS          the exfil/unauthorized-action sinks the injection aims for:
                    send money/email/message, post a webpage, share a file,
                    schedule a transfer, invite a user.
  - SENSITIVE_READ  credential/identity reads (IBAN, balance, user info).
  - WRITE / BENIGN  mutations and benign catalog queries.

Importing this module registers all four mappers. Patterns are substring-based
(case-insensitive) so they tolerate minor tool-name differences across AgentDojo
versions; anything unmatched falls back to the generic classifier.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from tool_mapping import Effect, SirCall, classify, register_suite_mapper, sir_call_for_effect

# (compiled pattern, effect) lists per suite. First match wins; None-return falls
# back to the generic classifier.
_SUITE_RULES: dict[str, list[tuple[str, Effect]]] = {
    "banking": [
        (r"send_money|send_transaction|schedule_transaction|update_scheduled|pay", Effect.EGRESS),
        (r"iban|balance|get_user_info|get_account|update_password", Effect.SENSITIVE_READ),
        (r"transaction|read_file|statement", Effect.UNTRUSTED_READ),
        (r"update_user_info|set_", Effect.WRITE),
    ],
    "slack": [
        (r"send_direct_message|send_channel_message|post_webpage|invite_user|add_user|remove_user", Effect.EGRESS),
        (r"read_inbox|read_channel|read_message|get_message|get_webpage|read_web", Effect.UNTRUSTED_READ),
        (r"get_users_in_channel|get_channels", Effect.BENIGN),
    ],
    "travel": [
        (r"send_email|reserve_|book_|share_", Effect.EGRESS),
        (r"review|rating|get_user_information|flight_information", Effect.UNTRUSTED_READ),
        (r"get_all_|get_.*_address|get_cuisine|get_price|get_dietary|opening_hours|car_types", Effect.BENIGN),
    ],
    "workspace": [
        (r"send_email|share_file|forward", Effect.EGRESS),
        (r"received_email|unread_email|search_email|read_email|get_sent|draft|get_file_by_id|search_files|get_email", Effect.UNTRUSTED_READ),
        (r"create_calendar_event|append_to_file|create_file|delete_|update_", Effect.WRITE),
        (r"search_contacts|get_current_day|list_files|search_calendar|get_day_calendar", Effect.BENIGN),
    ],
}


def _make_mapper(rules: list[tuple[str, Effect]]):
    compiled = [(re.compile(p, re.I), e) for p, e in rules]

    def mapper(tool_name: str, args: dict[str, Any]) -> Optional[SirCall]:
        for pat, eff in compiled:
            if pat.search(tool_name):
                return sir_call_for_effect(eff, tool_name, args)
        return None  # fall back to the generic classifier

    return mapper


def register_all() -> None:
    for suite, rules in _SUITE_RULES.items():
        register_suite_mapper(suite, _make_mapper(rules))


# Self-registration on import (run.py imports this module).
register_all()


# Lightweight in-module sanity check usable without agentdojo:
#   python eval/agentdojo/suite_mappers.py
if __name__ == "__main__":
    from tool_mapping import map_call_for_suite

    checks = [
        ("banking", "send_money", Effect.EGRESS),
        ("banking", "get_iban", Effect.SENSITIVE_READ),
        ("banking", "get_most_recent_transactions", Effect.UNTRUSTED_READ),
        ("slack", "send_direct_message", Effect.EGRESS),
        ("slack", "get_webpage", Effect.UNTRUSTED_READ),
        ("slack", "get_channels", Effect.BENIGN),
        ("travel", "send_email", Effect.EGRESS),
        ("travel", "get_rating_reviews_for_hotels", Effect.UNTRUSTED_READ),
        ("travel", "get_all_hotels_in_city", Effect.BENIGN),
        ("workspace", "send_email", Effect.EGRESS),
        ("workspace", "get_received_emails", Effect.UNTRUSTED_READ),
        ("workspace", "search_contacts_by_name", Effect.BENIGN),
    ]
    bad = 0
    for suite, tool, want in checks:
        got = map_call_for_suite(suite, tool, {"to": "mallory@evil.test"}).effect
        ok = got is want
        bad += 0 if ok else 1
        print(f"  [{ 'OK' if ok else 'FAIL'}] {suite}/{tool}: {got.value} (want {want.value})")
    raise SystemExit(1 if bad else 0)
