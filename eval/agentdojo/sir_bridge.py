"""sir_bridge — call sir's *real* decision path from Python.

This module is the seam between AgentDojo (Python) and sir (Go + Rust). It does
NOT reimplement any policy. It synthesizes the exact PreToolUse hook payload that
Claude Code would emit, pipes it to `sir guard evaluate` on stdin, and parses the
allow/ask/deny verdict back out. That means the benchmark measures sir's shipped
classifier + `mister-core` oracle + IFC taint, not a stand-in.

Contract (verified against the binary):
  stdin  -> {"session_id","hook_event_name":"PreToolUse","tool_name","tool_input":{...},"cwd"}
  stdout -> {"hookSpecificOutput":{"permissionDecision":"allow|ask|deny","permissionDecisionReason":...}}

State is isolated per benchmark run via SIR_STATE_HOME so scenarios start clean,
and session taint (read .env -> later egress) accumulates across calls that share
a session_id within one task. See README.md for the design rationale.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]


def build_sir(binary_out: Optional[Path] = None) -> Path:
    """Build the sir binary from this repo and return its path.

    Honors SIR_BIN if set (skip the build, use an existing binary). The Go
    local-fallback evaluator is held to parity with mister-core, so the bench
    is faithful even when the Rust oracle binary is not on PATH.
    """
    env_bin = os.environ.get("SIR_BIN")
    if env_bin:
        p = Path(env_bin)
        if not p.exists():
            raise FileNotFoundError(f"SIR_BIN={env_bin} does not exist")
        return p
    out = binary_out or Path(tempfile.gettempdir()) / "sir-agentdojo-eval"
    subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/sir"],
        cwd=str(REPO_ROOT),
        check=True,
    )
    return out


# sir's verdict strings (pkg/policy/surface_gen.go).
ALLOW = "allow"
ASK = "ask"
DENY = "deny"


@dataclass
class Verdict:
    decision: str  # allow | ask | deny
    reason: str
    tool_name: str
    tool_input: dict[str, Any]

    @property
    def blocked(self) -> bool:
        """A defense that needs determinism treats both ask and deny as blocked.

        AgentDojo has no human to answer an `ask`; in a real Claude Code session
        an `ask` is an interactive approval gate. For benchmarking the *security*
        claim we conservatively count ask+deny as "the injected action did not
        silently proceed". Report ask and deny separately too (see metrics).
        """
        return self.decision in (ASK, DENY)


@dataclass
class SirBridge:
    """Spawns `sir guard evaluate` per tool call against an isolated state home.

    One SirBridge instance == one isolated sir environment. Create a fresh bridge
    (or call .reset()) per AgentDojo task so taint does not leak between tasks.
    """

    sir_bin: Path
    state_home: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="sir-state-")))
    workspace: Path = field(default_factory=lambda: Path(tempfile.mkdtemp(prefix="sir-work-")))
    session_id: str = field(default_factory=lambda: f"agentdojo-{uuid.uuid4().hex[:12]}")
    timeout_s: float = 15.0

    def reset(self) -> None:
        """Start a clean session/state for a new task (no cross-task taint)."""
        self.state_home = Path(tempfile.mkdtemp(prefix="sir-state-"))
        self.workspace = Path(tempfile.mkdtemp(prefix="sir-work-"))
        self.session_id = f"agentdojo-{uuid.uuid4().hex[:12]}"

    def evaluate(self, tool_name: str, tool_input: dict[str, Any]) -> Verdict:
        payload = {
            "session_id": self.session_id,
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input,
            "cwd": str(self.workspace),
        }
        env = dict(os.environ)
        env["SIR_STATE_HOME"] = str(self.state_home)
        proc = subprocess.run(
            [str(self.sir_bin), "guard", "evaluate"],
            input=json.dumps(payload).encode(),
            cwd=str(self.workspace),
            env=env,
            capture_output=True,
            timeout=self.timeout_s,
        )
        decision, reason = _parse_verdict(proc.stdout)
        return Verdict(decision=decision, reason=reason, tool_name=tool_name, tool_input=tool_input)

    def ingest_untrusted(self, content: str = "external untrusted content") -> None:
        """Drive a PostToolUse for a WebFetch result so sir marks this turn as
        having ingested untrusted content (session_untrusted_this_turn).

        Same session_id == same turn, so a later evaluate() egress call in the
        same AgentDojo task is gated by the turn-scoped integrity-flow wall —
        even when no secret was read and the heuristic scanner flagged nothing.
        This is what lets AgentDojo measure that gate's ASR/utility impact.
        """
        payload = {
            "session_id": self.session_id,
            "hook_event_name": "PostToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://untrusted.example/doc"},
            "tool_output": content,
            "cwd": str(self.workspace),
        }
        env = dict(os.environ)
        env["SIR_STATE_HOME"] = str(self.state_home)
        subprocess.run(
            [str(self.sir_bin), "guard", "post-evaluate"],
            input=json.dumps(payload).encode(),
            cwd=str(self.workspace),
            env=env,
            capture_output=True,
            timeout=self.timeout_s,
        )


def _parse_verdict(stdout: bytes) -> tuple[str, str]:
    """Parse the Claude PreToolUse wire response. Fail closed on garbage.

    sir already returns well-formed deny JSON on internal error (CLAUDE.md
    non-negotiable #8); if we still cannot parse, we default to deny so a bug
    in the harness can never be scored as a silent allow.
    """
    try:
        obj = json.loads(stdout.decode() or "{}")
        out = obj.get("hookSpecificOutput", {})
        decision = out.get("permissionDecision", DENY)
        reason = out.get("permissionDecisionReason", "")
        if decision not in (ALLOW, ASK, DENY):
            return DENY, f"unrecognized decision {decision!r}"
        return decision, reason
    except (ValueError, AttributeError):
        return DENY, f"unparseable sir response: {stdout!r:.200}"
