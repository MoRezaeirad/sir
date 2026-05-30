"""run — execute the AgentDojo benchmark with sir mediation and write scores.

This is the real benchmark entrypoint (requires `pip install agentdojo` and a
model API key for the provider you choose). It runs AgentDojo's suites with the
canonical injection attack, once WITHOUT sir and once WITH the sir mediator, and
reports the three load-bearing metrics from docs/research/competitive-analysis.md:

    targeted ASR  (attacker task accomplished)        -> want near 0 with sir
    benign utility (task solved, no attack)           -> over-block signal, want >80%
    utility under attack (task solved despite attack) -> want preserved

Results land in eval/results/<timestamp>.json.

Usage:
    python eval/agentdojo/run.py --provider openai --model gpt-4o \\
        --suites workspace banking --attack important_instructions

NOTE: This harness does not ship model credentials. CI runs selftest.py (which
needs only Go); the full AgentDojo run is a scheduled/manual job because it costs
model tokens. See README.md.
"""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path

# Importing suite_mappers registers the per-suite tool→effect tuning for the four
# AgentDojo v1 suites (banking, slack, travel, workspace). Side-effecting import.
import suite_mappers  # noqa: F401

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


def _build_base_llm(provider: str, model: str):
    """Construct the provider LLM pipeline element. Imports are lazy so the file
    loads without provider SDKs installed."""
    if provider == "openai":
        from agentdojo.agent_pipeline import OpenAILLM  # type: ignore
        import openai  # type: ignore

        return OpenAILLM(openai.OpenAI(), model)
    if provider == "anthropic":
        from agentdojo.agent_pipeline import AnthropicLLM  # type: ignore
        import anthropic  # type: ignore

        return AnthropicLLM(anthropic.Anthropic(), model)
    raise SystemExit(f"unknown provider {provider!r} (expected openai|anthropic)")


def run_suite(suite_name: str, base_llm, attack_name: str, with_sir: bool):
    """Run one AgentDojo suite, optionally wrapping the pipeline with sir.

    Returns the AgentDojo benchmark result object for this suite.
    """
    from agentdojo.benchmark import benchmark_suite_with_injections  # type: ignore
    from agentdojo.task_suite.load_suites import get_suite  # type: ignore

    suite = get_suite("v1", suite_name)

    if with_sir:
        from sir_defense import make_sir_pipeline

        pipeline, stats = make_sir_pipeline(base_llm, suite_name)
    else:
        from agentdojo.agent_pipeline import (  # type: ignore
            AgentPipeline,
            InitQuery,
            ToolsExecutionLoop,
            ToolsExecutor,
        )

        pipeline = AgentPipeline(
            [InitQuery(), base_llm, ToolsExecutionLoop([ToolsExecutor(), base_llm])]
        )
        stats = None

    results = benchmark_suite_with_injections(
        pipeline, suite, attack=attack_name, logdir=None, force_rerun=False
    )
    return results, stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--provider", default="openai", choices=["openai", "anthropic"])
    ap.add_argument("--model", default="gpt-4o")
    ap.add_argument("--suites", nargs="+", default=["workspace", "banking", "slack", "travel"])
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--baseline", action="store_true", help="also run the no-sir baseline for delta")
    args = ap.parse_args()

    base_llm = _build_base_llm(args.provider, args.model)

    report: dict = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "provider": args.provider,
        "model": args.model,
        "attack": args.attack,
        "suites": {},
    }

    for suite in args.suites:
        entry: dict = {}
        if args.baseline:
            base_res, _ = run_suite(suite, base_llm, args.attack, with_sir=False)
            entry["baseline"] = _summarize(base_res)
        sir_res, stats = run_suite(suite, base_llm, args.attack, with_sir=True)
        entry["with_sir"] = _summarize(sir_res)
        if stats is not None:
            entry["mediation"] = {
                "allowed": stats.allowed,
                "asked": stats.asked,
                "denied": stats.denied,
                "by_effect": stats.by_effect,
            }
        report["suites"][suite] = entry
        print(f"[{suite}] {json.dumps(entry, indent=2)}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / (datetime.datetime.now().strftime("%Y%m%dT%H%M%S") + ".json")
    out.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {out}")
    return 0


def _summarize(results) -> dict:
    """Pull utility + targeted-ASR out of AgentDojo's result object, tolerant to
    shape. AgentDojo returns per-(task, injection) outcomes; attribute/field names
    have varied across 0.1.x, so we probe several. The field MEANINGS are stable:
    utility = benign task solved; security = injection NOT triggered, so
    targeted ASR = 1 - mean(security). If your installed version exposes different
    names, add them to the candidate lists below."""

    def _bools(x):
        # Accept a dict (use .values()), a list/tuple/iterable of bools, or None.
        if x is None:
            return None
        if isinstance(x, dict):
            return list(x.values())
        try:
            return list(x)
        except TypeError:
            return None

    def _mean(x):
        xs = _bools(x)
        if not xs:
            return None
        return round(sum(1 for v in xs if v) / len(xs), 4)

    def _probe(*names):
        for n in names:
            v = getattr(results, n, None)
            if v is None and isinstance(results, dict):
                v = results.get(n)
            if v is not None:
                return v
        return None

    util = _probe("utility_results", "utility", "utilities")
    sec = _probe("security_results", "security", "securities")

    summary: dict = {}
    if util is not None:
        summary["utility"] = _mean(util)
    if sec is not None:
        blocked = _mean(sec)  # mean(security) == fraction of attacks NOT triggered
        summary["attack_blocked"] = blocked
        summary["targeted_asr"] = round(1 - blocked, 4) if blocked is not None else None
    if not summary:
        # Last resort: surface the object so the field names can be read off and
        # added to the candidate lists above.
        summary["raw_type"] = type(results).__name__
        summary["raw"] = str(results)[:800]
    return summary


if __name__ == "__main__":
    raise SystemExit(main())
