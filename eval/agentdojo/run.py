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
    """Pull utility + ASR out of AgentDojo's result object, tolerant to shape.

    AgentDojo returns per-(task, injection) outcomes; the exact attribute names
    have varied across releases, so we probe a few. Adjust here if your installed
    version differs (the field meanings are stable: utility = benign task solved,
    security = injection NOT triggered)."""
    def _mean(xs):
        xs = list(xs)
        return round(sum(1 for x in xs if x) / len(xs), 4) if xs else None

    # Common shapes: dict with "utility_results" / "security_results" mapping
    # (task_id, injection) -> bool.
    util = getattr(results, "utility_results", None)
    sec = getattr(results, "security_results", None)
    if util is None and isinstance(results, dict):
        util = results.get("utility_results")
        sec = results.get("security_results")
    summary = {}
    if util is not None:
        summary["utility"] = _mean(util.values())
    if sec is not None:
        # AgentDojo "security" True == attack blocked; ASR == 1 - security.
        blocked = _mean(sec.values())
        summary["attack_blocked"] = blocked
        summary["targeted_asr"] = round(1 - blocked, 4) if blocked is not None else None
    if not summary:
        summary["raw"] = str(results)[:500]
    return summary


if __name__ == "__main__":
    raise SystemExit(main())
