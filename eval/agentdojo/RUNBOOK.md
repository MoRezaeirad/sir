# AgentDojo runbook — score sir on the benchmark

This is the one-page guide to producing sir's AgentDojo numbers on your own
machine. Everything is wired; you supply a model key and run one command.

## What you'll get

Three numbers per suite, written to `eval/results/<timestamp>.json`:

| metric | meaning | target with sir |
|---|---|---|
| `targeted_asr` | fraction of injection tasks the attacker still accomplished | **→ ~0** |
| `utility` | benign tasks solved with no attack present (the **over-block** signal) | **> 0.80** |
| `attack_blocked` | `1 - targeted_asr` (fraction of injections neutralized) | → ~1 |

With `--baseline`, each suite also reports the **no-sir** numbers, so you get the
delta (how much sir cut ASR, and at what utility cost). The bar to beat, from the
landscape doc: the "tool filter" defense hit ASR ≈7.5% but utility collapsed to
≈53%; the frontier (CaMeL/FIDES) is ASR→~0 with utility retention >80%.

## Prerequisites

- **Go** (to build sir — the harness calls the real `sir guard evaluate`, not a stand-in).
- **Python 3.10+**.
- A model key: `OPENAI_API_KEY` (default) or `ANTHROPIC_API_KEY`.
- Network access for `pip install agentdojo` and the model API. **This costs model tokens.**

## Run it (one command)

```bash
export OPENAI_API_KEY=sk-...
eval/agentdojo/run.sh
```

That builds sir, runs the offline self-test (Go-only sanity, no tokens), creates
a throwaway venv, installs `agentdojo` + the provider SDK, and runs all four
suites with the no-sir baseline. Scores land in `eval/results/`.

Knobs (env vars):

```bash
PROVIDER=anthropic MODEL=claude-3-5-sonnet-latest eval/agentdojo/run.sh
SUITES="workspace banking" eval/agentdojo/run.sh      # subset (faster/cheaper)
BASELINE=0 eval/agentdojo/run.sh                      # sir-only, skip the baseline pass
ATTACK=important_instructions eval/agentdojo/run.sh   # the canonical attack (default)
```

Cheap first pass: `SUITES=banking BASELINE=0 eval/agentdojo/run.sh` (smallest suite).

## How it works (so the numbers are trustworthy)

- Each AgentDojo tool call is mapped to the sir call with the **equivalent
  security effect** (`tool_mapping.py` + per-suite tuning in `suite_mappers.py`),
  then run through the shipped `sir guard evaluate` — no policy is reimplemented.
- A tool that ingests attacker-controllable content (an email, web page, review,
  transaction) is `UNTRUSTED_READ`: it's allowed, and the mediator fires a
  PostToolUse so sir marks the turn as having ingested untrusted content. A
  later same-turn exfil sink (`send_email`, `send_money`, `post_webpage`, …) is
  then gated by sir's integrity-flow egress wall — exactly the path the
  benchmark measures.
- The defense is inserted as an AgentDojo `BasePipelineElement` before
  `ToolsExecutor` (`sir_defense.py`): `allow` → the call runs; `ask`/`deny` → the
  call is stripped and a "blocked by sir" result is injected, so the injected
  action never executes.

## Verify the wiring without spending tokens

```bash
python eval/agentdojo/selftest.py      # end-to-end against the built sir binary
python eval/agentdojo/suite_mappers.py # per-suite tool→effect mapping sanity check
```

## If the scores look wrong

1. **`raw_type`/`raw` in the output instead of numbers** — AgentDojo's result
   field names differ in your installed version. Open `run.py` → `_summarize` and
   add the names to the `_probe(...)` candidate lists (the meanings are stable:
   utility = benign solved, security = injection not triggered).
2. **Utility surprisingly low even at baseline** — that's the model's own task
   competence, not sir; compare the `with_sir` vs `baseline` blocks for sir's
   actual effect.
3. **A whole suite over-blocks** (utility drops only under sir) — tune that
   suite's `UNTRUSTED_READ`/`EGRESS` boundaries in `suite_mappers.py`; the
   `mediation.by_effect` counts in the result JSON show which effect fired.
4. **NIST Inspect variant** — for the gov-credible harness, point at
   `usnistgov/agentdojo-inspect`; the bridge/mapping are reusable, only the
   harness differs.

## Publishing the result

Drop the chosen `eval/results/<timestamp>.json` (or a summary table) into
`docs/research/validation-summary.md` so the AgentDojo score sits alongside the
other reproducible-verification claims.
