# sir × AgentDojo — benchmark harness (P0.1)

This is the first item from [docs/research/roadmap-to-best.md](../../docs/research/roadmap-to-best.md):
make sir's protection **measurable** against the benchmark the whole field reports
against — [AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich,
NeurIPS 2024 Datasets & Benchmarks; MIT-licensed).

> Status: **scaffold.** The bridge, mapping, defense element, runner, and an
> offline self-test are wired and the self-test passes against the real `sir`
> binary. The AgentDojo tool→sir-verb mapping is intentionally explicit and
> conservative so it can be refined per suite. See "What to refine next".

## Why this exists

CaMeL, FIDES, and every serious runtime defense report on AgentDojo. Without a
number, sir's claims are unfalsifiable to researchers — and sir's own threat
model invites researchers to verify. This harness lets sir be scored on the
three load-bearing metrics:

| metric | meaning | sir target |
|---|---|---|
| **targeted ASR** | attacker's injected task accomplished | **→ ~0** |
| **benign utility** | task solved with no attack present | **>80%** (this is the over-block / false-positive signal) |
| **utility under attack** | task still solved despite the injection | preserved |

The bar to clear (from the landscape doc): the "tool filter" defense hit ASR
≈7.5% but utility collapsed to ≈53%; the CaMeL/FIDES frontier is ASR→~0 with
utility retention >80%. Anything that drops benign utility below ~80% reads as
"too noisy to use".

## How it works (no policy is reimplemented)

```
AgentDojo tool call ──► tool_mapping.py ──► sir_bridge.py ──► `sir guard evaluate`
   (send_email,            (security-effect      (synthesizes the      (REAL classifier
    read_file, ...)         classification)       Claude PreToolUse      + mister-core
                                                   hook payload)          + IFC taint)
                                                        │
                                  allow / ask / deny ◄──┘
```

- **`sir_bridge.py`** — spawns the shipped `sir guard evaluate` per tool call with
  an isolated `SIR_STATE_HOME`, feeds it the exact Claude Code PreToolUse JSON,
  and parses the `permissionDecision`. Fails **closed** (deny) on any unparseable
  response. Session taint accumulates across calls sharing a `session_id`, so the
  *read-then-exfiltrate* (lethal-trifecta) chain is exercised faithfully.
- **`tool_mapping.py`** — maps each AgentDojo tool to the sir call with the
  equivalent **security effect**: `EGRESS` (send/exfil), `SENSITIVE_READ`
  (credentials → SECRET wall), `UNTRUSTED_READ` (reads of attacker-controllable
  content — emails, web pages, documents — the injection carrier), `WRITE`,
  `BENIGN`. AgentDojo tools don't map 1:1 to shell/file ops, so we map by
  *effect* — which is exactly what sir gates. This is the layer to grow.
- **`sir_defense.py`** — `SirToolMediator`, an AgentDojo `BasePipelineElement`
  inserted before `ToolsExecutor`. allow → call runs; ask/deny → call is stripped
  and a "blocked by sir" tool result is injected, so the injected action never
  fires. When an `UNTRUSTED_READ` is allowed, the mediator also calls
  `bridge.ingest_untrusted()` (a PostToolUse) to arm sir's **turn-scoped
  integrity gate** (`session_untrusted_this_turn`), so a later *same-turn* exfil
  is hard-denied even when no secret was read and the heuristic scanner flagged
  nothing. This is what lets AgentDojo measure that gate's ASR/utility impact.
  Mirrors a live Claude Code PreToolUse gate.
- **`run.py`** — runs the suites with/without sir and writes ASR + utility +
  mediation stats to `../results/`.
- **`selftest.py`** — offline, no-network, no-API-key end-to-end check.

## Run it

**Full benchmark — one command** (see [RUNBOOK.md](RUNBOOK.md) for the details):

```bash
export OPENAI_API_KEY=sk-...        # or ANTHROPIC_API_KEY
eval/agentdojo/run.sh               # builds sir, self-tests, installs agentdojo, runs all suites + baseline
# -> eval/results/<timestamp>.json
```

Offline wiring check (only needs the Go toolchain — **this is the CI gate**, no tokens):

```bash
python eval/agentdojo/selftest.py        # end-to-end against the built sir binary
python eval/agentdojo/suite_mappers.py   # per-suite tool→effect mapping sanity check
```

Manual invocation (what `run.sh` calls):

```bash
pip install -r eval/agentdojo/requirements.txt
SIR_BIN=$(go build -o /tmp/sir ./cmd/sir && echo /tmp/sir) \
  python eval/agentdojo/run.py --provider openai --model gpt-4o --suites workspace banking --baseline
```

Per-suite tool→effect tuning lives in [`suite_mappers.py`](suite_mappers.py)
(banking / slack / travel / workspace). Also wire the NIST Inspect fork
(`usnistgov/agentdojo-inspect`) for the gov-credible variant — same
mapping/bridge, different harness.

## Status & what to verify on first run

1. **Per-suite mapping — tuned (done).** `suite_mappers.py` classifies each v1
   suite's injection-carrier reads (`UNTRUSTED_READ`) and exfil sinks (`EGRESS`)
   by their real tool semantics; `python suite_mappers.py` checks the mapping. If
   AgentDojo renames a tool, the substring patterns degrade gracefully to the
   generic classifier — widen the patterns if a key tool slips.
2. **P0.3 integrity-flow — wired (done).** `UNTRUSTED_READ` calls arm sir's
   turn-scoped `session_untrusted_this_turn` gate via `ingest_untrusted`, so a
   same-turn exfil after ingesting attacker content is hard-denied (selftest
   Scenario D: deny same-turn, ask cross-turn).
3. **`_summarize` result parsing — hardened, verify once.** It probes the known
   AgentDojo result field names (attr or dict) and accepts dict/list values. If
   your version exposes different names you'll see `raw_type`/`raw` in the output;
   add the names to the `_probe(...)` lists. See RUNBOOK "If the scores look wrong".
4. **Confirm the message-shape adapters** in `sir_defense.py` against the
   installed AgentDojo `ChatMessage`/`FunctionCall` types (tolerant dict/attr
   access already, but worth a glance on a new major version).

## Notes

- The Go local-fallback evaluator is held to parity with `mister-core`, so the
  bench is faithful even without the Rust binary on PATH.
- Per-call subprocess spawn is simple and correct but not fast; a persistent
  verdict daemon / batch verb is a future optimization for large sweeps.
