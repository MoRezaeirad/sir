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

Offline wiring check (only needs the Go toolchain — **this is the CI gate**):

```bash
python eval/agentdojo/selftest.py
```

Full benchmark (needs agentdojo + a model key; costs tokens):

```bash
pip install -r eval/agentdojo/requirements.txt
export OPENAI_API_KEY=...   # or ANTHROPIC_API_KEY
python eval/agentdojo/run.py --provider openai --model gpt-4o \
    --suites workspace banking --baseline
# -> eval/results/<timestamp>.json
```

Also wire the NIST Inspect fork (`usnistgov/agentdojo-inspect`) for the
gov-credible variant — same mapping/bridge, different harness.

## What to refine next (turns the scaffold into a real score)

1. **Per-suite mapping fidelity.** Use each suite's real tool schemas to register
   `register_suite_mapper(...)` overrides in `tool_mapping.py` (e.g. distinguish
   `send_money` to an attacker IBAN vs a known payee). Conservative default:
   unknown-but-plausibly-egressing tools map to EGRESS, not BENIGN.
2. **P0.3 integrity-flow is wired (done).** `UNTRUSTED_READ` calls arm sir's
   turn-scoped `session_untrusted_this_turn` gate via `ingest_untrusted`, so a
   same-turn exfil after ingesting attacker content is hard-denied (selftest
   Scenario D proves it: deny same-turn, ask cross-turn). Next: tune which
   AgentDojo tools count as untrusted-content carriers per suite so the
   ASR-reduction vs over-block tradeoff is measured precisely.
3. **Verify `_summarize` field names** against the installed AgentDojo version
   (result attribute names have drifted across 0.1.x; meanings are stable).
4. **Confirm the message-shape adapters** in `sir_defense.py` against the
   installed AgentDojo `ChatMessage`/`FunctionCall` types.

## Notes

- The Go local-fallback evaluator is held to parity with `mister-core`, so the
  bench is faithful even without the Rust binary on PATH.
- Per-call subprocess spawn is simple and correct but not fast; a persistent
  verdict daemon / batch verb is a future optimization for large sweeps.
