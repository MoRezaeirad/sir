# SIR Documentation

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Install SIR, turn on protection, understand the output |
| [Architecture](architecture.md) | End-to-end pipeline, kernel internals, design principles |
| [Competitive Analysis](competitive-analysis.md) | How sir compares with Edera and Operant AI |
| [API Reference](api.md) | Schemas, provider protocol, CLI commands |
| [SDK Guide](sdk.md) | Build integrations using the Go or Python SDK |
| [Provider Guide](providers.md) | Write and publish new providers |
| [Policy Reference](policy.md) | Policy rules, taint, grants, friction bounding |
| [Observability](observability.md) | JSONL export, OTLP, ledger, harness reports |
| [Security Model](security.md) | Non-negotiables, evasion harness, threat model |
| [Contributing](contributing.md) | How to contribute code, providers, and tests |

> SIR is experimental and in active development on the `sir-v2` branch. Test on your own machine. Run `sir doctor` if anything breaks. [Report issues](https://github.com/somoore/sir/issues).

Start with the [README](../README.md). Then pick the shortest path for your job.

### Use sir
- [Runtime behavior](user/runtime-security-overview.md) — what sir catches at the boundary, and what it doesn't.
- [FAQ](user/faq.md) — daily commands and troubleshooting.
- Agent setup — [Claude Code](user/claude-code-hooks-integration.md) · [Cursor](user/cursor-support.md) · [Gemini CLI](user/gemini-support.md) · [Codex](user/codex-support.md).
- [SIEM integration](user/siem-integration.md) — OTLP attributes, detection IDs, and the Slack relay.

### Contribute
- [CONTRIBUTING.md](../CONTRIBUTING.md) — setup, standards, PR process.
- [first-30-minutes](contributor/first-30-minutes.md) — fast orientation.
- [core-mental-model](contributor/core-mental-model.md) · [security-engineering-core](contributor/security-engineering-core.md) — how decisions are made and where the trust boundary sits.
- [ARCHITECTURE.md](../ARCHITECTURE.md) — system design and invariants.

### Verify the claims
- [Threat model](research/sir-threat-model.md) — attacker model and scope.
- [Security verification guide](research/security-verification-guide.md) — reproduce the guarantees.
- [Observability design](research/observability-design.md) — the three-tier (governance / detection / investigation) model.
