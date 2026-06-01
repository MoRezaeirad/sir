# SIR JSON Schemas (v0)

JSON Schema (draft 2020-12) definitions for the SIR provider protocol. These are the canonical data contracts. The Go SDK (`pkg/sdk/`) and Python SDK (`sdk/python/sir_sdk.py`) both implement these contracts.

## Published contracts

| Schema | Description |
|---|---|
| `sir.signal.v0.schema.json` | Raw signal emitted by a signal_provider |
| `sir.provider.v0.schema.json` | Provider manifest declaration |
| `sir.effect_request.v0.schema.json` | Request from SIR kernel to an effect_provider |
| `sir.effect_result.v0.schema.json` | Response from an effect_provider |
| `sir.capabilities.v0.schema.json` | Response to a capabilities query |
| `sir.case.v0.schema.json` | Harness test case with evasion flags |
| `sir.policy_request.v0.schema.json` | Request from SIR kernel to a policy_provider (action, target, actor, taint, enforceability, mode) |
| `sir.policy_verdict.v0.schema.json` | Policy provider verdict (advisory only) |
| `sir.advisory_request.v0.schema.json` | Request from SIR kernel to an advisory_provider (same shape as policy request) |
| `sir.advisory_signal.v0.schema.json` | Advisory provider risk signal |
| `sir.attribution.v0.schema.json` | Attribution result: confidence, methods, ambiguities, spoofing_risk |
| `sir.ledger.v0.schema.json` | Ledger entry: tamper-evident decision record (SIEM exporters depend on this) |
| `sir.enforceability.v0.schema.json` | Enforceability analysis: enforces/detects/blind with reason |
| `sir.action.v0.schema.json` | Correlated attributed action (input to policy evaluation) |

Each published contract has a conformance fixture in `fixtures/` demonstrating a valid instance.

## Internal types (intentionally unpublished)

The following types are computed internally and are not yet published contracts. External providers should not depend on them until published.

| Type | Status | Roadmap note |
|---|---|---|
| `sir.taint` | Internal | Published as `sir.taint.v1` when the taint/grant API stabilizes. Today taint labels are `[]string` carried through the evaluation pipeline; the structured form is not yet stable enough for external consumers. |
| `sir.grant` | Internal | Published as `sir.grant.v1` alongside taint. Grants and taint-clears inherit the attribution confidence context they were created in (narrow scope / short TTL when confidence was low). |

## Attribution contract note

`sir.attribution.v0` describes the full structured form (confidence, methods, ambiguities, spoofing_risk). The current kernel emits attribution as a bare confidence string (`high / medium / low / unknown`) in `sir.ledger.v0`'s `decision.attribution` field. The structured form will replace the bare string in v1. Policy rules may key on the confidence value today; the remaining fields are forward-compatible extensions.

## Stability

All schemas carry a `v0` suffix. They are in active development. Breaking changes are possible. A v1 stability guarantee will be declared when the provider API stabilizes.

See the [API Reference](../docs/api.md) for field-level documentation and examples.
