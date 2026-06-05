# Cedar as an authoritative SIR policy provider

This wires [Cedar](https://www.cedarpolicy.com/) into SIR as an **authoritative**
`policy_provider`: its Cedar decision **replaces** SIR's native decision — it can
GRANT actions native would gate, RESTRICT actions native would allow, and (because
authoritative mode turns the native floors off) RE-IMPLEMENT the exfiltration wall
in Cedar. It is the Cedar counterpart of
[`../opa-authoritative`](../opa-authoritative/), with the same guarantees.

## The Permit/Forbid → allow/ask/deny problem

Cedar has only **permit** and **forbid** — no "ask". SIR needs three verdicts.
The convention: a `forbid` whose `@id` starts with **`ask:`** maps to SIR's
**ask**; any other forbid → **deny**; permit → **allow**. The bridge reads the
matched policy `@id` from `cedar authorize --verbose`. Cedar's "any forbid
overrides any permit" gives most-restrictive for free, and the bridge prefers a
real deny over an `ask:` forbid when both match. (Verified — see
[VERIFIED_QUERIES.md](VERIFIED_QUERIES.md).)

## Files

| File | Purpose |
|---|---|
| `provider.py` | The SIR↔Cedar bridge (uses `sir_sdk`, runs `cedar authorize --verbose`). |
| `sir_sdk.py` | Vendored copy of the SDK so this provider imports it on any install (pinned to `sdk/python/sir_sdk.py`). |
| `policies/sir.cedar` | The sir-domain policy: grants, restricts (agents/skills/MCPs/hooks), re-implemented floors. |
| `provider.yaml` | The SIR provider manifest. |
| `fixtures/` | Sample `sir.policy_request`s for `sir provider test`. |

## Prerequisites

```sh
cargo install cedar-policy-cli      # provides the `cedar` binary (v4.x)
```

## Wire it into SIR

SIR adds the provider's own directory (and the bundled `sdk/python`) to the
provider's `PYTHONPATH` automatically when it spawns it, so `import sir_sdk`
resolves with no manual env — this directory ships a vendored `sir_sdk.py` for
exactly that reason. No `PYTHONPATH` needed:

```sh
bin/sir provider install examples/providers/cedar-authoritative/provider.yaml
bin/sir provider use cedar-authoritative
bin/sir provider authoritative cedar-authoritative --on-failure deny
bin/sir provider status cedar-authoritative        # → Authority: AUTHORITATIVE
```

No sidecar needed — Cedar runs as a fast local `cedar authorize` per call. (If
you want warmth, a cedar-agent HTTP server can be swapped in via the bridge.)

## What the policy does

Same three sections as the OPA example:

- **GRANT** (native asks; Cedar permits on a clean session): `run_ephemeral`,
  `mcp_network_unapproved`.
- **RESTRICT**: deny AI agents reading raw credential files; deny delegation after
  untrusted ingestion; deny a denylist of skills (`like "*data-exfil*"`);
  **ask** on `sir_self`; hard-deny detected MCP credential-leak / injection.
- **RE-IMPLEMENTED FLOORS** (authoritative = these are the policy's job):
  `session_secret` → no egress; `session_untrusted_read/this_turn` → no egress;
  `session_was_secret` → **ask** on push.

The v1 session signals are passed in Cedar `context` (the bridge adds them), which
is what makes the floor re-implementation possible. Because Cedar's string ops are
limited, the bridge also pre-computes a couple of helpers (`target_is_credential`,
`target_lower`) into `context` for the policy to read.

## Query Cedar directly

```sh
echo '[]' > /tmp/entities.json
echo '{"session_secret":true}' > /tmp/ctx.json
cedar authorize --verbose \
  --policies policies/sir.cedar --entities /tmp/entities.json \
  --principal 'SIR::Actor::"ai_coding_agent"' \
  --action    'SIR::Action::"net_external"' \
  --resource  'SIR::Target::"https://api.github.com"' \
  --context   /tmp/ctx.json
# → DENY  +  "note: … policies: floor-secret-egress"
```

## Verify it end-to-end

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"npx create-react-app x"}}' \
  | bin/sir guard evaluate         # → allow (Cedar granted; native would ask)

echo '{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}' \
  | bin/sir guard evaluate         # → deny (Cedar org rule)
```

**Fail-closed check** — with `--on-failure deny`, if `cedar` is unavailable the
decision is `deny`, never a silent allow (verified with `CEDAR_BIN=/nonexistent`).

See [VERIFIED_QUERIES.md](VERIFIED_QUERIES.md) for the full tested matrix, and
[docs/research/pdp-provider-delegation.md](../../../docs/research/pdp-provider-delegation.md)
for the PDP scope and non-delegable floors.
