# OPA as an authoritative SIR policy provider

This wires [Open Policy Agent](https://www.openpolicyagent.org/) into SIR as an
**authoritative** `policy_provider`: its Rego verdict **replaces** SIR's native
decision — it can GRANT actions native would gate, RESTRICT actions native would
allow, and (because authoritative mode turns the native floors off) it
RE-IMPLEMENTS the exfiltration wall itself.

It runs OPA **warm** (a localhost sidecar) and queries it over HTTP, so each
decision is a sub-millisecond round-trip on the live path — the recommended shape
for an authoritative provider (a cold `opa eval` spawn per call would add
friction and, under fail-closed, latency).

## Files

| File | Purpose |
|---|---|
| `provider.py` | The SIR↔OPA bridge (uses `sir_sdk`, POSTs the request to the warm OPA server). |
| `sir_sdk.py` | Vendored copy of the SDK so this provider imports it on any install (pinned to `sdk/python/sir_sdk.py`). |
| `policy/sir.rego` | The sir-domain policy: grants, restricts (agents / skills / MCPs / hooks), and re-implemented integrity floors. |
| `provider.yaml` | The SIR provider manifest. |
| `fixtures/` | Sample `sir.policy_request`s for `sir provider test`. |

## Prerequisites

```sh
brew install opa            # or https://www.openpolicyagent.org/docs/latest/#1-download-opa
```

## 1. Start OPA warm (sidecar)

From this directory:

```sh
opa run --server --addr 127.0.0.1:8181 policy/
```

Leave it running. Edit `policy/sir.rego` freely — OPA hot-reloads it.

## 2. Wire it into SIR

SIR adds the provider's own directory (and the bundled `sdk/python`) to the
provider's `PYTHONPATH` automatically when it spawns it, so `import sir_sdk`
resolves with no manual env — this directory ships a vendored `sir_sdk.py` for
exactly that reason. No `PYTHONPATH` needed:

```sh
bin/sir provider install examples/providers/opa-authoritative/provider.yaml
bin/sir provider use opa-authoritative
bin/sir provider authoritative opa-authoritative --on-failure deny
bin/sir provider status opa-authoritative        # → Authority: AUTHORITATIVE
```

`--on-failure deny` means: if OPA is ever unreachable, SIR denies (fail closed).
Use `ask` for a softer posture.

## 3. What the policy does

- **GRANT** (native asks; OPA allows on a clean session): `run_ephemeral` (npx),
  `mcp_network_unapproved` (MCP arg URLs), `net_external` to an org-approved host.
- **RESTRICT** (org rules native does not have): deny AI agents reading raw
  credential files; deny delegation/subagents after untrusted-content ingestion;
  deny a denylist of skills; always-ask on `sir_self`; hard-deny detected MCP
  credential-leak / injection.
- **RE-IMPLEMENTED FLOORS** (authoritative mode = these are the policy's job):
  secret-in-context → no egress; untrusted-content-ingested → no egress (the
  lethal-trifecta wall); was-secret → re-ask on push. Most-restrictive wins, so a
  floor deny always overrides a grant.

The v1 session signals (`session_secret`, `session_was_secret`,
`session_untrusted_read`, `session_untrusted_this_turn`) are what make the floor
re-implementation possible — without them OPA couldn't see the integrity state.

## 4. Verify it end-to-end

Drive real decisions through SIR's PreToolUse path (`sir guard evaluate`):

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"npx cowsay hi"}}' \
  | bin/sir guard evaluate          # → allow (OPA granted; native would ask)

echo '{"tool_name":"Read","tool_input":{"file_path":"~/.aws/credentials"}}' \
  | bin/sir guard evaluate          # → deny (OPA org rule)
```

**Fail-closed check** — stop the OPA sidecar, then re-run either command: with
`--on-failure deny` the decision becomes `deny` ("authoritative policy provider
… did not return a usable decision"), never a silent allow.

## Notes

- Authority is an **operator act** (`sir provider authoritative`), never something
  the provider claims on the wire.
- SIR keeps a small set of **non-delegable floors** even under PDP (sir
  self-modification, posture-file tamper, …) — see
  [docs/research/pdp-provider-delegation.md](../../../docs/research/pdp-provider-delegation.md).

### How the re-implemented exfil floor stays correct (taint accrual)

The floor keys on `input.session_secret` / `input.session_untrusted_read`, which
SIR populates from session state. Crucially, that state accrues **independently
of who decides** (verified): SIR scans completed tool output for credentials and
marks the session secret at PostToolUse regardless of the PreToolUse verdict, and
a sensitive `read_ref` that the provider *allows* still marks secret (the marker
keys on the final verdict). So an authoritative provider's grant cannot blind the
signal the floor depends on — fact-gathering runs even when the decision is
delegated. (Note: a bare `env_read` like `printenv X` does **not** mark the
session secret pre-execution in SIR — native or authoritative — unless the value
is matched as a credential in the output; this is pre-existing SIR behavior, not
a PDP effect. Egress floors fire on the secret/untrusted signals, so write your
policy against those, not against the assumption that any env read taints.)
