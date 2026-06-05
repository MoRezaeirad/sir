# Policy as code for AI coding agents — Cedar as an authoritative SIR provider

> **Experimental.** SIR is in active development and not yet suitable for
> production. Authoritative policy delegation is an explicit operator opt-in with
> zero default blast radius. Test on your own machine. See the
> [project warning](../README.md).

## Why this is different

Most agent-security tools can only do one thing: **add friction.** They sit in
front of an action and decide whether to let the native rules also fire. They can
tighten; they can never loosen. The result feels like "gates by default," and the
policy you already maintain for your infrastructure has nothing to say about it.

SIR inverts that. An operator can mark an external policy engine — OPA, Cedar, a
Rego pack — as the **authoritative** `policy_provider`. Its verdict then
**replaces** SIR's native decision. It can:

- **GRANT** an action native would gate (the part no other layer can do),
- **RESTRICT** an action native would allow (org-specific rules native doesn't have),
- **RE-IMPLEMENT the integrity floors** itself — because authoritative mode turns
  native's automatic floors off and hands the policy that job.

This is **PDP (Policy Decision Point) delegation**: the same policy language an org
already runs against its infrastructure now governs agent actions — verbs, skills,
MCP calls, hooks, and IFC taint — as *policy as code*. The policy is the whole
truth for the delegated decision surface.

With Cedar, that policy is written in
[Cedar](https://www.cedarpolicy.com/)'s **principal / action / resource / context**
model: a typed, analyzable, AWS-backed language whose policy set is amenable to
formal reasoning. Cedar is the **Permit/Forbid** counterpart of the
[OPA provider](opa-policy-provider.md) — same guarantees, different engine.

### The Permit/Forbid → allow/ask/deny key design point

Cedar has only **permit** and **forbid** — there is no native "ask". SIR needs
three verdicts. This provider encodes the third one in the policy itself:

> A `forbid` whose `@id` starts with **`ask:`** maps to SIR's **ask**; any other
> forbid maps to **deny**; a permit maps to **allow**.

The bridge reads the matched policy `@id` from `cedar authorize --verbose` and
applies that rule. Cedar's own semantics — "any forbid overrides any permit" —
give most-restrictive ordering for free, and the bridge additionally prefers a
real **deny** over an `ask:` forbid when both match in the same decision. That one
convention is what lets a two-verdict engine drive SIR's three-verdict surface.

Two honest guardrails keep delegation safe:

- **Fail closed.** If the authoritative provider is unreachable, times out, or
  returns empty/malformed output, SIR never silently falls back to allow — it
  holds the action (`ask`, or `deny` in managed mode). Silence is never a grant.
- **A small set of non-delegable floors.** Delegation covers the *core decision*,
  not everything. SIR keeps integrity/tamper floors (sir self-modification,
  posture-file tamper, the exfil wall, and others) that fire regardless of the
  provider's verdict, so PDP can't be turned into a self-amplification or
  exfiltration bypass. The authoritative list of record is
  [docs/research/pdp-provider-delegation.md §7](research/pdp-provider-delegation.md#7-scope--what-pdp-does-not-delegate-non-delegable-floors).

The rest of this guide is the verified, end-to-end walkthrough of building one with
Cedar. The working example lives in
[`examples/providers/cedar-authoritative/`](../examples/providers/cedar-authoritative/).

---

## Build & use a policy-based provider with Cedar

### 1. Prerequisites

```sh
cargo install cedar-policy-cli      # provides the `cedar` binary
```

Verified against **cedar-policy-cli 4.11.0**.

### 2. The bridge — how SIR talks to a provider

A provider is just a process that speaks **stdio-JSON**: SIR writes one JSON
object per line to its stdin, the provider writes one JSON object per line back.
The reference bridge,
[`examples/providers/cedar-authoritative/provider.py`](../examples/providers/cedar-authoritative/provider.py),
uses the `sir_sdk` helper (`sir_sdk.run_policy_provider`) so it only has to
implement two functions: `caps()` and `evaluate(request)`.

The round trip is:

```text
SIR  ──sir.policy_request.v1──▶  provider.py  ──argv + ctx file──▶  cedar authorize --verbose
SIR  ◀──sir.policy_verdict.v0──  provider.py  ◀──ALLOW/DENY + @ids──  cedar
```

Concretely, `evaluate(request)`:

1. receives the `sir.policy_request` dict (v0 fields + v1 session signals),
2. maps it into Cedar's principal/action/resource/context via `map_to_cedar` and
   runs `cedar authorize --verbose`,
3. parses the decision and the matched policy `@ids`, maps them to a SIR verdict,
   and wraps it with `sir_sdk.policy_verdict(...)`.

`map_to_cedar` builds the four Cedar inputs from the request:

| SIR request field | Cedar input | Example |
|---|---|---|
| `resolved_actor` | principal `SIR::Actor::"…"` | `SIR::Actor::"ai_coding_agent"` |
| `action` | action `SIR::Action::"…"` | `SIR::Action::"net_external"` |
| `target` | resource `SIR::Target::"…"` | `SIR::Target::"https://api.github.com"` |
| `taint` | `context.taint` | `["untrusted_content"]` |
| `session_secret` | `context.session_secret` | **v1** — a live secret is in context now |
| `session_was_secret` | `context.session_was_secret` | **v1** — the session ever held a secret (high-water mark) |
| `session_untrusted_read` | `context.session_untrusted_read` | **v1** — untrusted content ingested this session |
| `session_untrusted_this_turn` | `context.session_untrusted_this_turn` | **v1** — untrusted content this turn |

The v1 session signals are what make floor re-implementation possible — without
them Cedar couldn't see the integrity state the native walls key on. SIR populates
them on **every** request regardless of who decides (fact-gathering is never
delegated), so an authoritative grant cannot blind the signals a floor depends on.

Cedar's CLI string operators are limited (no substring `contains`), so the bridge
also **pre-computes a couple of boolean helpers into `context`** that the policy
reads directly: `target_is_credential` (path matches a credential pattern) and
`target_lower` (the lowercased target, for `like "*…*"` wildcard matches).

The contract has one safety-critical rule: when the bridge genuinely cannot run
Cedar (binary missing, timeout, error) it returns **`None`** (no verdict) — it
never invents an `allow`. Under an authoritative registration SIR turns "no
verdict" into a fail-closed `ask`/`deny`, so the bridge never has to guess a safe
default.

> Authority is an **operator act** (`sir provider authoritative`), never a wire
> claim. The bridge's capabilities still declare `is_advisory: true`; the operator
> — not the provider — decides it is authoritative.

### 3. Permit/Forbid → allow/ask/deny in the bridge

The bridge maps Cedar's two-verdict output onto SIR's three verdicts using the
matched `@id`s parsed from `cedar authorize --verbose`:

| Cedar result | Matched `@id` | SIR verdict |
|---|---|---|
| ALLOW (exit 0) | — | **allow** |
| DENY | any `@id` **not** starting `ask:` | **deny** |
| DENY | only `@id`s starting `ask:` | **ask** (prefix stripped) |
| DENY | no identifiable policy | **deny** |

When a decision matches both a real `deny` and an `ask:` forbid, the bridge prefers
the **deny** — most-restrictive wins, so an `ask` can never soften a deny. The
`--verbose` output the bridge parses looks like:

```text
DENY

note: this decision was due to the following policies:
  floor-secret-egress
```

The bridge captures the indented `@id` lines under the `note: … following
policies:` block. An `allow` decision reports `default-permit` (or a matched
grant) the same way.

### 4. Query Cedar directly

Cedar v4.11 reads the entity store and the request `context` from **files**, not
inline strings, so write both to temp files first. From the example directory:

```sh
echo '[]' > /tmp/entities.json
echo '{"session_secret":true}' > /tmp/ctx.json
cedar authorize --verbose \
  --policies policies/sir.cedar --entities /tmp/entities.json \
  --principal 'SIR::Actor::"ai_coding_agent"' \
  --action    'SIR::Action::"net_external"' \
  --resource  'SIR::Target::"https://api.github.com"' \
  --context   /tmp/ctx.json
```

The matched policy is reported in the verbose note:

```text
DENY

note: this decision was due to the following policies:
  floor-secret-egress
```

That `DENY` + `policies: floor-secret-egress` is exactly what `provider.py`'s
`_matched_policy_ids` reads and maps to a SIR `deny`. (An empty `context`, i.e.
`echo '{}' > /tmp/ctx.json`, on the same request reports `ALLOW` via
`default-permit`.)

### 4b. The policy

[`policies/sir.cedar`](../examples/providers/cedar-authoritative/policies/sir.cedar)
is organized in three sections, with a permissive default at the top.

```cedar
// Default: permit. (Demo policy is permissive-by-default; a production egress
// policy would invert this to default-deny. Documented as a policy-author choice.)
@id("default-permit")
permit (principal, action, resource);
```

**A. GRANT** — remove friction native imposes. Grants are `permit`s, still
overridden by any forbid above them (most-restrictive), so a grant can never punch
through a floor:

```cedar
@id("grant-ephemeral-clean")
permit (principal, action == SIR::Action::"run_ephemeral", resource)
when { !context.session_secret && !context.session_untrusted_read && !context.session_untrusted_this_turn };

@id("grant-mcp-network")
permit (principal, action == SIR::Action::"mcp_network_unapproved", resource)
when { !context.session_secret && !context.session_untrusted_read && !context.session_untrusted_this_turn };
```

**B. RESTRICT** — org rules native doesn't enforce. Note the `ask:`-prefixed
forbid for `sir_self`, and that skill denylisting reads the bridge-provided
`target_lower` because Cedar can't substring-match a free-form target:

```cedar
// AI agents may not read raw credential files (uses pre-computed target_is_credential).
@id("deny-agent-credential-read")
forbid (principal == SIR::Actor::"ai_coding_agent", action == SIR::Action::"read_ref", resource)
when { context.target_is_credential };

// sir self-modification is always at least an ask (defense in depth).
@id("ask:sir-self")
forbid (principal, action == SIR::Action::"sir_self", resource);

// Denylisted skills — Cedar `like` wildcard on the bridge-lowercased target.
@id("deny-denylisted-skill")
forbid (principal, action in [SIR::Action::"delegate", SIR::Action::"run_ephemeral", SIR::Action::"execute_dry_run"], resource)
when { context.target_lower like "*data-exfil*" || context.target_lower like "*shell-runner*" || context.target_lower like "*auto-deploy*" };
```

Detected MCP credential-leak and injection are hard denies
(`deny-mcp-credential-leak`, `deny-mcp-injection`).

**C. RE-IMPLEMENTED FLOORS** — authoritative mode makes these the policy's job.
The session-signal floors key on the v1 `context` booleans:

```cedar
// Confidentiality wall: a live secret in context must not reach an external sink.
@id("floor-secret-egress")
forbid (principal, action in [SIR::Action::"net_external", SIR::Action::"dns_lookup", SIR::Action::"push_remote"], resource)
when { context.session_secret };

// Lethal-trifecta exfil leg: untrusted content ingested → hold egress.
@id("floor-untrusted-egress")
forbid (principal, action in [SIR::Action::"net_external", SIR::Action::"dns_lookup", SIR::Action::"push_remote"], resource)
when { context.session_untrusted_read || context.session_untrusted_this_turn };

// High-water mark: a session that EVER held a secret re-prompts on push. ASK.
@id("ask:floor-was-secret-push")
forbid (principal, action in [SIR::Action::"push_origin", SIR::Action::"push_remote"], resource)
when { context.session_was_secret };
```

Because any forbid out-ranks the default permit — and a real deny out-ranks an
`ask:` forbid — a floor `deny` always overrides any GRANT in the same evaluation.

### 5. Wire it into SIR

From the repo root. SIR adds the provider's own directory and the bundled
`sdk/python` to the provider's `PYTHONPATH` automatically (absolute paths) when it
spawns it — including the install health handshake — so you do **not** need to set
`PYTHONPATH` yourself. Vendor `sir_sdk.py` beside your `provider.py`, or rely on
the bundled copy:

```sh
bin/sir provider install examples/providers/cedar-authoritative/provider.yaml
bin/sir provider use cedar-authoritative
bin/sir provider authoritative cedar-authoritative --on-failure deny
bin/sir provider status cedar-authoritative        # → Authority: AUTHORITATIVE
```

`--on-failure deny` means: if Cedar is ever unreachable, SIR denies (fail closed).
Use `ask` for a softer posture. Demote back to advisory any time with
`bin/sir provider advisory cedar-authoritative`.

No sidecar is needed — Cedar runs as a fast local `cedar authorize` per call. (If
you want warmth, a cedar-agent HTTP server can be swapped in behind the bridge.)

### 6. Verified query series

These are **real, tested outputs** captured live against `policies/sir.cedar`
(cedar-policy-cli 4.11.0). They are reproduced from
[`examples/providers/cedar-authoritative/VERIFIED_QUERIES.md`](../examples/providers/cedar-authoritative/VERIFIED_QUERIES.md);
do not hand-edit — re-run to refresh.

**Bridge decisions** (`cedar authorize --verbose` mapped to allow/ask/deny):

| Scenario | Request (abbrev) | Verdict | Rule fired |
|---|---|---|---|
| **Agents** | | | |
| agent reads `~/.aws/credentials` | `action=read_ref`, `actor=ai_coding_agent` | **DENY** | `deny-agent-credential-read` |
| human reads `~/.aws/credentials` | `action=read_ref`, `actor=human_developer` | ALLOW | `default-permit` |
| **Skills** | | | |
| denylisted skill data-exfil | `action=delegate`, `target=…data-exfil…` | **DENY** | `deny-denylisted-skill` |
| **MCP** | | | |
| mcp network arg-url (clean) | `action=mcp_network_unapproved`, clean | **ALLOW** | `grant-mcp-network` |
| mcp injection detected | `action=mcp_injection_detected` | **DENY** | `deny-mcp-injection` |
| **Hooks / sir-self** | | | |
| sir self-modification | `action=sir_self` | **ASK** | `sir-self` (via `ask:` @id) |
| **IFC / integrity floors (re-implemented)** | | | |
| secret-in-context egress | `action=net_external`, `session_secret=true` | **DENY** | `floor-secret-egress` |
| untrusted-read egress | `action=net_external`, `session_untrusted_read=true` | **DENY** | `floor-untrusted-egress` |
| was-secret push | `action=push_origin`, `session_was_secret=true` | **ASK** | `floor-was-secret-push` (via `ask:`) |
| delegate after untrusted | `action=delegate`, `session_untrusted_this_turn=true` | **DENY** | `deny-delegate-after-untrusted` |
| **Grants / default** | | | |
| clean run_ephemeral | `action=run_ephemeral`, clean | **ALLOW** | `grant-ephemeral-clean` |
| clean git commit | `action=commit` | ALLOW | `default-permit` |
| **Most-restrictive (deny out-ranks ask)** | | | |
| secret + was-secret push | `session_secret=true`, `session_was_secret=true` | **DENY** | `floor-secret-egress` |

The last row is the tie-break proof: a `session_secret` egress is forbidden by the
real-deny `floor-secret-egress`, which out-ranks the `ask:floor-was-secret-push`
forbid that also matches — so the bridge reports **deny**, not ask.

**End-to-end** — real `sir guard evaluate` with authoritative Cedar active and
`--on-failure deny`, captured as a real end user (**no `PYTHONPATH` set**). The
"decided by" column is read from the ledger's `provider_verdicts`:

"Decided by" is the matched `@id` from the ledger's `provider_verdicts`. Payloads
are the real shapes Claude Code emits — the subagent tool is `Agent`, carrying
`subagent_type`, which is how the denylisted-skill `@id` sees the skill name.

| Tool call (real payload) | Native would | sir decision | Decided by |
|---|---|---|---|
| `Bash: npx create-react-app x` | ask (`run_ephemeral`) | **allow** | Cedar permit |
| `Bash: git commit -m wip` | allow | **allow** | Cedar permit |
| `Read: ~/.ssh/id_rsa` | ask | **deny** | Cedar `deny-agent-credential-read` |
| `Bash: sudo rm -rf …` | ask | **ask** | Cedar `ask:privileged` |
| `Agent{subagent_type:"data-exfil"}` | ask (delegate) | **deny** | Cedar `deny-denylisted-skill` |
| `Bash: sir provider authoritative evil` | ask | **ask** | sir **non-delegable** sir-self floor |

Reproduce through SIR's PreToolUse path (no `PYTHONPATH` needed):

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"npx create-react-app x"}}' \
  | bin/sir guard evaluate         # → allow (Cedar granted; native would ask)

echo '{"tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}' \
  | bin/sir guard evaluate         # → deny (Cedar org rule)

echo '{"tool_name":"Agent","tool_input":{"subagent_type":"data-exfil","prompt":"x"}}' \
  | bin/sir guard evaluate         # → deny (Cedar denylisted-skill)
```

**Integrity floor, in-band (verified).** Taint the session the production way (a
`post-evaluate` whose tool *output* carries a credential pattern), then a `curl`
egress in that session is **denied**, with the ledger showing Cedar's re-implemented
`floor-secret-egress` deciding in-band (`fail_closed: false`). sir's native
non-delegable secret-egress protection also backstops it — policy can grant friction
away but cannot delete the exfiltration wall.

**Fail-closed (verified).** With `--on-failure deny`, if `cedar` is unavailable the
decision is **deny**, never a silent allow — verified end-to-end via `sir guard`
with `CEDAR_BIN=/nonexistent` ("did not return a usable decision — blocked (fail
closed)").

### 7. Cedar vs OPA — when to pick which

Both engines drive the same authoritative `policy_provider` contract with the same
fail-closed and non-delegable-floor guarantees. They differ in shape:

| | **Cedar** | **OPA / Rego** |
|---|---|---|
| Model | typed principal/action/resource/context | general document + Rego rules |
| Verdicts | permit/forbid (**ask** encoded via `ask:` @id) | allow/ask/deny native |
| Analyzability | strongly typed, formally analyzable policy set | flexible, expressive, less constrained |
| String ops | limited (bridge pre-computes helpers) | rich built-ins (substring, regex) |
| Runtime | local `cedar authorize` per call | warm localhost sidecar (`opa run --server`) |
| Backing | AWS-backed Cedar project | CNCF Open Policy Agent |

Pick **Cedar** when you want a typed, analyzable policy set and are comfortable
encoding "ask" with the `ask:` convention. Pick **OPA** when you want Rego's
flexibility and rich string handling, native three-verdict output, and a warm
sidecar with hot-reload. See the [OPA provider guide](opa-policy-provider.md) for
the Rego walkthrough.

---

## See also

- [docs/providers.md](providers.md) — the full provider model (signal / effect /
  policy / advisory / export) and the "Authoritative mode" section.
- [docs/opa-policy-provider.md](opa-policy-provider.md) — the OPA/Rego counterpart
  of this guide.
- [docs/research/pdp-provider-delegation.md](research/pdp-provider-delegation.md)
  — the design of record: fail-closed failure-mode table, the non-delegable
  floors (§7), and the trust boundary.
- [`examples/providers/cedar-authoritative/`](../examples/providers/cedar-authoritative/)
  — the working example: `provider.py`, `policies/sir.cedar`, `provider.yaml`,
  fixtures, and the verified query log.
