# Policy as code for AI coding agents — OPA as an authoritative SIR provider

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

This is **PDP (Policy Decision Point) delegation**: the same Rego an org already
runs against Terraform, Kubernetes, and CI now governs agent actions — verbs,
skills, MCP calls, hooks, and IFC taint — as *policy as code*. The policy is the
whole truth for the delegated decision surface.

Two honest guardrails keep that power safe:

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
OPA. The working example lives in
[`examples/providers/opa-authoritative/`](../examples/providers/opa-authoritative/).

---

## Build & use a policy-based provider with OPA

### 1. Prerequisites

```sh
brew install opa            # or https://www.openpolicyagent.org/docs/latest/#1-download-opa
```

Verified against **OPA 1.17.0**.

### 2. The bridge — how SIR talks to a provider

A provider is just a process that speaks **stdio-JSON**: SIR writes one JSON
object per line to its stdin, the provider writes one JSON object per line back.
The reference bridge,
[`examples/providers/opa-authoritative/provider.py`](../examples/providers/opa-authoritative/provider.py),
uses the `sir_sdk` helper (`sir_sdk.run_policy_provider`) so it only has to
implement two functions: `caps()` and `evaluate(request)`.

The round trip is:

```text
SIR  ──sir.policy_request.v1──▶  provider.py  ──POST input──▶  OPA (warm sidecar)
SIR  ◀──sir.policy_verdict.v0──  provider.py  ◀──{result}─────  OPA
```

Concretely, `evaluate(request)`:

1. receives the `sir.policy_request` dict (v0 fields + v1 session signals),
2. POSTs it to the warm OPA server as the OPA `input` document,
3. reads `{verdict, rules_matched, reason}` back and wraps it with
   `sir_sdk.policy_verdict(...)`.

The contract has one safety-critical rule: when the bridge genuinely cannot reach
OPA it returns **`None`** (no verdict) — it never invents an `allow`. Under an
authoritative registration SIR turns "no verdict" into a fail-closed `ask`/`deny`,
so the bridge never has to guess a safe default.

> Authority is an **operator act** (`sir provider authoritative`), never a wire
> claim. The bridge's capabilities still declare `is_advisory: true`; the operator
> — not the provider — decides it is authoritative.

### 3. Writing the policy

The policy reads a `sir.policy_request`. The fields that matter:

| Field | Example | Meaning |
|---|---|---|
| `input.action` | `run_ephemeral`, `delegate`, `net_external`, `read_ref`, `push_origin`, `mcp_network_unapproved`, `sir_self` | the verb being evaluated |
| `input.target` | `~/.ssh/id_rsa`, `registry.npmjs.org`, a skill name, an MCP server | path / URL / command / name |
| `input.resolved_actor` | `ai_coding_agent` | `ai_coding_agent` \| `human_developer` \| `unknown` |
| `input.taint` | `["untrusted_content"]` | prior-session taint labels |
| `input.session_secret` | `true` | **v1** — a live secret is in context now |
| `input.session_was_secret` | `true` | **v1** — the session ever held a secret (high-water mark) |
| `input.session_untrusted_read` | `true` | **v1** — untrusted content ingested this session |
| `input.session_untrusted_this_turn` | `true` | **v1** — untrusted content this turn |

The v1 session signals are what make floor re-implementation possible — without
them OPA couldn't see the integrity state the native walls key on. SIR populates
them on **every** request regardless of who decides (fact-gathering is never
delegated), so an authoritative grant cannot blind the signals a floor depends on.

The policy assembles a decision at `data.sir.policy.decision`, collecting every
rule that fires and reducing to the **most restrictive** verdict (`deny` > `ask` >
`allow`) so a permissive rule can never override a deny. It has three sections.

**A. GRANT** — remove friction native imposes (snippets from `policy/sir.rego`):

```rego
# Native asks on every run_ephemeral; grant it on a clean session.
fired contains {"rule": "grant-ephemeral-clean", "verdict": "allow", ...} if {
	input.action == "run_ephemeral"
	clean_session
}

# Allow external egress to an org-approved host (native would ask) — clean session only.
# SECURITY: match the parsed HOST, never a substring of the raw URL. Rego is not a
# URL parser, so the bridge (provider.py) parses the authority with urllib.parse and
# passes the trusted `input.target_host`; the policy just compares that field. This
# defeats "api.github.com.evil.example" AND "evil.example/?u=https://api.github.com".
approved_egress_hosts := {"api.github.com", "registry.npmjs.org", "pypi.org"}
fired contains {"rule": "grant-approved-egress", "verdict": "allow", ...} if {
	input.action == "net_external"
	clean_session
	host_is_approved(input.target_host) # exact or true-subdomain
}
```

> **Parse where there's a parser, match where there's a matcher.** A reference
> provider should not hand-roll URL parsing in Rego — `provider.py` computes
> `target_host` with the stdlib `urllib.parse.urlsplit().hostname` (drops scheme,
> userinfo, port, path, query) and the policy does a plain exact/subdomain compare.
> Verified: legit hosts (incl. `objects.pypi.org`, `:443`, `user@…`) grant;
> `api.github.com.evil.example`, `evil.example/?u=https://api.github.com`,
> `pypi.org.evil.example` do not.

**B. RESTRICT** — org rules native doesn't enforce:

```rego
# AI agents may not read raw credential files (deny, not ask).
fired contains {"rule": "deny-agent-credential-read", "verdict": "deny", ...} if {
	input.action == "read_ref"
	input.resolved_actor == "ai_coding_agent"
	is_credential_path(input.target)
}

# No delegation to subagents while untrusted content is in play (injection containment).
fired contains {"rule": "deny-delegate-after-untrusted", "verdict": "deny", ...} if {
	input.action == "delegate"
	untrusted_ingested
}
```

**C. RE-IMPLEMENTED FLOORS** — authoritative mode makes these the policy's job:

```rego
# Confidentiality wall: a live secret in context must not flow to an external sink.
egress_actions := {"net_external", "dns_lookup", "push_remote"}
fired contains {"rule": "floor-secret-egress", "verdict": "deny", ...} if {
	input.action in egress_actions
	input.session_secret
}

# Lethal-trifecta exfil leg: untrusted content ingested → egress is held.
fired contains {"rule": "floor-untrusted-egress", "verdict": "deny", ...} if {
	input.action in egress_actions
	untrusted_ingested
}
```

Because most-restrictive wins, a floor `deny` always overrides any GRANT in the
same evaluation.

### 4. Query OPA directly

Run OPA **warm** — a localhost sidecar, not a cold `opa eval` per call. From the
example directory:

```sh
opa run --server --addr 127.0.0.1:8181 policy/
```

Leave it running; edit `policy/sir.rego` freely — OPA hot-reloads. The HTTP
decision endpoint is the `decision` rule inside package `sir.policy`, so the path
is `/v1/data/sir/policy/decision`. POST the `sir.policy_request` as `input`:

```sh
curl -s -X POST http://127.0.0.1:8181/v1/data/sir/policy/decision \
  -H 'Content-Type: application/json' \
  -d '{"input": {"action": "read_ref",
                 "resolved_actor": "ai_coding_agent",
                 "target": "/home/dev/.ssh/id_rsa"}}'
```

OPA wraps the rule result under `result`:

```json
{
  "result": {
    "verdict": "deny",
    "rules_matched": ["deny-agent-credential-read"],
    "reason": "AI agents may not read raw credential files — use a secret manager."
  }
}
```

That `{verdict, rules_matched, reason}` triad is exactly what `provider.py` reads
and forwards to SIR.

### 5. Wire it into SIR

From the repo root. SIR adds the provider's own directory and the bundled
`sdk/python` to the provider's `PYTHONPATH` automatically (absolute paths) when it
spawns it — including the install health handshake — so you do **not** need to set
`PYTHONPATH` yourself. Vendor `sir_sdk.py` beside your `provider.py`, or rely on
the bundled copy:

```sh
bin/sir provider install examples/providers/opa-authoritative/provider.yaml
bin/sir provider use opa-authoritative
bin/sir provider authoritative opa-authoritative --on-failure deny
bin/sir provider status opa-authoritative        # → Authority: AUTHORITATIVE
```

`--on-failure deny` means: if OPA is ever unreachable, SIR denies (fail closed).
Use `ask` for a softer posture. Demote back to advisory any time with
`bin/sir provider advisory opa-authoritative`.

### 6. Verified query series

These are **real, tested outputs** captured live against `policy/sir.rego` (OPA
1.17.0). They are reproduced from
[`examples/providers/opa-authoritative/VERIFIED_QUERIES.md`](../examples/providers/opa-authoritative/VERIFIED_QUERIES.md);
do not hand-edit — re-run to refresh.

**Raw OPA decisions** (POST to `/v1/data/sir/policy/decision`):

| Scenario | Request (abbrev) | Verdict | Rule fired |
|---|---|---|---|
| **Agents** | | | |
| agent reads `~/.ssh/id_rsa` | `action=read_ref`, `actor=ai_coding_agent` | **DENY** | `deny-agent-credential-read` |
| human reads `~/.ssh/id_rsa` | `action=read_ref`, `actor=human_developer` | ALLOW | (default) |
| agent npx (clean) | `action=run_ephemeral`, clean | **ALLOW** | `grant-ephemeral-clean` |
| **Skills** | | | |
| denylisted skill data-exfil | `action=delegate`, `target=…data-exfil…` | **DENY** | `deny-denylisted-skill` |
| allowed skill lint | `action=delegate`, `target=…lint` | ALLOW | (default) |
| **MCP** | | | |
| mcp network arg-url (clean) | `action=mcp_network_unapproved`, clean | **ALLOW** | `grant-mcp-network` |
| mcp credential leak | `action=mcp_credential_leak` | **DENY** | `deny-mcp-credential-leak` |
| mcp injection detected | `action=mcp_injection_detected` | **DENY** | `deny-mcp-injection` |
| **Hooks / sir-self** | | | |
| sir self-modification | `action=sir_self` | **ASK** | `ask-sir-self` |
| **IFC / integrity floors (re-implemented)** | | | |
| secret-in-context egress | `action=net_external`, `session_secret=true` | **DENY** | `floor-secret-egress` |
| untrusted-read egress | `action=net_external`, `session_untrusted_read=true` | **DENY** | `floor-untrusted-egress` |
| was-secret push | `action=push_origin`, `session_was_secret=true` | **ASK** | `floor-was-secret-push` |
| delegate after untrusted | `action=delegate`, `session_untrusted_this_turn=true` | **DENY** | `deny-delegate-after-untrusted` |
| **Grants (native would ask)** | | | |
| egress to approved host (clean) | `action=net_external`, `target=…npmjs.org` | **ALLOW** | `grant-approved-egress` |
| egress to UNAPPROVED host (clean) | `action=net_external`, `target=…evil.example.com` | ALLOW | (default — see note) |
| **Most-restrictive combination** | | | |
| approved host BUT secret session | `action=net_external`, npmjs.org, `session_secret=true` | **DENY** | `floor-secret-egress` |

> **Permissive-by-default note (a policy-authoring choice).** The demo policy uses
> `default verdict := "allow"`, so an unapproved external host on a clean session
> is *allowed* — that is why the UNAPPROVED-host row above is ALLOW. A production
> policy would flip to default-deny for egress. This is documented as a deliberate
> choice of the example, not a SIR behavior.

**End-to-end** — real `sir guard evaluate` with authoritative OPA active and
`--on-failure deny`, captured as a real end user (**no `PYTHONPATH` set**). The
"decided by" column is read from the ledger's `provider_verdicts`, so it names the
layer that actually produced the verdict:

"Decided by" is read from the ledger's `provider_verdicts`. Payloads are the real
shapes Claude Code emits — note the subagent tool is `Agent`, carrying
`subagent_type`, which is how the denylisted-skill rule sees the skill name.

| Tool call (real payload) | Native would | sir decision | Decided by |
|---|---|---|---|
| `Bash: npx create-react-app x` | ask (`run_ephemeral`) | **allow** | OPA `grant-ephemeral-clean` |
| `Bash: git commit -m wip` | allow | **allow** | OPA (default permit) |
| `Read: ~/.aws/credentials` | ask | **deny** | OPA `deny-agent-credential-read` |
| `Bash: sudo rm -rf …` | ask | **ask** | OPA `ask-privileged` |
| `Bash: curl …registry.npmjs.org…` | ask (`net_external`) | **allow** | OPA `grant-approved-egress` |
| `Agent{subagent_type:"data-exfil"}` | ask (delegate) | **deny** | OPA `deny-denylisted-skill` |
| `Bash: sir provider authoritative evil` | ask | **ask** | sir **non-delegable** sir-self floor |

Reproduce through SIR's PreToolUse path (no `PYTHONPATH` needed):

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"npx cowsay hi"}}' \
  | bin/sir guard evaluate          # → allow (OPA granted; native would ask)

echo '{"tool_name":"Read","tool_input":{"file_path":"~/.aws/credentials"}}' \
  | bin/sir guard evaluate          # → deny (OPA org rule)

echo '{"tool_name":"Agent","tool_input":{"subagent_type":"data-exfil","prompt":"x"}}' \
  | bin/sir guard evaluate          # → deny (OPA denylisted-skill)
```

**Integrity floor, in-band (verified).** Taint the session the production way — a
`post-evaluate` whose tool *output* carries a credential pattern marks it secret —
then a `curl` egress in that session is **denied**, and the ledger shows OPA's
re-implemented `floor-secret-egress` rule decided in-band (`fail_closed: false`).
sir's **native non-delegable** secret-egress protection also backstops this: an
authoritative policy can grant friction away but cannot delete the exfiltration
wall.

**Fail-closed (verified).** Make OPA unreachable (stop the sidecar / dead
`OPA_URL`), then re-run the `npx …` command: with `--on-failure deny` the decision
becomes **deny** ("authoritative policy provider … did not return a usable
decision — blocked (fail closed)"). Never a silent allow.

### 7. Write your own rule

Add a rule by appending a `fired contains {...}` block to `policy/sir.rego`. Each
block contributes one candidate verdict; the most-restrictive reducer does the
rest. For example, to always ask before any push to a non-origin remote:

```rego
fired contains {
	"rule": "ask-nonorigin-push",
	"verdict": "ask",
	"reason": "Pushing to a non-origin remote needs human review.",
} if {
	input.action in {"push_origin", "push_remote"}
	not contains(input.target, "origin")
}
```

Save the file — OPA hot-reloads it. Verify the rule in isolation with a `curl`
POST (step 4), then end-to-end with `sir guard evaluate` (step 6). When the rule
is right, no SIR restart is needed; the warm sidecar picks it up immediately.

---

## See also

- [docs/providers.md](providers.md) — the full provider model (signal / effect /
  policy / advisory / export) and the "Authoritative mode" section.
- [docs/research/pdp-provider-delegation.md](research/pdp-provider-delegation.md)
  — the design of record: fail-closed failure-mode table, the non-delegable
  floors (§7), and the trust boundary.
- [`examples/providers/opa-authoritative/`](../examples/providers/opa-authoritative/)
  — the working example: `provider.py`, `policy/sir.rego`, `provider.yaml`,
  fixtures, and the verified query log.
