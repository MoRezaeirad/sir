<!-- VERIFIED Cedar query outputs — captured live (cedar-policy-cli 4.11.0) against
     policies/sir.cedar via the bridge. Real, tested results. -->

# Verified Cedar query series (sir-domain)

Bridge decisions (`cedar authorize --verbose` → mapped to allow/ask/deny), verdict | rules_matched:

| Scenario | Request (abbrev) | Verdict | Rule fired |
|---|---|---|---|
| **Agents** | | | |
| agent reads ~/.aws/credentials | action=read_ref, actor=ai_coding_agent | **DENY** | deny-agent-credential-read |
| human reads ~/.aws/credentials | action=read_ref, actor=human_developer | ALLOW | default-permit |
| **Skills** | | | |
| denylisted skill data-exfil | action=delegate, target=…data-exfil… | **DENY** | deny-denylisted-skill |
| **MCP** | | | |
| mcp network arg-url (clean) | action=mcp_network_unapproved, clean | **ALLOW** | grant-mcp-network |
| mcp injection detected | action=mcp_injection_detected | **DENY** | deny-mcp-injection |
| **Hooks / sir-self** | | | |
| sir self-modification | action=sir_self | **ASK** | sir-self (via `ask:` @id) |
| **IFC / integrity floors (re-implemented)** | | | |
| secret-in-context egress | action=net_external, session_secret=true | **DENY** | floor-secret-egress |
| untrusted-read egress | action=net_external, session_untrusted_read=true | **DENY** | floor-untrusted-egress |
| was-secret push | action=push_origin, session_was_secret=true | **ASK** | floor-was-secret-push (via `ask:`) |
| delegate after untrusted | action=delegate, session_untrusted_this_turn=true | **DENY** | deny-delegate-after-untrusted |
| **Grants / default** | | | |
| clean run_ephemeral | action=run_ephemeral, clean | **ALLOW** | grant-ephemeral-clean |
| clean git commit | action=commit | ALLOW | default-permit |
| **Most-restrictive (deny out-ranks ask)** | | | |
| secret + was-secret push | session_secret=true, session_was_secret=true | **DENY** | floor-secret-egress |

# Cedar has no "ask" — how this works

Cedar only has `permit`/`forbid`. The bridge maps a **`forbid` whose `@id` starts
with `ask:`** to SIR's `ask`; any other forbid → `deny`; permit → `allow`. A real
deny out-ranks an `ask:` forbid (most-restrictive), verified by the
secret+was-secret row above (deny wins). The matched `@id` comes from
`cedar authorize --verbose`.

# Verified end-to-end (real `sir guard evaluate`, authoritative Cedar, `--on-failure deny`)

Captured as a real end user: provider installed via `sir provider install/use/authoritative`,
each query piped to `sir guard evaluate` with **no PYTHONPATH set** (the true install
condition — see the SDK-path note below). Decided-by is read from the ledger's
`provider_verdicts`.

Every row was run individually through `sir guard evaluate`; "decided by" is the
matched `@id` from the ledger's `provider_verdicts` (Cedar's `--verbose` reports it).
Payloads are the real shapes Claude Code emits (subagent tool = `Agent`, carrying
`subagent_type`).

| Tool call (real payload) | Native would | sir decision | Decided by (ledger) |
|---|---|---|---|
| `Bash: npx create-react-app x` | ask (run_ephemeral) | **allow** | Cedar permit |
| `Bash: git commit -m wip` | allow | **allow** | Cedar permit |
| `Read: ~/.ssh/id_rsa` | ask | **deny** | Cedar `deny-agent-credential-read` |
| `Bash: sudo rm -rf …` | ask | **ask** | Cedar `ask:privileged` |
| `Agent{subagent_type:"data-exfil"}` | ask (delegate) | **deny** | Cedar `deny-denylisted-skill` |
| `Agent{subagent_type:"lint"}` | ask (delegate) | **allow** | Cedar permit |
| `Bash: sir provider authoritative evil` | ask | **ask** | sir **non-delegable** sir-self floor (policy cannot override) |

## Integrity floors — driven through the real session lifecycle

Tainted the production way (a `post-evaluate` whose tool output carries a real
credential pattern marks the session secret; a `WebFetch` of external content marks
untrusted-read), then the action is evaluated in that session. Every row is
ledger-verified `fail_closed: false` (Cedar decided in-band).

| Sequence | sir decision | Deciding rule (`@id`, from ledger) |
|---|---|---|
| credential in output → `curl …` | **deny** | Cedar `floor-secret-egress` |
| credential in output → `nslookup …` | **deny** | Cedar `floor-secret-egress` |
| credential in output → `git push origin` | **ask** | Cedar `floor-was-secret-push` |
| WebFetch untrusted → `curl …` | **deny** | Cedar `floor-untrusted-egress` |
| WebFetch untrusted → `Agent{…}` (delegate) | **deny** | Cedar `deny-delegate-after-untrusted` |

As with OPA, two layers hold the wall: Cedar's re-implemented `floor-secret-egress`
decides in-band, **and** sir's native non-delegable secret-egress protection backstops
it regardless. An authoritative policy can grant friction away but cannot delete the
exfiltration wall.

## MCP defenses — driven through the real scanner path (end-to-end)

Each MCP row was driven by a real `post-evaluate` whose MCP tool output carried the
triggering content, then the follow-up was evaluated in that session (identical to OPA):

| Sequence | sir decision | Enforced by |
|---|---|---|
| MCP output has AWS keys → then `curl …` | **deny** | session marked secret → native secret-egress floor (Cedar `floor-secret-egress` re-implements it) |
| MCP output has injection → next MCP call | **ask** | server tainted + posture critical → sir's **non-delegable** tainted-MCP floor |
| `grant-mcp-network` (approved server + unapproved arg-URL) | **allow** | Cedar permit, in-band |

The credential-leak and injection legs are enforced by sir's native non-delegable MCP
floors (an authoritative policy cannot weaken them); the Cedar rules are
defense-in-depth.

# Verified fail-closed

`CEDAR_BIN=/nonexistent` (cedar unavailable) + `--on-failure deny` → **deny**, end-to-end via
`sir guard evaluate` ("authoritative policy provider … did not return a usable decision —
blocked (fail closed)"). Never a silent allow.

# SDK-path note (why no PYTHONPATH is needed)

sir adds the provider's own directory and the bundled `sdk/python` to the spawned provider's
`PYTHONPATH` automatically, using absolute paths. You do **not** need to `export
PYTHONPATH=…` — vendor `sir_sdk.py` beside your `provider.py`, or rely on the bundled copy.
(An earlier build resolved the SDK path relative to the working directory, which fail-closed
every provider unless sir ran from the repo root; fixed.)
