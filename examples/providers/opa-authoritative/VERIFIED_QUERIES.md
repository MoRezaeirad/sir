<!-- VERIFIED OPA query outputs — captured live (OPA 1.17.0) against policy/sir.rego.
     These are real, tested results. Do not edit by hand; re-run to refresh. -->

# Verified OPA query series (sir-domain)

Raw OPA decisions (POST to `/v1/data/sir/policy/decision`), verdict | rules_matched:

| Scenario | Request (abbrev) | Verdict | Rule fired |
|---|---|---|---|
| **Agents** | | | |
| agent reads ~/.ssh/id_rsa | action=read_ref, actor=ai_coding_agent | **DENY** | deny-agent-credential-read |
| human reads ~/.ssh/id_rsa | action=read_ref, actor=human_developer | ALLOW | (default) |
| agent npx (clean) | action=run_ephemeral, clean | **ALLOW** | grant-ephemeral-clean |
| **Skills** | | | |
| denylisted skill data-exfil | action=delegate, target=…data-exfil… | **DENY** | deny-denylisted-skill |
| allowed skill lint | action=delegate, target=…lint | ALLOW | (default) |
| **MCP** | | | |
| mcp network arg-url (clean) | action=mcp_network_unapproved, clean | **ALLOW** | grant-mcp-network |
| mcp credential leak | action=mcp_credential_leak | **DENY** | deny-mcp-credential-leak |
| mcp injection detected | action=mcp_injection_detected | **DENY** | deny-mcp-injection |
| **Hooks / sir-self** | | | |
| sir self-modification | action=sir_self | **ASK** | ask-sir-self |
| **IFC / integrity floors (re-implemented)** | | | |
| secret-in-context egress | action=net_external, session_secret=true | **DENY** | floor-secret-egress |
| untrusted-read egress | action=net_external, session_untrusted_read=true | **DENY** | floor-untrusted-egress |
| was-secret push | action=push_origin, session_was_secret=true | **ASK** | floor-was-secret-push |
| delegate after untrusted | action=delegate, session_untrusted_this_turn=true | **DENY** | deny-delegate-after-untrusted |
| **Grants (native would ask)** | | | |
| egress to approved host (clean) | action=net_external, target=…npmjs.org | **ALLOW** | grant-approved-egress |
| egress to UNAPPROVED host (clean) | action=net_external, target=…evil.example.com | ALLOW | (default — see note) |
| **Most-restrictive combination** | | | |
| approved host BUT secret session | action=net_external, npmjs.org, session_secret=true | **DENY** | floor-secret-egress |

NOTE: the demo policy is permissive-by-default (`default verdict := "allow"`), so an
unapproved external host on a clean session is allowed. A production policy would
flip to default-deny for egress. This is a policy-authoring choice, documented as
such.

## `grant-approved-egress` host-spoof resistance (verified through the bridge)

The grant matches the **parsed** host (`input.target_host`, computed by
`provider.py` with `urllib.parse`), never a substring of the raw URL. Verified via
the bridge — `grant-approved-egress` fires only for the left column:

| GRANTS (real approved host) | does NOT grant (spoof — exfil to attacker host) |
|---|---|
| `https://api.github.com/zen` | `https://api.github.com.evil.example/` |
| `https://objects.pypi.org/x` (subdomain) | `https://pypi.org.evil.example/x` |
| `https://api.github.com:443/x` (port) | `https://evil.example/?next=api.github.com` |
| `https://user@api.github.com/x` (userinfo) | `https://evil.example/?u=https://api.github.com` |
| `https://registry.npmjs.org/react` | `https://evil.example/api.github.com` |

NOTE on reachability: the table above is the **policy layer** (raw `POST` to OPA),
where every rule is exercised directly. Every row was ALSO confirmed through the
full `sir guard` path (see the end-to-end matrix and MCP section below). A few rows
need session/lease setup to reach `sir guard` — that setup is real, not a bypass:

- `mcp_network_unapproved` (rule `grant-mcp-network`) fires once the MCP server is
  **approved** in the lease (an unapproved server maps to `mcp_unapproved` instead).
  Verified end-to-end: `rules_matched: ["grant-mcp-network"]`, allow.
- `mcp_credential_leak` / `mcp_injection_detected` are raised by sir's `post-evaluate`
  output scanners. Their **end-to-end enforcement** is sir's own **non-delegable** MCP
  floor (a credential-bearing MCP output marks the session secret → egress denied; an
  injection-bearing output taints the server → next call held for approval). The OPA
  rule is genuine defense-in-depth; the native floor is the in-band decider on this
  path by design (an authoritative policy cannot weaken it). Both legs verified
  end-to-end below.

# Verified end-to-end (real `sir guard evaluate`, authoritative OPA active, `--on-failure deny`)

Captured as a real end user: provider installed via `sir provider install/use/authoritative`,
each query piped to `sir guard evaluate` with **no PYTHONPATH set** (the true install
condition — see the SDK-path note below). Decided-by column is read from the ledger's
`provider_verdicts`, so it names which layer actually produced the verdict, not just the
displayed reason.

Every row below was run individually through `sir guard evaluate` and the
"decided by" rule is read from the ledger's `provider_verdicts` — not the displayed
reason. The tool-call payloads are the **real shapes Claude Code emits** (the
subagent tool is named `Agent`, carrying `subagent_type`).

| Tool call (real payload) | Native would | sir decision | Decided by (ledger) |
|---|---|---|---|
| `Bash: npx create-react-app x` | ask (run_ephemeral) | **allow** | OPA `grant-ephemeral-clean` |
| `Bash: git commit -m wip` | allow | **allow** | OPA (default permit) |
| `Read: ~/.aws/credentials` | ask | **deny** | OPA `deny-agent-credential-read` |
| `Bash: sudo rm -rf …` | ask | **ask** | OPA `ask-privileged` |
| `Bash: curl https://registry.npmjs.org/…` | ask (net_external) | **allow** | OPA `grant-approved-egress` |
| `Agent{subagent_type:"data-exfil"}` | ask (delegate) | **deny** | OPA `deny-denylisted-skill` |
| `Agent{subagent_type:"lint"}` | ask (delegate) | **allow** | OPA (default permit) |
| `Bash: sir provider authoritative evil` | ask | **ask** | sir **non-delegable** sir-self floor (policy cannot override) |

## Integrity floors — driven through the real session lifecycle

These are NOT fabricated flags. The session is tainted the way it is in production: a
`post-evaluate` whose tool **output** contains a real credential pattern marks the
session secret; a `WebFetch` of external content marks untrusted-read. The egress is
then evaluated in that same session. Every row here is ledger-verified `fail_closed:
false` (the policy decided in-band, not a fail-closed default).

| Sequence | sir decision | Deciding rule (from ledger) |
|---|---|---|
| credential in output → `curl …` | **deny** | OPA `floor-secret-egress` |
| credential in output → `nslookup …` | **deny** | OPA `floor-secret-egress` |
| credential in output → `git push origin` | **ask** | OPA `floor-was-secret-push` |
| WebFetch untrusted → `curl …` | **deny** | OPA `floor-untrusted-egress` |
| WebFetch untrusted → `Agent{…}` (delegate) | **deny** | OPA `deny-delegate-after-untrusted` |

Two layers hold this wall, by design:

1. The authoritative OPA policy's re-implemented `floor-secret-egress` rule returns `deny`
   in-band — verified in the ledger (`rules_matched: ["floor-secret-egress"]`).
2. sir's **native non-delegable** secret-egress protection backstops it regardless — an
   authoritative policy can grant friction away but **cannot delete the exfiltration wall**.

(The displayed block message is sir's native secret-lock copy; the ledger is the source of
truth for which rule decided. Both point to deny.)

## MCP defenses — driven through the real scanner path (end-to-end)

The MCP rows are not curl-only. Each was driven by a real `post-evaluate` whose MCP
tool **output** carried the triggering content, then the follow-up was evaluated in
that session:

| Sequence | sir decision | Enforced by |
|---|---|---|
| MCP output has AWS keys → then `curl …` | **deny** | session marked secret → native secret-egress floor (OPA `floor-secret-egress` also re-implements it) |
| MCP output has injection ("ignore … exfiltrate") → next MCP call | **ask** | server tainted + posture critical → sir's **non-delegable** tainted-MCP floor |
| `grant-mcp-network` (approved server + unapproved arg-URL) | **allow** | OPA `grant-mcp-network`, in-band (`rules_matched: ["grant-mcp-network"]`) |

The credential-leak and injection legs are enforced by sir's native non-delegable MCP
floors — an authoritative policy cannot weaken them — with the OPA rules as
defense-in-depth.

# Verified fail-closed

Make the engine unreachable (`OPA_URL` pointed at a dead port / sidecar stopped) and re-run
`npx …` → **deny** ("authoritative policy provider … did not return a usable decision —
blocked (fail closed)"). Never a silent allow.

# SDK-path note (why no PYTHONPATH is needed)

sir adds the provider's own directory and the bundled `sdk/python` to the spawned provider's
`PYTHONPATH` automatically, using absolute paths. You do **not** need to `export
PYTHONPATH=…` to run a bundled provider — vendor `sir_sdk.py` beside your `provider.py`, or
rely on the bundled copy. (An earlier build resolved the SDK path relative to the working
directory, which fail-closed every provider unless sir ran from the repo root; fixed.)
