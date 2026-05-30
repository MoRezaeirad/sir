# sir Threat Model

> [!NOTE]
> sir is experimental — test on your own machine, not shared infrastructure. `sir doctor` recovers any wedged state; [report bugs](https://github.com/somoore/sir/issues).

sir ("Sandbox in Reverse") is an experimental security runtime for AI coding agents. Traditional sandboxes constrain a process from below — syscalls, filesystem jails, seccomp. sir inverts that: it constrains the *agent* from above, intercepting tool calls at the hook layer before they execute and routing them through a Rust policy oracle (`mister-core`) that returns allow, ask, or deny. Every decision is appended to an immutable hash-chained ledger.

This approach exists because AI coding agents are not a single sandboxable process. They orchestrate tools, spawn subprocesses, and call MCP servers. The dangerous surface is not syscalls — it is *intents* like "read `.env`, then `curl` an external host." sir uses **information flow control (IFC)** to track data sensitivity across operations: if the agent reads a secret file, that taint propagates to any file it writes, any commit, and any push attempt in the same session.

> **Warning:** sir is experimental and v1 has known limitations. It is not a complete containment boundary, the hook layer is advisory policy enforcement rather than OS-level prevention (unless `sir run` is used), and several detections are heuristic.

This document lays out the shipped threat model, the trust assumptions behind it, and the residual risk that remains so external researchers can evaluate it honestly.

<!-- BEGIN GENERATED SUPPORT SCOPE -->
**Scope note.** The threat model is written primarily against Claude Code because Claude Code is the **reference-support** target: it has the richest hook surface (11 events), native interactive approval, and the most complete sir coverage. Gemini CLI has **near-parity support** — full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning — but some Claude-specific mitigations are not available: PermissionRequest approval brokering, SubagentStart delegation gating, ConfigChange tamper detection at the moment of change, InstructionsLoaded pre-read scanning, and Elicitation interception. Codex has **limited support** with partial tool-path coverage: Bash, native-write, MCP, and permission-request hooks are registered where Codex emits them, but missing lifecycle hooks and upstream delivery gaps mean sir still relies on sentinel hashing plus a final `Stop` sweep as the posture backstop. Wherever a mitigation below depends on one of the missing hooks, the threat is correspondingly wider on the affected agent. See [../user/codex-support.md](../user/codex-support.md) and [../user/gemini-support.md](../user/gemini-support.md) for the per-agent coverage matrices.
<!-- END GENERATED SUPPORT SCOPE -->

## Assets and trust boundaries

The assets sir is trying to protect are straightforward:

- Credentials and other sensitive local files.
- The host agent's hook config.
- Project posture files such as `CLAUDE.md` and `.mcp.json`.
- The active lease and session state.
- The integrity of the forensic ledger.

The core trust boundaries are:

- Tool calls crossing from the model into the local machine.
- Hook-managed policy decisions between Go and Rust.
- External sinks such as network egress, pushes, and untrusted MCP servers.
- The sir-owned canonical state under `~/.sir/`.

## Adversary model

sir assumes an attacker **can**:

- Inject instructions through repository content, MCP responses, or fetched content.
- Publish malicious packages with postinstall tamper.
- Influence the agent into reading, writing, or exfiltrating data the developer did not intend.

sir does **not** assume the attacker can:

- Gain kernel-level control of the host.
- Bypass the host agent and write arbitrary state under `~/.sir/`.

sir **does** detect post-install binary tampering: `mister-core` is hash-verified against the install-time manifest on first use per process, and `sir verify` checks both binaries on demand. A swapped policy oracle triggers a hard deny on all tool calls.

## In-scope threats

### Confused deputy actions

**Threat:** the agent is induced to take actions the developer did not intend.

**Mitigations:**

- Sensitive reads are approval-gated.
- Posture-file writes are approval-gated.
- Risky sinks are checked against trust and session posture.
- Every decision is logged to the ledger.

### Credential exfiltration

**Threat:** the agent reads `.env`, `*.pem`, `.aws/*`, or similar data and tries to send it outward.

**Mitigations:**

- By default (every shipped profile, personal → managed) a raw read of a sensitive file is **denied**, and the agent gets the redacted `sir secret view` (key names, values masked) inline — so credential values never enter model context. A deliberate raw read escalates via `sir approve`; that approval marks the turn or session secret.
- Secret posture blocks untrusted egress and unapproved pushes.
- Secret taint is **monotonic**. The live secret flag is turn-scoped and clears on a turn boundary (instantly on the next user message, or after a 30s gap), but a per-session high-water mark persists. Crossing a turn boundary therefore *downgrades* the deny floor to an approval prompt on egress and pushes — it never silently reverts to the clean-session baseline (which would allow `push origin`). `sir unlock` is the explicit, logged way to clear the high-water mark.
- File/data lineage is independent of the turn counter: a secret copied or renamed into a file carries a derived-secret label that still blocks a later push, even across turn boundaries.
- `sir unlock` and explicit allowlists are visible, logged escape hatches.

**Residual risk:** sir does not follow secrets through model reasoning, paraphrase, or arbitrary child processes. Concretely, lineage tracks secrets that move *through the filesystem*; it cannot see a secret that is laundered through model context and re-emitted as fresh agent-authored bytes a turn later. The boundary between what is and is not caught across a turn boundary:

| Path | Across a turn boundary |
|------|------------------------|
| Read `.env` → next turn `curl`/push with the value inline | **Re-prompted** (high-water mark asks; not a hard deny, and the value itself is invisible to sir) |
| `cp .env leak.txt` → next turn push `leak.txt` | **Still denied** (the file carries a derived-secret lineage label) |
| Read `.env` → same turn `curl` | **Denied** (live secret-session deny floor) |

The first row is the honest residual: a context-laundered secret re-emitted inline is gated by an approval prompt, not blocked outright, because sir never observes the secret bytes on disk. The monotonic high-water mark guarantees that prompt fires instead of a silent allow; it does not — and cannot — recover the hard deny for data sir never saw.

#### Raw secret-read coverage (deny + redact)

The deny-raw-read gate fires on a classified *sensitive read* — verb `read_ref`
with a sensitive target. That covers two entry vectors and is explicit about
what it does not:

| Read vector | Covered? |
|-------------|----------|
| `Read` tool on a sensitive path | **Yes** — denied + redacted view |
| Bash via a known read program reading a sensitive path — `cat`, `tac`, `nl`, `head`, `tail`, `less`, `more`, `bat`/`batcat`, `xxd`, `hexdump`, `od`, `sed`, `awk`/`gawk`, `grep`, `rg`, `ag`, `ack`, `strings`, `file` (flag-aware; see `pkg/hooks/classify/reads.go`) | **Yes** — denied + redacted view |
| Interpreter one-liners that open the file themselves — `python -c "open('.env').read()"`, `node -e ...`, `ruby -e ...`, `perl -e ...` | **No** — the file argument is inside interpreter source, not a classified read; content is invisible to sir |
| A script or arbitrary binary that reads the file (`./run.sh` that cats `.env`) | **No** — sir sees the program invocation, not its file I/O |
| A read program not on the list, or obfuscated past the lexical classifier | **No** — prefix-aware shell classification, not full POSIX |
| Secrets arriving in **MCP tool output** | Not this gate — covered separately by MCP argument/response scanning and session taint (see *MCP injection and credential leakage*) |

This is intentionally a *content-never-enters-context* control for the common
read paths, not a complete read interceptor. The vectors marked **No** fall back
to the downstream floors: if such a read does taint the session (e.g. an
approved read, an env-var read, or MCP content), the secret-session egress wall
and lineage tracking still gate the exit. Widening this matrix (more read
programs, interpreter heuristics) is tracked as ongoing hardening; the honest
boundary is documented here rather than implied.

### Supply-chain posture tamper

**Threat:** a package install modifies hook config, posture files, or other sir-critical state.

**Mitigations:**

- Install sentinels are hashed before and after package installs.
- Posture drift triggers alerts and restore.
- `sir doctor` can verify and repair from canonical state.

**Residual risk:** sir catches filesystem consequences, not every runtime behavior of a malicious installer.

### MCP injection and credential leakage

**Threat:** remote content enters the model through MCP and steers the next action toward exfiltration or posture tamper.

**Mitigations:**

- MCP response scanning for common injection markers.
- MCP argument scanning for credential disclosure.
- Elevated posture after injection signals.
- Optional `sir mcp` and `sir mcp wrap` hardening for command-based servers.

**Residual risk:** MCP injection detection is **heuristic** — roughly 50 regex patterns covering authority framing, exfil instructions, credential harvesting, and hidden markers. Encoded, paraphrased, or non-English prompt-injection techniques that avoid the literal patterns are not guaranteed to be caught at `PostToolUse`. This is a known v1 limitation.

The fail-closed backstop is downstream, and it is the load-bearing piece of this mitigation: credential detection can still mark the session secret, and secret-session IFC plus delegation gating still apply on the next tool use even when the original MCP framing was opaque to the literal scanner. Untrusted MCP servers are also tainted on detection, so future traffic is treated with elevated posture.

There is also an **integrity-flow egress wall** that does not depend on the secret path. When the session has ingested untrusted content, the policy oracle escalates subsequent external network egress and outbound DNS from the clean-session approval prompt to a hard **deny** — the exfiltration leg of the lethal trifecta (private data + untrusted content + egress). This is the integrity dual of the confidentiality secret-session wall and follows the FIDES "low-integrity data must not reach a high-integrity sink" rule. It fires on two signals of different strength:

- a **strong, session-scoped** signal — a detected injection, or a read of external-package-provenance content — that holds for the rest of the session; and
- a **weak, turn-scoped** signal — *any* MCP tool response or fetched web content ingested **this turn**, set regardless of whether the ~50-pattern scanner flagged it. This is what catches an injection the literal scanner missed: it blocks the dangerous *same-turn* untrusted→egress shape, then clears at the turn boundary so cross-turn "fetch now, legitimately call an API later" workflows stay quiet (the "quiet on normal coding" contract).

The wall is enforced in `mister-core` (`policy_guards.rs`), mirrored in the Go local-fallback evaluator for parity, and only ever tightens the clean-session prompt into a deny — it never widens a deny. The escape hatch, after verifying intent, is `sir unlock`.

### Posture disablement

**Threat:** the agent edits hook config or other posture files to remove sir from the loop.

**Mitigations:**

- Writes to posture files are gated.
- The sir-owned hook subtree is hashed and restored from canonical state.
- Serious drift triggers deny-all until verified.

## Managed mode and runtime containment

Managed mode shifts the trust anchor from the local working copy to an org-owned manifest referenced by `SIR_MANAGED_POLICY_PATH`. In managed mode, `sir install` seeds state from that manifest and `sir doctor` restores managed lease and hook state instead of accepting new local baselines.

`sir run <agent>` is the optional below-hook layer:

- **macOS** uses localhost-only `sandbox-exec` plus a provider-aware local proxy with launch-time DNS pinning.
- **Linux** uses `unshare --net` containment with exact-destination egress allowlisting and durable-state protection.

Both are meaningful hardening layers and are the only parts of sir that provide OS-level prevention rather than hook-layer policy. They remain experimental and are not yet a cross-platform transparent egress firewall.

## Privacy contract

The optional OTLP exporter is off unless `SIR_OTLP_ENDPOINT` is set. When enabled, it exports verdict metadata to infrastructure you already operate. Secret-labeled file paths are hashed before emission. If `SIR_LOG_TOOL_CONTENT=1` is also enabled, sir may attach redacted investigation evidence, not raw secrets.

## What remains out of scope

Being explicit about what sir does not cover matters more than claiming broad protection. The following are outside the v1 threat model:

- **Model-internal reasoning and semantic laundering of secrets** — sir cannot follow a secret through the model's paraphrase or summarization.
- **Unrecognized child-process behavior below the shell classifier** — the shell classifier is lexical and can be evaded by novel wrappers.
- **Complete host containment on every platform** — `sir run` is macOS and Linux only, and still experimental.
- **Same-user OS-level protection** without help from the host agent or operating system.
- **Turn-boundary precision** — sir advances turns instantly on each user message and falls back to a 30-second gap heuristic, which can be wrong under unusual pacing. The monotonic secret high-water mark bounds the blast radius of an imprecise boundary: a stale or premature turn advance downgrades the deny floor to an approval prompt, never to a silent allow.
- **The default lease**, which is deliberately permissive to reduce developer friction and is not a hardened profile.

> **Note:** If you find a way to violate one of the in-scope guarantees above, that is a security bug and we want to hear about it. See the verification path below.

## Standards mapping

sir's controls map onto the public agent-security frameworks so reviewers can
place each guarantee in a shared taxonomy. This is the basis of the evaluation
story, alongside the reproducible benchmark harness (`eval/agentdojo/`) and the
signed-build + SLSA-provenance + SBOM release artifacts (see the release workflow
and `docs/contributor/supply-chain-policy.md`).

| sir control | OWASP LLM / Agentic | MITRE ATLAS | CSA MAESTRO | MCP-T |
|---|---|---|---|---|
| Allow/ask/deny tool-call mediation | LLM06 Excessive Agency; ASI02 Tool Misuse | M0029 human-in-the-loop; M0030 restrict tool use on untrusted data | Agent Frameworks | — |
| Secret-session + derived-lineage egress wall | LLM02 Sensitive Info Disclosure | T0024 exfiltration | Data Operations | T5 |
| Integrity-flow egress wall (untrusted → egress) | LLM01 Prompt Injection; ASI01 Goal Hijack | T0051 LLM Prompt Injection | Foundation Models | T4 |
| MCP injection scan + server taint | LLM01; ASI06 Memory/Context Poisoning | T0051 (indirect) | Agent Frameworks | T3, T4 |
| MCP tool-schema pinning (`sir mcp scan`) | LLM03 Supply Chain; ASI04 Agentic Supply Chain | T0011.002 Poisoned AI Agent Tool | Deployment Infra | T6, T11 |
| Posture-file tamper detection + restore | LLM03; ASI05 Unexpected Code Execution | T0011 Poison Training/Config | Deployment Infra | T6 |
| Install-sentinel supply-chain hashing | LLM03 Supply Chain | T0010 ML Supply Chain Compromise | Data Operations | T11 |
| Least-privilege lease; managed mode | LLM06; ASI03 Identity & Privilege Abuse | M0026 least-privilege agent perms | Agent Frameworks | T1, T2 |
| Below-hook runtime containment (`sir run`) | — | M0005 control access to systems | Deployment Infra | T8 |
| Hash-chained ledger; OTLP (no raw secrets) | LLM02 | logging/monitoring | Eval & Observability | T12 |

The mapping is a guide, not a certification. Where a control is heuristic (MCP
injection scanning, shell classification) the relevant row is a *detection*
contribution, backstopped by the deterministic IFC floors; the residual-risk
sections above are the honest boundary.

## Verification path

If you are a researcher evaluating sir, start here. These are the fastest paths to form your own opinion before trusting a release or rollout, and to reproduce the claims above:

- [validation-summary.md](validation-summary.md) — the short evidence view.
- [security-verification-guide.md](security-verification-guide.md) — runnable end-to-end checks against a fresh install.
- `go test ./...` — full Go test surface including IFC, hooks, ledger, and MCP scanning.
- `cargo test --locked` — `mister-core` policy oracle and shared protocol.
- `make public-contract` — keeps shipped docs and toolchain promises aligned with the code.

To contribute findings, file a bug report for false negatives or classifier gaps, and follow the security vulnerability process for anything that crosses an in-scope guarantee. We would rather hear about a credible bypass than ship around one.
