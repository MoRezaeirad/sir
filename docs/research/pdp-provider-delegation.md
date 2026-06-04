# Authoritative Policy Providers (PDP Delegation)

> Status: implemented (Chunks 1–2 merged; latency work is Chunk 3, a decision
> cache deferred in favor of a warm-provider sidecar). This doc is the rationale
> of record for the scoped invariant amendment.

## 1. Problem

`sir` should be *quiet on normal coding, loud on dangerous transitions*, but feels
like "gates by default." The structural cause: **external policy could only ever
add friction, never remove it.** A `policy_provider` was composed advisory-only —
`compose_policy_verdicts` (`mister-core/src/policy.rs:132`, Go
`pkg/kernel/kernel.go:151`) let a provider escalate `allow → ask` and nothing
else; a non-advisory verdict was a no-op. So OPA / Rego / Cedar could only tighten,
never *grant* authority native would gate — the inverse of the point.

## 2. Goal

Let a `policy_provider` be **authoritative**: when configured and reachable, its
verdict *is* the decision — including granting actions native would gate; native
`sir` (Rust oracle + Go) governs only when none is configured. This is **PDP
(Policy Decision Point) delegation of the core decision**, decided with the
operator:

- **Trust model:** the provider overrides the `core.Evaluate` decision, not the
  pre-decision integrity floors (§7).
- **Floor default — "policy is the whole truth":** within the delegated surface,
  native verdict floors do not run unless the policy re-implements them. Enabling
  PDP is an informed decision to make the provider the posture for that surface;
  the exfiltration-protection tradeoff was made explicit at decision time.
- **Failure model — "fail closed":** "policy is the whole truth" governs what
  happens when the provider **answers**, not when it **cannot** — a
  configured-but-unreachable authoritative provider must never silently grant.

### 2a. Decision is delegated; fact-gathering is NOT

"Floors bypassed" means the native **verdict** floors do not decide the outcome.
sir still computes every upstream fact on every request: taint tracking, IFC
labels, the secret-session high-water mark, untrusted-ingestion detection,
attribution. Those facts populate the provider's request; skipping them would
degrade "policy is the whole truth" to "policy decides **blind**."

### 2b. The escape hatch must carry the signals

"Floors off is acceptable because the operator can re-implement the wall in
policy" only holds if the request carries the signals the native walls key on:
`session_secret` (live), `session_was_secret` (high-water),
`session_untrusted_read` (strong), `session_untrusted_this_turn` (turn-scoped).
Chunk 1 extended the request schema (`sir.policy_request.v1`) to carry that full
integrity/session set explicitly, alongside the taint list; the SDK docs show the
exfil wall re-implemented in Rego as the canonical example. Without it the escape
hatch would be illusory.

## 3. Invariant amendment

This change **amends a written non-negotiable.** CLAUDE.md core model said "Go
must never widen a Rust deny," and `core-mental-model.md` framed Go as narrowing
authority with "the upper bound = read `mister-core`."

Under PDP delegation an **authoritative** provider verdict **does** replace the
native decision and may widen it. The amendment is **scoped**: it applies *only*
when an authoritative provider is configured and produces a verdict. With no
authoritative provider the invariant holds unchanged — native remains the upper
bound, and `TestDifferentialFallbackNeverMorePermissive` (empty-`PolicyVerdicts`
corpus) is unaffected. Both docs were updated in the same change set; the
upper-bound framing is now "read `mister-core` **OR** the active authoritative
policy."

## 4. Failure-mode table (the safety core)

Every row is **fail closed** when the provider is *authoritative and configured* —
the action does not silently proceed; it is `deny`ed or held for approval (`ask`).

| Situation | Today (advisory) | PDP authoritative |
|---|---|---|
| **Empty stdout** (SDK "quiet allow") | no verdict → native floors | **FAIL CLOSED.** Silence MUST NOT mean grant; the quiet-allow convention inverts. |
| Provider unreachable / spawn error | non-fatal → native floors | **FAIL CLOSED** (deny/ask). Never fall to native-allow. |
| Provider timeout (>budget) | non-fatal → native floors | **FAIL CLOSED.** |
| Malformed / unparseable output | parse error → native floors | **FAIL CLOSED.** |
| Verdict = explicit `allow` | (skipped, no-op) | **GRANT** — the whole point. |
| Verdict = `ask` / `deny` | escalates allow→ask only | Verdict taken as-is. |
| No authoritative provider configured | native governs | native governs (unchanged). |

The most dangerous line is **empty stdout** — today the SDK's quiet-allow signal
(silence = grant), which for an authoritative provider must flip to fail-closed.

## 5. Configuration & trust boundary

- Authoritative is **explicit operator opt-in** via a registry field
  (`authority: "authoritative"` vs default `"advisory"`), never a wire
  self-declaration.
- **One authoritative `policy_provider` at a time** — the registry already
  enforces one active `policy_provider` (`exclusiveKind`); authoritative is a
  property of that one.
- Registry mutation (who is authoritative) is a posture-file write that **asks**
  (#9), enforced *outside* the PDP path — O3 (§9).

## 6. `ask` vs `deny` on failure, and latency

Fail-closed default is **`ask`** so a transient sidecar blip holds rather than
hard-blocks; **managed mode forces `deny`** (a missing PDP there is a control
failure); a per-provider `on_failure: ask|deny` override exists. A *sustained*
outage becomes a prompt-storm — an accepted fail-safe (loud beats silent-grant).

Latency: a fail-closed PDP on the old 200ms budget would re-introduce friction.
**Preferred fix:** run the provider **warm** — a localhost sidecar/daemon rather
than spawn-per-call — plus a raised authoritative timeout (~1s, capped, so a hung
provider becomes a fast fail-closed `ask`), keeping every decision a live
consultation.

**OPTION (deferred):** a durable decision cache was considered but is *not* the
committed approach — caching grants on the security path trades away live
consultation. If a cache is ever built, these constraints are mandatory: a
complete key over the *entire* normalized input `(action, target, resolved_actor,
sorted(taint), session flags, policy_version_hash)`; cache `allow`/`ask` only,
never `deny`, never a fail-closed result; fail closed on a session-hash mismatch;
hard-invalidate on any posture transition.

## 7. Scope — what PDP does NOT delegate (non-delegable floors)

The override sits AFTER `core.Evaluate`. Integrity/tamper floors short-circuit in
`pkg/hooks/evaluate.go` **before** `evaluatePolicy` runs, so they are NOT subject
to the authoritative override. All are deny/ask — fail-safe (native gates where a
provider might grant; never the reverse). Per operator decision, all stay
non-delegable hard floors even under PDP:

1. **sir-state-tamper** (`sirStateTamper`) — O3 self-amplification boundary
   (agent writing into `~/.sir`).
2. **sir self-modification** (`VerbSirSelf` floor) — shell-command counterpart of
   row 1: `sir provider authoritative|use|swap|…` posture-changing subcommands run
   via the sir binary (bypassing the row-1 file-write floor). O3-critical now the
   `sir provider authoritative` CLI exists: without it an injected agent under a
   permissive provider could promote its OWN provider and seize the decision
   point. Held for approval (ask), pre-override.
3. **posture-file writes** (#9) · 4. **outbound secret leak** — the exfil wall ·
   5. **DNS-tunnel exfil** · 6. **tainted-MCP / injection** ·
   7. **delegation-after-injection** · 8. **opaque-shell escalation**.
   (Functions: `gitConfigSensitiveAsk`, `outboundSecretLeak`, `dnsTunnelEscalation`,
   `evaluateTaintedMCPServer`, `evaluateDelegationHardDeny`, `opaqueShellEscalation`.)

So "policy is the whole truth" applies to the `core.Evaluate` decision surface,
NOT these pre-decision floors. **Delegation of the core decision, not full
delegation.** Other floors (e.g. the exfil wall) could be made delegable later as
deliberate opt-ins; the O3/self-amplification rows (1–3) must always stay hard.

## 8. Insertion point — substitution in the Go orchestrator

Both pure compose functions stay **UNTOUCHED** (Rust `compose_policy_verdicts`,
Go `composePolicyVerdicts`): Rust never sees provider failures or the registry, so
fail-closed and `IsAuthoritative()` live only in Go; leaving compose alone keeps
Go/Rust parity by construction. The entire authoritative decision lives in the Go
orchestrator, at the single production chokepoint (verified) `pkg/hooks/evaluate.go`
→ `evaluatePolicy` → `core.Evaluate` (forks Rust-binary and Go-fallback). The
substitution:

`collectPolicyVerdictsFromRegistry` detects the active authoritative entry via
`entry.IsAuthoritative()` (registry only — never the wire flag) and holds its
verdict aside, NOT passing it to Rust as a grant. Rust receives only advisory
verdicts; its floored result becomes `native_base_verdict` (the audit base). The
orchestrator then OVERRIDES the final verdict with the authoritative one. Floors
run-then-discard, harmless: `kernel.Evaluate` is pure and taint accrues from
`action.Sensitivity`, not the verdict.

Fail-closed lives in Go, where failures are visible. The deadliest case is NOT the
error branch: `parsePolicyVerdicts` returns `(nil, nil)` on empty stdout — so
`IsAuthoritative() && len(verdicts)==0 && err==nil` is itself fail-closed.
Multiple verdicts from one provider reduce to the **most restrictive**
(deny > ask > allow), so a provider bug cannot accidentally grant. The ledger
records `decided_by`, `native_floors_bypassed: true`, and `native_base_verdict` —
the audit trail IS the safety net (no raw secrets, #7).

### 8c. The override must be sealed through EVERYTHING downstream (the lesson)

The "single-point override" framing was too optimistic: the `core.Evaluate`
verdict passes through THREE downstream surfaces that can mutate it, each a
fail-open hole unless sealed (one structural guard each, not per-site flags):

1. **Native convenience downgrades** (evaluate.go ~326–409): six blocks turn
   ask→allow (SilentApprovedHosts, ReuseSessionApprovals, AutoLeaseApprovedRemotes
   ×2, NarrowEnvReads, manual approval) — an authoritative ASK would be silently
   allowed. *Seal:* set `coreResp.AuthoritativeActive` in the override block and
   wrap the ENTIRE convenience region in `if !AuthoritativeActive`.
2. **Observe mode** (`applyObserveMode`) downgrades deny/ask→allow unless `Floor`
   — an authoritative DENY would become allow. *Seal:* `applyCoreEvaluationResult`
   marks `hookResp.Floor=true` when AuthoritativeActive. (`applyThinkingGuard` only
   tightens ask→deny — fail-safe, no seal needed.)
3. **Corrupt registry** (`loadProviderRegistry`) returned an empty registry on a
   parse error → "no authoritative provider" → native governs → fail-open (#3).
   *Seal:* `loadProviderRegistryChecked` surfaces the error and `evaluatePolicy`
   fails closed on a corrupt registry; a **missing** file is nil and proceeds to
   native.

**Lesson** (same shape as the bypass-floors finding): "the override doesn't hold
because something I didn't enumerate runs after it." Authoritative-final must hold
through every post-`core.Evaluate` surface — seal the whole surface, not one spot.

## 9. Resolved decisions

Authority is **registry-only** (§8). O1 on-failure → §6; O2 latency → §6; O3
self-amplification: hard NO — the provider governs *actions*, not *sir's config*,
so registry mutation stays a posture-file write that asks, outside the PDP path
(§5). The two unique to this section:

- **O4 — audit:** extend `ProviderPolicyEvidence` with `decided_by`,
  `native_floors_bypassed`, `native_base_verdict`, `rules_matched`, and on failure
  `provider_failure:{reason,on_failure}`. The audit trail is the safety net.
- **O5 — orthogonal layers:** PDP decides allow/ask/deny; an `effect_provider`
  independently enforces containment. An authoritative `allow` means "policy
  permits this action," NOT "run outside the sandbox" — it still runs inside any
  effect_provider jail.

## 10. Build plan & test net

Safety valve: **explicit operator opt-in = zero default blast radius.** Shipped in
chunks behind the opt-in, fail-closed paths + adversarial net FIRST; docs amend
WITH the behavior. The net asserts that for an authoritative provider every
failure mode (empty stdout — written first — unreachable, timeout, malformed,
wrong schema) yields ask-or-deny, never allow-where-native-would-gate. The
`sir provider authoritative` CLI is itself gated as a non-delegable sir-self floor
(§7 row 2) so an injected agent can't self-promote even under a permissive
provider.
