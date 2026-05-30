# Runtime Taint-Driven Containment

> **Status:** experimental. The macOS taint gate described in §3 ships today; the
> Linux story (§4) and the taint-driven *default* (§5) are design, not yet
> implemented. This document is the honest roadmap.

## 1. Why

sir's hook layer is **advisory**: it classifies a tool call and returns
allow/ask/deny, but a tool executor that ignores the deny still makes that one
call. sir detects the violation (a `PostToolUse` for a denied id) and locks the
session, but it cannot *prevent* the call. The only layer that can physically
prevent egress is `sir run` — below-hook OS containment (a network namespace +
iptables on Linux, a local proxy under `sandbox-exec` on macOS).

Until now that containment enforced only a **static allowlist**: egress was
permitted to approved hosts regardless of what the agent had read. That leaves a
gap precisely where it matters — if the agent reads a secret (or ingests
untrusted content) and then exfiltrates to an *allowlisted* host, the OS layer
did nothing, because it had no view of session taint. The hook layer would deny
that egress, but the whole point of `sir run` is to hold when the hook is
bypassed.

**Taint-driven containment** closes that gap: the OS egress chokepoint consults
the live session posture and denies external egress under the same conditions
the hook layer hard-denies, so the floor holds even with the hook out of the
loop.

## 2. The hard-deny / ask boundary

The hook layer has two kinds of egress restriction:

- **Hard deny** — a secret is live in context this turn; untrusted content was
  ingested (the integrity-flow egress wall); or the session is locked
  (`DenyAll`). These are non-negotiable.
- **Ask** — the cross-turn secret **high-water mark** (`SessionEverSecret`).
  Once a session has ever held a secret, egress re-prompts across turn
  boundaries (never a silent allow) until `sir unlock`.

The OS proxy **mirrors only the hard denies**. It deliberately does *not* act on
the high-water mark, because:

1. The proxy cannot offer an interactive prompt mid-connection.
2. Treating an *ask* as a *deny* would block egress the user already approved at
   the hook layer, breaking legitimate cross-turn workflows.

This keeps the proxy strictly a backstop for the hook's hard floors — additive
denial, never a new source of friction the user can't resolve. It is consistent
with the project rule that Go may be *stricter* than Rust but the user-visible
contract must stay coherent.

### Conditions the gate denies on

| Session signal | Meaning | Proxy action |
|----------------|---------|--------------|
| `DenyAll` | session locked (hook-integrity violation, corruption) | deny external egress |
| `SecretSession` | a secret is live in context this turn | deny external egress |
| `UntrustedContentThisTurn` / `RecentlyReadUntrusted` | untrusted content ingested | deny external egress |
| `SessionEverSecret` only | cross-turn high-water mark (an *ask*) | **allow** (not the proxy's call) |
| corrupt/unreadable posture | indeterminate | deny (fail closed) |
| loopback destination | not exfil | always allow |

## 3. macOS implementation (shipped)

On macOS, `sir run` routes the agent's traffic through an in-process HTTP
CONNECT + SOCKS5 proxy (`pkg/runtime`, `LocalProxy`). The agent writes session
state to a **shadow state home** seeded before launch; its hooks update that
shadow posture as it runs.

`LocalProxy.EnableTaintGate(projectRoot, shadowStateHome)` attaches a
`postureGate` that, at each egress decision (`serveHTTP`, `serveConnect`, the
SOCKS path), after the allowlist check and before the dial:

1. reads the shadow posture (re-reading only when its file mtime changes, so the
   hot path is a single `stat`);
2. if a hard-deny condition holds and the destination is not loopback, returns
   `403` (HTTP) / SOCKS failure and records a blocked egress.

Fail-closed: a *corrupt* posture file denies external egress; a *missing* one is
treated as clean (it just hasn't been written yet — the allowlist still applies).

**Established tunnels are revalidated.** A CONNECT/SOCKS tunnel opened while the
session is clean would otherwise keep carrying bytes for its lifetime, so a
secret read *after* the tunnel opens could exfiltrate over the existing TLS/SSH
connection. A per-tunnel watcher re-checks the gate on an interval (default 1s,
cheap because the posture read is mtime-keyed) and tears both ends down on a
hard-deny transition. The recheck interval bounds the residual window in which a
freshly-tainted session can still use an open tunnel.

This is unit-tested for every condition above, including mid-tunnel teardown,
and proven end-to-end through the proxy request path
(`pkg/runtime/proxy_taint_test.go`).

## 4. Linux (design)

Linux containment uses `slirp4netns` + `iptables` inside a user+net namespace,
not the Go proxy, so the egress decision lives in kernel packet filtering rather
than an application chokepoint. Taint-driven denial there means **dynamically
tightening the ruleset** when the session becomes tainted:

- A small supervisor in the sir parent watches the shadow posture (the same
  signal the macOS gate reads) and, on a hard-deny transition, swaps the
  namespace's egress chain to drop all non-loopback traffic; on `sir unlock` /
  turn reset that clears the deny, it restores the allowlist chain.
- Open challenge: long-lived connections established *before* taint. The macOS
  proxy already handles this with a per-tunnel watcher that tears the tunnel
  down on a hard-deny transition (§3); the Linux equivalent must also drop
  established conntrack entries (`conntrack -D` / a `--ctstate` rule) when it
  swaps the chain, so an in-flight connection cannot outlive the taint.

This is deferred: it is more invasive, needs root-in-namespace rule edits at
runtime, and wants its own test rig. The macOS gate is the proof of concept.

## 5. Path to a taint-driven default

Making `sir run` (rather than `sir install`) the default is the long-term goal —
prevention, not just detection. It is a **hard-to-reverse posture change for
every user** (OS-level containment can break legitimate workflows: VPNs,
corporate proxies, unusual toolchains), so it must be staged and gated on
evidence, never flipped silently.

Proposed stages:

1. **Parity** (in progress). Taint-driven egress on both macOS and Linux, at
   feature parity with the hook-layer hard floors. *(macOS done; Linux per §4.)*
2. **Readiness surface.** A preflight (`sir run --check` / `sir doctor`
   integration) that reports whether containment is available and what it would
   enforce, and a one-command opt-in (`sir config containment on`) that flips
   the default for *that user* without touching anyone else.
3. **Opt-in telemetry of friction.** Measure how often containment blocks
   *legitimate* egress in real use, via the existing friction ledger, so the
   default decision rests on data, not vibes.
4. **Default with escape hatch.** Only once friction is demonstrably low: make
   contained launch the default, with a clearly-documented `sir run --no-contain`
   / `sir config containment off` escape, and a loud first-run notice.

Until stage 4's criteria are met, the default stays `sir install` (advisory +
detection) and `sir run` stays the explicit, experimental opt-in. This document
will be updated as each stage lands.
