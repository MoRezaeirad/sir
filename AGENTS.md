# sir — Sandbox in Reverse

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

Security runtime for AI coding agents. Go CLI, Rust policy oracle, quiet on normal coding, loud on dangerous transitions.

## Core model

- `sir` collects facts, manages state, writes the ledger, and talks to host-agent hooks.
- `mister-core` decides allow / deny / ask from normalized inputs.
- Go may add restrictions from facts Rust cannot see. Go must never widen a Rust deny.

## Layout

```text
cmd/sir/        CLI entrypoints
pkg/agent/      Codex / Gemini / Codex adapters
pkg/hooks/      hook handlers, shell mapping, labels, MCP scans
pkg/session/    durable posture and secret-session state
pkg/ledger/     append-only decision history
pkg/runtime/    optional below-hook containment
pkg/mcp/        MCP inventory and rewrite
pkg/core/       MSTR/1 bridge to mister-core
mister-core/    Rust policy oracle
mister-shared/  Rust shared protocol and types
testdata/       fixtures and invariant inputs
tests/          higher-level integration coverage
```

## Non-negotiables

1. Go stays standard-library only unless there is a reviewed exception.
2. `mister-core` and `mister-shared` stay zero-dependency and zero-unsafe.
3. Corrupted state fails closed. Only `os.IsNotExist` can seed fresh defaults.
4. Go verb strings must stay aligned with Rust verb parsing.
5. Session mutation must stay lock-safe and atomic on disk.
6. Path-sensitive checks must resolve symlinks before classification.
7. The ledger and telemetry never store raw secrets.
8. Hook handlers return well-formed deny JSON on internal errors.
9. Posture-file writes always ask.
10. Public guarantees need tests or contract checks.

## Supply chain rules

These rules encode the existing supply chain posture. Violating them silently degrades integrity guarantees.

11. External tool downloads in CI must verify SHA256 **fatally** — never `|| echo` or any other non-zero exit suppression. The pattern is always: `curl … | sha256sum --check` then extract. A verification failure must abort the job.
12. Every GitHub Action must be pinned to a full commit SHA, never a tag or branch ref. Format: `uses: owner/action@<40-char-sha> # vX.Y.Z`. Dependabot keeps these current.
13. Hand-pinned tool installs (syft, slsa-verifier, zizmor, actionlint, cargo-deny, govulncheck, gosec) must bump version **and** SHA256 in the same commit. The comment `# Bump both values together` is a contract, not optional.
14. The binary-size canary in `release.yml` must cover every archive format shipped. Currently `.tar.gz` (Unix) and `.zip` (Windows). Adding a new target format requires extending the glob.
15. No new external Go module dependencies without explicit review and AGENTS.md amendment. The zero-external-dep invariant is enforced by CI but must also be a conscious decision.
16. `sir-core`, `mister-core`, and `mister-shared` stay zero external Rust crate dependencies. The CI allowlist in `Cargo.lock` enforces this; expanding it requires explicit approval.
17. SLSA provenance restoration is tracked in `release.yml` (search for "SLSA provenance — deferred"). Do not silently drop it — re-enable when `slsa-github-generator` ships the exit-27 fix.

## Working docs

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/contributor/core-mental-model.md](docs/contributor/core-mental-model.md)
- [docs/contributor/security-engineering-core.md](docs/contributor/security-engineering-core.md)
- [docs/contributor/supply-chain-policy.md](docs/contributor/supply-chain-policy.md)
- [docs/research/security-verification-guide.md](docs/research/security-verification-guide.md)
