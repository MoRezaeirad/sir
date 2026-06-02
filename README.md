# SIR — Sandbox in Reverse

> Keep AI coding agents productive while gating secrets, shells, networks, package scripts, CI/CD, and tool trust.

**sir** is a local-first security runtime for AI coding agents. It detects installed coding agents, installs hooks for selected enabled protection targets, classifies proposed actions, tracks secret-tainted sessions, and records every `allow`, `ask`, or `deny` in a tamper-evident ledger. For the current testing build, Claude Code is the enabled hook-install target; Cursor, Gemini CLI, and Codex remain visible in discovery/support/status surfaces but are disabled for hook installation.

Quiet on normal coding. Loud on dangerous transitions.

<div align="center">

[![release](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.github.com%2Frepos%2Fsomoore%2Fsir%2Freleases%3Fper_page%3D1&query=%24%5B0%5D.tag_name&label=release&style=flat-square&labelColor=141311&color=B4660A)](https://github.com/somoore/sir/releases)
[![license](https://img.shields.io/badge/license-apache_2.0-2A2824?style=flat-square&labelColor=141311)](LICENSE)
[![platform](https://img.shields.io/badge/platform-macos_%C2%B7_linux_%C2%B7_windows-1E6E85?style=flat-square&labelColor=141311)](docs/getting-started.md)

</div>

## Why use sir?

AI agents can read files, run shells, call MCP tools, install packages, and push code. sir puts a policy boundary at the moment model-controlled work crosses into secrets, external network, CI/CD, package scripts, or tool trust.

- Blocks raw credential reads while returning redacted views.
- Carries taint across turns, so secret-to-egress transitions are denied.
- Stays local, auditable, and open: policy is readable and evidence stays on your machine unless you export it.

## Quick start

macOS / Linux:
```bash
curl -fsSL https://raw.githubusercontent.com/somoore/sir/main/scripts/download.sh | bash
sir config             # discover agents and choose an enabled protection target
sir on
sir status
```

Windows PowerShell:
```powershell
irm https://raw.githubusercontent.com/somoore/sir/main/scripts/download.ps1 | iex
sir config
sir status
```

## How it decides

Hooks and MCP proxy signals are normalized into intent, target, sensitivity, attribution, and session taint. Rust `sir-core` owns the final deterministic decision. Go provides explicit evidence through `EvaluationInput`, then handles stateful post-decision work: ledgering, prompt bounding, provider execution, and local UX.

## What it catches

In a protected agent session, ask the agent to read `.env`: sir denies the raw read and returns a redacted key view. Then ask it to run `curl https://httpbin.org/get` while credentials are live in the session: sir blocks the secret-to-egress transition.

```bash
sir why
sir explain
sir log verify
```

## Agent support

<!-- BEGIN GENERATED SUPPORT SUMMARY -->
- **Claude Code** — **Reference support.** Full 11-hook lifecycle with native interactive approval and complete tool-path coverage.
<!-- END GENERATED SUPPORT SUMMARY -->

Run `sir support --json` for the machine-readable support contract.

Current testing target: Claude Code is enabled for hook installation. Non-Claude adapter coverage is documented so status, parsing, discovery, and compatibility work remain honest, but non-Claude install targets are disabled in this build.

## Install / update / uninstall

```bash
sir install --agent claude
sir config             # discover agents and choose an enabled target
sir update
sir uninstall
```

## Verify it

```bash
sir status
sir doctor
sir support
sir log verify
```

## Commands

```bash
sir on | sir off
sir why | sir explain
sir log tail | sir log verify
sir support --json | sir doctor --json
```

## Honest limits

Default `hook_gate` mode enforces through cooperative agent hooks. It is not a VM, kernel sandbox, or endpoint agent, and it can miss detached children, script-file exfil such as `python myscript.py`, and actions the agent never emits as hooks.

`sir run` is experimental macOS/Linux containment. Windows is hook mediation only. Managed mode shifts the trust anchor to a signed policy path through `SIR_MANAGED_POLICY_PATH`. `sir status` reports what the active mode can actually enforce.

## Extend sir

sir is open, flexible, and pluggable. Bring your own sandbox or effect provider, policy engine such as OPA or Cedar, signal source such as Falco/eBPF/MCP telemetry, and observability export for JSONL, OTLP, SIEM, S3, or webhooks.

The API and SDKs make provider work small: providers speak stdio JSON, can be written in any language, and can raise risk or apply effects without overriding sir's native safety floors. Start with [providers](docs/providers.md), [API](docs/api.md), and [SDK](docs/sdk.md).

## Contribute

Good contribution areas: agent adapters, Cursor and MCP conformance fixtures, stronger effect providers, evasion harness cases, provider examples, and docs that make guarantees reproducible.

```bash
# Requires [Rust 1.94.0](https://rustup.rs/) (pinned in rust-toolchain.toml)
# Requires [Go 1.22+](https://go.dev/dl/) with toolchain auto-fetch to go1.25.10
make contributor-check
```

## Documentation

[Getting Started](docs/getting-started.md) · [Architecture](docs/architecture.md) · [Competitive Analysis](docs/competitive-analysis.md) · [API](docs/api.md) · [SDK](docs/sdk.md) · [Providers](docs/providers.md) · [Policy](docs/policy.md) · [Observability](docs/observability.md) · [Security](docs/security.md)

> [!WARNING]
> SIR is experimental and in active development on the `sir-v2` branch. Test on your own machine, not shared infrastructure. Run `sir doctor` if anything breaks. [Report issues](https://github.com/somoore/sir/issues).

Apache 2.0 - see [LICENSE](LICENSE).
