# Codex Support

> [!NOTE]
> sir is experimental — test on your own machine, not shared infrastructure. `sir doctor` recovers any wedged state; [report bugs](https://github.com/somoore/sir/issues).

sir — Sandbox in Reverse — is an experimental security runtime for AI coding agents. Codex has **limited adapter support** today: sir can parse and evaluate Codex hook payloads where Codex exposes Bash, native-write, MCP, and permission-request hooks, but lifecycle coverage remains narrower than Claude Code and upstream hook delivery is still the boundary. `sir install` detects Codex, but Codex hook installation is disabled in this testing build. If your workflow needs installed hook protection right now, choose the currently enabled target: Claude Code.

> [!NOTE]
> Minimum supported version is `0.118.0`. `sir doctor` warns on older versions.

<!-- BEGIN GENERATED SUPPORT DOC -->
## Status: limited support on codex-cli 0.118.0+ (partial tool coverage)

| Surface | Status | Notes |
|---|---|---|
| Hook events wired | ✅ 6 events | PreToolUse, PermissionRequest, PostToolUse, UserPromptSubmit, SessionStart, Stop |
| Tool-path coverage | ⚠ Partial | Bash, native write, MCP, and permission-request hooks are registered where the host agent emits them; missing lifecycle hooks remain documented below. |
| Feature flag | ⚠ Required | Enable `codex_hooks` before any registered hooks can fire. |
| Interactive approvals | ❌ No | Codex folds sir's internal ask verdict into block with remediation text. |
| Permission-request broker | ✅ Yes | sir can broker agent-native permission request events through the same policy path. |
| File-read IFC labeling | ✅ Yes | Bash-mediated sensitive reads (cat/sed/head/tail/grep/etc.) are promoted to read_ref before execution. |
| File-write pre-gating | ✅ Yes | apply_patch/Edit/Write posture mutations are pre-gated when Codex emits their hooks; sentinel hashing remains the backstop. |
| Shell classification | ✅ Yes | Bash commands are classified for egress, DNS, persistence, sudo, and install risk. |
| MCP tool hooks | ✅ Yes | sir registers Codex MCP matchers and sees MCP arguments/responses when Codex emits mcp__* tool hooks. |
| Delegation gating | ❌ No | Codex exposes no SubagentStart-equivalent hook. |
| Config change detection | ❌ No | Codex exposes no ConfigChange-equivalent hook. |
| InstructionsLoaded scanning | ❌ No | Codex exposes no InstructionsLoaded-equivalent hook. |
| Elicitation interception | ❌ No | Codex exposes no Elicitation-equivalent hook. |
| Terminal posture sweep | ✅ Yes | The final posture sweep runs on Stop because Codex exposes no SessionEnd hook. |
<!-- END GENERATED SUPPORT DOC -->

## Current install boundary

`sir install` rejects `--agent codex` in this build and does not create or update `~/.codex/hooks.json` or `~/.codex/config.toml`. Use the enabled target for installed hook protection:

```bash
sir install --agent claude
sir doctor
```

Codex hooks still require `codex_hooks` when evaluating an existing or manual Codex hook setup, but SIR will not enable that feature flag while Codex install is disabled.

## What works today

Codex is useful with sir when the workflow stays on covered tool paths:

- External egress blocking, including the integrity-flow wall that blocks egress after untrusted content (MCP output) was ingested this turn.
- DNS and `sudo` classification.
- Shell-obfuscation decomposition (`echo $(curl …)`, backticks, `eval`) and fail-closed on opaque `| sh` execution on the Bash path.
- Package-install and posture sentinel checks.
- Bash-mediated sensitive reads such as `cat .env` or `sed -n ... .env`.
- Native `apply_patch` / `Edit` / `Write` posture pre-gating when Codex emits those hooks.
- MCP argument and response scanning when Codex emits `mcp__*` tool hooks.
- Credential output scanning.

If your Codex session is mostly shell, patching, build, test, git, and approved MCP calls, you still get meaningful enforcement.

## The important limitation

Codex does not currently expose the full lifecycle hook surface Claude Code exposes. sir registers the tool hooks Codex makes available, but upstream hook delivery remains the boundary.

The biggest consequence is the lifecycle gap:

- sir has no Codex `SubagentStart`, `ConfigChange`, `InstructionsLoaded`, `SessionEnd`, or `Elicitation` equivalent.
- Posture drift is still caught by sentinel hashing.
- The final posture sweep runs on `Stop` because Codex has no `SessionEnd`.

That is why Codex is documented as limited support, not near-parity.

## Other gaps

- No sub-agent delegation hook.
- No config-change hook.
- No instructions-loaded hook.
- No elicitation hook.

## Troubleshooting

- **`sir doctor` warns about `codex_hooks`:** enable it only if you are maintaining an existing or manual Codex hook setup.
- **`sir status` shows missing Codex hooks:** Codex install is disabled in this build; use the enabled target for installed protection.
- **A file write was not pre-gated:** confirm the Codex version and whether the tool emitted `apply_patch`, `Edit`, or `Write` through the hook surface.
