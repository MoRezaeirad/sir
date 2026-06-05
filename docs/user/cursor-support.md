# Cursor Support

> [!NOTE]
> sir is experimental - test on your own machine, not shared infrastructure. `sir doctor` recovers any wedged state; [report bugs](https://github.com/somoore/sir/issues).

sir - Sandbox in Reverse - is an experimental security runtime for AI coding agents. Cursor has **near-parity adapter support** today, not reference support. sir can parse and evaluate Cursor hooks for shell, read, MCP, prompt, delegation, stop, and session-end paths, plus after-action file-edit backstops, and sir enforces only when Cursor emits the corresponding hook. `sir install` detects Cursor, but Cursor hook installation is disabled in this testing build. Cursor hook ask/allow behavior is not treated as a reliable security boundary, so sir folds internal `ask` verdicts into deny-with-remediation text.

> [!NOTE]
> Minimum supported version is `3.6.21`. `sir doctor` warns on older versions.

<!-- BEGIN GENERATED SUPPORT DOC -->
## Status: near-parity support on Cursor 3.6.21+

| Surface | Status | Notes |
|---|---|---|
| Hook events wired | ✅ 15 events | preToolUse, postToolUse, postToolUseFailure, beforeShellExecution, afterShellExecution, beforeMCPExecution, afterMCPExecution, beforeReadFile, afterFileEdit, subagentStart, beforeSubmitPrompt, sessionStart, preCompact, stop, sessionEnd |
| Tool-path coverage | ⚠ Hook-scoped | Shell, read, MCP, prompt, delegation, and final-sweep hooks are registered; file edits rely on preToolUse when Cursor emits it plus afterFileEdit/posture backstops. |
| Interactive approvals | ❌ No | Cursor hook ask behavior is not treated as a reliable security boundary; sir folds ask into deny with remediation text. |
| Permission-request broker | ❌ No | Cursor exposes no PermissionRequest-equivalent hook. |
| File-read IFC labeling | ✅ Yes | beforeReadFile and preToolUse label sensitive reads before execution where Cursor emits those hooks. |
| File-write pre-gating | ❌ No | Cursor's dedicated file-edit hook is after-action; sir relies on post-hook checks and posture sentinels unless Cursor also emits a generic preToolUse for that edit path. |
| Shell classification | ✅ Yes | Bash commands are classified for egress, DNS, persistence, sudo, install, and dangerous-shell risk. |
| MCP tool hooks | ✅ Yes | beforeMCPExecution/afterMCPExecution expose MCP arguments and responses when Cursor emits those hooks. |
| Delegation gating | ✅ Yes | Delegation policy is enforced at Cursor's subagentStart hook. |
| Config change detection | ❌ No | Cursor exposes no ConfigChange-equivalent hook. |
| InstructionsLoaded scanning | ❌ No | Cursor exposes no InstructionsLoaded-equivalent hook. |
| Elicitation interception | ❌ No | Cursor exposes no Elicitation-equivalent hook. |
| Terminal posture sweep | ✅ Yes | sessionEnd and stop provide final posture sweep coverage where Cursor emits them. |
<!-- END GENERATED SUPPORT DOC -->

## Current install boundary

`sir install` rejects `--agent cursor` in this build and does not create or update `~/.cursor/hooks.json`. Use the enabled target for installed hook protection:

```bash
sir install --agent claude
sir status
sir doctor
```

This page remains the coverage contract for existing/manual Cursor hook payloads and status surfaces.

## What works today

Cursor is useful with sir when the workflow stays on covered hook paths:

- Shell classification before and after Cursor shell execution.
- Sensitive-read labeling through `beforeReadFile` and `preToolUse` where Cursor emits those hooks.
- Posture-file write protection where Cursor emits `preToolUse` for generic edits; `afterFileEdit` is after-action, so post-hook checks and posture sentinels are the backstop for file-edit drift.
- MCP argument and response scanning through `beforeMCPExecution` and `afterMCPExecution`.
- Prompt submission checks, subagent-start delegation gating, and final posture sweeps on `stop` and `sessionEnd`.
- Credential output scanning on hooked post-tool paths.

## The important limitation

Cursor is not Claude Code reference support. The guarantee is hook-scoped: if Cursor does not emit a hook for a tool path, sir cannot mediate that action before it runs. Cursor also has no reliable native approval channel for sir's `ask` verdict, so sir returns deny-with-remediation instead of treating Cursor ask/allow behavior as a security boundary.

Cursor also lacks PermissionRequest, ConfigChange, InstructionsLoaded, and Elicitation equivalents. If those lifecycle controls matter for your workflow, prefer Claude Code.

## Troubleshooting

- **`sir install --agent cursor` is rejected:** expected in this build; Cursor hook installation is not enabled.
- **`sir status` shows missing Cursor hooks:** Cursor install is disabled in this build; use the enabled target for installed protection.
- **A file edit was not blocked before it ran:** confirm whether Cursor emitted `preToolUse`; `afterFileEdit` is after-action and relies on post-hook checks plus posture sentinels.
