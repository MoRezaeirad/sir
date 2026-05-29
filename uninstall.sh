#!/usr/bin/env bash
set -euo pipefail

echo "sir -- Uninstall"
echo "================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }

echo "This will remove ALL sir components from your system:"
echo ""
echo "  Binaries:"
echo "    ~/.local/bin/sir"
echo "    ~/.local/bin/mister-core"
echo ""
echo "  Agent hooks (Claude Code, Gemini CLI, Codex — whichever are present):"
echo "    removed via 'sir uninstall' so every agent config is cleaned correctly"
echo ""
echo "  State data:"
echo "    ~/.sir/  (all project state, ledgers, leases, session data)"
echo ""

echo -e "${RED}This action is irreversible. All sir log history will be lost.${NC}"
echo ""
echo -n "Type 'delete' to confirm removal of ALL sir data: "
# Resolve the confirmation across every invocation style:
#
#   1. SIR_UNINSTALL_YES=1                     -> confirm non-interactively (automation)
#   2. stdin has data       (read succeeds)    -> use it
#        - `printf 'delete' | bash uninstall.sh`  : the pipe carries the answer
#        - interactive `bash uninstall.sh`        : stdin is the terminal
#   3. stdin is empty/EOF, /dev/tty readable    -> prompt the controlling terminal
#        - `curl -fsSL .../uninstall.sh | bash`   : stdin is the consumed curl
#          stream (EOF), so step 2's read fails and we ask the real terminal
#   4. neither available                        -> CONFIRM stays empty -> cancel
#
# Order matters: try stdin BEFORE /dev/tty so a piped confirmation is never
# ignored in favor of the terminal (that was the bug — it hung waiting for tty
# input while a `delete` sat unread on the pipe). `|| true`/`2>/dev/null` keep
# `set -e` from aborting on EOF or an unreadable /dev/tty so we reach the
# explicit cancel below instead of dying mid-prompt.
CONFIRM=""
if [ "${SIR_UNINSTALL_YES:-}" = "1" ]; then
    CONFIRM="delete"
elif read -r CONFIRM; then
    : # got the answer from stdin (piped data, or an interactive terminal)
elif { read -r CONFIRM < /dev/tty; } 2>/dev/null; then
    : # stdin was empty (curl|bash) — prompt the controlling terminal instead
else
    CONFIRM="" # nothing readable anywhere: fall through to the cancel below
fi

if [ "$CONFIRM" != "delete" ]; then
    echo "Uninstall cancelled."
    exit 0
fi

echo ""

# Resolve the sir binary.
SIR_BIN=""
if [ -x "$HOME/.local/bin/sir" ]; then
    SIR_BIN="$HOME/.local/bin/sir"
elif command -v sir >/dev/null 2>&1; then
    SIR_BIN="$(command -v sir)"
fi

# Remove agent hooks. Prefer the binary, which cleans every detected agent
# (Claude / Gemini / Codex) in each one's native config format. Fall back to a
# best-effort Claude-only cleanup if the binary is missing.
if [ -n "$SIR_BIN" ]; then
    info "Removing sir hooks from all detected agents (sir uninstall)..."
    "$SIR_BIN" uninstall || warn "sir uninstall reported an issue; continuing with file removal"
else
    warn "sir binary not found — falling back to Claude-only hook cleanup."
    GLOBAL_SETTINGS="$HOME/.claude/settings.json"
    if [ -f "$GLOBAL_SETTINGS" ] && grep -q "sir guard" "$GLOBAL_SETTINGS" 2>/dev/null; then
        if command -v python3 >/dev/null 2>&1; then
            python3 - "$GLOBAL_SETTINGS" <<'PYEOF' 2>/dev/null
import sys, json
path = sys.argv[1]
with open(path) as f:
    settings = json.load(f)
if 'hooks' in settings:
    del settings['hooks']
with open(path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
PYEOF
            info "Removed sir hooks from $GLOBAL_SETTINGS"
        else
            warn "python3 not found — manually remove the 'hooks' key from $GLOBAL_SETTINGS"
        fi
        warn "Gemini/Codex hooks (if any) were NOT cleaned without the sir binary —"
        warn "reinstall sir and run 'sir uninstall', or edit those configs by hand."
    fi
fi

# Remove binaries.
for BIN in "$HOME/.local/bin/sir" "$HOME/.local/bin/mister-core"; do
    if [ -f "$BIN" ]; then
        rm "$BIN"
        info "Removed $BIN"
    else
        warn "$BIN not found (already removed?)"
    fi
done

# Clean up legacy hooks file if it exists.
OLD_HOOKS="$HOME/.claude/hooks/hooks.json"
if [ -f "$OLD_HOOKS" ] && grep -q "sir guard" "$OLD_HOOKS" 2>/dev/null; then
    rm "$OLD_HOOKS"
    info "Removed legacy hooks file $OLD_HOOKS"
fi

# Remove all sir state.
if [ -d "$HOME/.sir" ]; then
    PROJECT_COUNT=$(find "$HOME/.sir/projects" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
    rm -rf "$HOME/.sir"
    info "Removed ~/.sir/ ($PROJECT_COUNT project(s) of state data)"
else
    warn "~/.sir/ not found (already removed?)"
fi

# Remove per-project .claude/.sir/ directory in the current directory if present.
if [ -d ".claude/.sir" ]; then
    rm -rf ".claude/.sir"
    info "Removed .claude/.sir/ in current directory"
fi

# Notify about any PATH entry left in shell profiles.
for PROFILE in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
    if [ -f "$PROFILE" ] && grep -q "# sir - Sandbox in Reverse" "$PROFILE" 2>/dev/null; then
        warn "PATH entry for sir found in $PROFILE — you may want to remove:"
        echo "      # sir - Sandbox in Reverse"
        echo "      export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
    fi
done

echo ""
info "sir has been completely uninstalled."
echo ""
echo "    To reinstall: curl -fsSL https://raw.githubusercontent.com/somoore/sir/main/scripts/download.sh | bash"
echo ""
