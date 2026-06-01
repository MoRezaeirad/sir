#!/usr/bin/env bash
set -euo pipefail

echo "sir -- Sandbox in Reverse"
echo "========================="
echo ""

# Idempotent update path — if sir is already installed, this script will
# rebuild the binaries and replace them, preserving lease and session state
# at ~/.sir/. Hooks are re-registered for any enabled protection target selected
# by the user. This testing build enables Claude Code.
#
# There is no auto-updater, no background checker, and no `sir update`
# subcommand. To update sir, the developer re-runs this install script
# (typically via `curl ... | bash`). This is the entire update mechanism.
CURRENT_VERSION="none"
if command -v sir >/dev/null 2>&1; then
    CURRENT_VERSION=$(sir version 2>/dev/null | awk '{print $2}' || echo "unknown")
    echo "Existing sir installation detected: $CURRENT_VERSION"
    echo "Re-running install.sh will rebuild and replace the binaries."
    echo "Your lease and session state at ~/.sir/ will be preserved."
    echo ""
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }

INSTALL_ARGS=("$@")
EXPLICIT_AGENT=""
ASSUME_YES=0
for ((i=0; i<${#INSTALL_ARGS[@]}; i++)); do
    case "${INSTALL_ARGS[$i]}" in
        --yes)
            ASSUME_YES=1
            ;;
        --agent)
            if (( i + 1 < ${#INSTALL_ARGS[@]} )); then
                EXPLICIT_AGENT="${INSTALL_ARGS[$((i + 1))]}"
            fi
            ;;
        --agent=*)
            EXPLICIT_AGENT="${INSTALL_ARGS[$i]#--agent=}"
            ;;
    esac
done

agent_name() {
    case "$1" in
        claude) echo "Claude Code" ;;
        gemini) echo "Gemini CLI" ;;
        codex) echo "Codex" ;;
        cursor) echo "Cursor" ;;
        *) echo "$1" ;;
    esac
}

agent_launch_command() {
    case "$1" in
        claude) echo "claude" ;;
        gemini) echo "gemini" ;;
        codex) echo "codex" ;;
        cursor) echo "cursor-agent" ;;
        *) echo "$1" ;;
    esac
}

detect_agent() {
    case "$1" in
        claude)
            command -v claude >/dev/null 2>&1 || [ -d "$HOME/.claude" ]
            ;;
        gemini)
            command -v gemini >/dev/null 2>&1 || [ -d "$HOME/.gemini" ]
            ;;
        codex)
            command -v codex >/dev/null 2>&1 || [ -d "$HOME/.codex" ]
            ;;
        cursor)
            command -v cursor-agent >/dev/null 2>&1 || command -v cursor >/dev/null 2>&1 || [ -d "$HOME/.cursor" ]
            ;;
        *)
            return 1
            ;;
    esac
}

print_detected_agents() {
    echo "Detected AI coding agents:"
    if [ ${#DETECTED_AGENTS[@]} -eq 0 ] && [ ${#DETECTED_NON_INSTALL_AGENTS[@]} -eq 0 ]; then
        echo "    none"
        return
    fi
    for agent_id in "${DETECTED_AGENTS[@]}"; do
        echo "    [enabled]  $(agent_name "$agent_id")"
    done
    for agent_id in "${DETECTED_NON_INSTALL_AGENTS[@]}"; do
        echo "    [disabled] $(agent_name "$agent_id") — protection not enabled in this build"
    done
}

choose_hook_agent() {
    print_detected_agents
    if [ ${#DETECTED_AGENTS[@]} -eq 0 ]; then
        warn "No detected agent is enabled for hook protection in this build."
        return 1
    fi
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi
    if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
        warn "An enabled agent was detected, but no interactive terminal is available to select hook setup."
        warn "sir binaries will be installed; run 'sir config' or 'sir install --agent claude' when ready."
        return 1
    fi

    printf "    Select agent to protect now [1=Claude Code, Enter=1, s=skip]: " > /dev/tty
    local reply
    if ! read -r reply < /dev/tty; then
        warn "No confirmation received. Skipping hook setup."
        return 1
    fi
    case "$reply" in
        ""|1|claude|Claude|CLAUDE)
            return 0
            ;;
        s|S|skip|SKIP|n|N|no|NO|No)
            return 1
            ;;
        *)
            warn "Only Claude Code is enabled for hook protection in this build. Skipping hook setup."
            return 1
            ;;
    esac
}

declare -a DETECTED_AGENTS=()
declare -a DETECTED_NON_INSTALL_AGENTS=()
declare -a INSTALLED_AGENTS=()
declare -a SIR_INSTALL_ARGS=()
RUN_SIR_INSTALL=0

# --- Downgrade guard ---
# Refuse to install a version older than the one currently on disk.
#
# Threat model: an attacker (or disgruntled developer) with write access
# to $HOME/.local/bin could clone an older, less-hardened release (e.g.
# one that predates MCP defense or credential scanning) and run this
# script to overwrite a more-hardened build. The older binaries are
# still validly signed and the hook configurations are still structurally
# valid, so no tamper alert fires — yet security features have been
# silently stripped.
#
# This guard enforces: install.sh never produces an install older than
# what it replaces, unless the operator explicitly overrides with
# SIR_ALLOW_DOWNGRADE=1. For enterprise MDM deployments, the MDM-pushed
# version always wins against a local clone of an older tag.
#
# The target version is read directly from the source we're about to
# build (cmd/sir/version.go::Version), so a tampered install.sh cannot
# lie about the target.
TARGET_VERSION=""
if [ -f "cmd/sir/version.go" ]; then
    TARGET_VERSION=$(sed -n 's/^const Version = "\([^"]*\)".*/\1/p' cmd/sir/version.go | head -n1)
fi

if [ -n "$TARGET_VERSION" ] && [ "$CURRENT_VERSION" != "none" ] && [ "$CURRENT_VERSION" != "unknown" ]; then
    # sort -V handles v-prefixed semver naturally; the smaller sorts first.
    LOWER_VERSION=$(printf '%s\n%s\n' "$CURRENT_VERSION" "$TARGET_VERSION" | sort -V | head -n1)
    if [ "$CURRENT_VERSION" != "$TARGET_VERSION" ] && [ "$LOWER_VERSION" = "$TARGET_VERSION" ]; then
        if [ "${SIR_ALLOW_DOWNGRADE:-0}" != "1" ]; then
            error "Downgrade blocked.
    installed:   $CURRENT_VERSION
    installing:  $TARGET_VERSION

    Refusing to replace a newer sir with an older one.

    This protects against an attacker cloning an older release and
    running install.sh to silently strip newer security features
    without tripping any tamper alert (older hooks are still valid,
    just missing later detections).

    For legitimate rollback, set SIR_ALLOW_DOWNGRADE=1:

        SIR_ALLOW_DOWNGRADE=1 ./install.sh

    For enterprise MDM deployments: any install.sh invocation that
    would downgrade fails unless the enforcing operator explicitly
    sets SIR_ALLOW_DOWNGRADE=1. The baseline version pushed by MDM
    always wins against a local clone of an older tag."
        else
            warn "Downgrade explicitly allowed via SIR_ALLOW_DOWNGRADE=1."
            warn "  installed:  $CURRENT_VERSION"
            warn "  installing: $TARGET_VERSION"
        fi
    fi
fi

# --- Pinned toolchain versions ---
# Keep in sync with .github/workflows/ci.yml and Makefile
RUST_VERSION="1.94.0"
GO_MIN_VERSION="1.22"

# --- Pinned rustup installer ---
# RUSTUP_VERSION is the version of the *installer* (rustup-init), not the Rust
# toolchain. RUST_VERSION above is the toolchain that rustup-init will fetch.
#
# The rustup-init binary is pinned by SHA-256 so this script never executes
# an unverified remote blob — addresses OpenSSF Scorecard findings about
# `curl | sh` supply-chain exposure (see issue #95).
#
# Canonical hashes are published at:
#   https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/<target>/rustup-init.sha256
# Each file is one line: "<hex-sha256>  rustup-init".
#
# To refresh on a rustup version bump:
#   for t in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
#            x86_64-apple-darwin aarch64-apple-darwin; do
#     curl -fsSL "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/$t/rustup-init.sha256"
#   done
RUSTUP_VERSION="1.28.2"
RUSTUP_INIT_SHA256_LINUX_X86_64="20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c"
RUSTUP_INIT_SHA256_LINUX_ARM64="e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c"
RUSTUP_INIT_SHA256_DARWIN_X86_64="9c331076f62b4d0edeae63d9d1c9442d5fe39b37b05025ec8d41c5ed35486496"
RUSTUP_INIT_SHA256_DARWIN_ARM64="20ef5516c31b1ac2290084199ba77dbbcaa1406c45c1d978ca68558ef5964ef5"

# --- Source verification ---
# If building from a git checkout, verify the commit is on main or a tag
if [ -d ".git" ]; then
    CURRENT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    info "Building from source at commit: $CURRENT_COMMIT"

    # Warn if working tree is dirty
    if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
        warn "Working tree has uncommitted changes."
    fi
fi

# Check for Rust toolchain
if ! command -v cargo &> /dev/null; then
    warn "Rust toolchain not found."
    echo "    Installing Rust $RUST_VERSION via rustup-init $RUSTUP_VERSION..."
    echo ""
    echo "  About to download and run the official Rust installer (rustup-init)."
    echo "  Source: https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/"
    echo "  To verify this independently: https://rust-lang.org/tools/install"
    echo "  Press Ctrl+C to cancel."
    echo ""
    # Supply chain note: rustup-init is downloaded over HTTPS from
    # static.rust-lang.org, then verified against a pinned SHA-256 before
    # it is ever executed. This replaces the previous `curl | sh` pattern
    # which executed unverified bytes straight from the network.
    # See https://rust-lang.org/tools/install for manual verification steps.

    # Detect host triple for rustup-init download.
    RUSTUP_OS=$(uname -s)
    RUSTUP_ARCH=$(uname -m)
    case "${RUSTUP_OS}-${RUSTUP_ARCH}" in
        Linux-x86_64)
            RUSTUP_TARGET="x86_64-unknown-linux-gnu"
            RUSTUP_EXPECTED_SHA256="$RUSTUP_INIT_SHA256_LINUX_X86_64"
            ;;
        Linux-aarch64 | Linux-arm64)
            RUSTUP_TARGET="aarch64-unknown-linux-gnu"
            RUSTUP_EXPECTED_SHA256="$RUSTUP_INIT_SHA256_LINUX_ARM64"
            ;;
        Darwin-x86_64)
            RUSTUP_TARGET="x86_64-apple-darwin"
            RUSTUP_EXPECTED_SHA256="$RUSTUP_INIT_SHA256_DARWIN_X86_64"
            ;;
        Darwin-arm64)
            RUSTUP_TARGET="aarch64-apple-darwin"
            RUSTUP_EXPECTED_SHA256="$RUSTUP_INIT_SHA256_DARWIN_ARM64"
            ;;
        *)
            error "Unsupported platform for pinned rustup-init: ${RUSTUP_OS}-${RUSTUP_ARCH}.
    Supported: Linux x86_64, Linux arm64, macOS x86_64, macOS arm64.
    For other platforms, install Rust $RUST_VERSION manually from
    https://rust-lang.org/tools/install and re-run this script."
            ;;
    esac

    # Download to a scratch dir so we never leave half-verified blobs behind.
    RUSTUP_TMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t rustup-init)
    # shellcheck disable=SC2064
    trap "rm -rf \"$RUSTUP_TMPDIR\"" EXIT INT TERM
    RUSTUP_URL="https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_TARGET}/rustup-init"

    info "Downloading rustup-init ${RUSTUP_VERSION} for ${RUSTUP_TARGET}..."
    curl --proto '=https' --tlsv1.2 -fsSL -o "$RUSTUP_TMPDIR/rustup-init" "$RUSTUP_URL"

    # Verify SHA-256 before executing. Fail closed on mismatch.
    # Prefer shasum (present on both macOS and most Linux) over sha256sum
    # (missing on default macOS), matching how the rest of this script
    # handles the same portability gap below.
    info "Verifying rustup-init SHA-256..."
    if command -v sha256sum &> /dev/null; then
        echo "${RUSTUP_EXPECTED_SHA256}  rustup-init" \
            | (cd "$RUSTUP_TMPDIR" && sha256sum --check --status) \
            || error "rustup-init SHA-256 verification failed.
    expected: $RUSTUP_EXPECTED_SHA256
    Refusing to execute unverified installer. Aborting."
    else
        echo "${RUSTUP_EXPECTED_SHA256}  rustup-init" \
            | (cd "$RUSTUP_TMPDIR" && shasum -a 256 --check --status) \
            || error "rustup-init SHA-256 verification failed.
    expected: $RUSTUP_EXPECTED_SHA256
    Refusing to execute unverified installer. Aborting."
    fi
    info "rustup-init SHA-256 verified."

    chmod +x "$RUSTUP_TMPDIR/rustup-init"
    "$RUSTUP_TMPDIR/rustup-init" -y --default-toolchain "$RUST_VERSION"

    rm -rf "$RUSTUP_TMPDIR"
    trap - EXIT INT TERM

    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
    info "Rust $RUST_VERSION installed."
else
    CURRENT_RUST=$(rustc --version | awk '{print $2}')
    info "Rust toolchain found: $CURRENT_RUST"
    if [ "$CURRENT_RUST" != "$RUST_VERSION" ]; then
        warn "Expected Rust $RUST_VERSION, found $CURRENT_RUST"
        warn "Consider: rustup install $RUST_VERSION && rustup default $RUST_VERSION"
    fi
fi

# Check for Go toolchain
if ! command -v go &> /dev/null; then
    error "Go toolchain not found. Install Go ${GO_MIN_VERSION}+ from https://go.dev/dl/ and re-run this script."
else
    info "Go toolchain found: $(go version)"
fi

if [ -n "$EXPLICIT_AGENT" ]; then
    case "$EXPLICIT_AGENT" in
        claude) ;;
        *)
            error "Unsupported --agent value: $EXPLICIT_AGENT

    This build detects multiple AI coding agents, but hook protection is
    currently enabled for Claude Code only.
    Enabled install agent: claude"
            ;;
    esac
    if detect_agent "$EXPLICIT_AGENT"; then
        info "$(agent_name "$EXPLICIT_AGENT") detected for explicit install."
        DETECTED_AGENTS+=("$EXPLICIT_AGENT")
        SIR_INSTALL_ARGS=(--yes "${INSTALL_ARGS[@]}")
        RUN_SIR_INSTALL=1
    else
        error "--agent $EXPLICIT_AGENT requested but $(agent_name "$EXPLICIT_AGENT") was not detected on this machine.

    Install $(agent_name "$EXPLICIT_AGENT") first, then re-run this script."
    fi
else
    if detect_agent claude; then
        DETECTED_AGENTS+=("claude")
    fi
    for agent_id in gemini codex cursor; do
        if detect_agent "$agent_id"; then
            DETECTED_NON_INSTALL_AGENTS+=("$agent_id")
        fi
    done
    if choose_hook_agent; then
        if [ ${#DETECTED_AGENTS[@]} -gt 0 ]; then
            info "$(agent_name "${DETECTED_AGENTS[0]}") hook setup selected."
            SIR_INSTALL_ARGS=(--yes "${INSTALL_ARGS[@]}")
            RUN_SIR_INSTALL=1
        fi
    else
        warn "Skipping automatic hook setup."
    fi
fi

# Build mister-core (Rust) — use --locked to enforce Cargo.lock
info "Building mister-core (Rust) with --locked..."
CARGO_INCREMENTAL=0 CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release --locked
info "mister-core built."

# Build sir (Go) — static binary, stripped, reproducible
info "Building sir (Go) with static linking..."
mkdir -p bin
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/sir ./cmd/sir
info "sir built."

# Generate checksums of built binaries
info "Generating checksums of built binaries..."
if command -v sha256sum &> /dev/null; then
    sha256sum target/release/mister-core bin/sir
else
    shasum -a 256 target/release/mister-core bin/sir
fi

# Install binaries
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

info "Installing binaries to $INSTALL_DIR..."
# Atomic replace via cp-to-tmp + mv. A plain `cp src dst` in-place keeps the
# existing inode and overwrites its bytes; on macOS Tahoe 26.5 beta the
# kernel caches the prior binary's code signature against that inode, and
# launching the new bytes fails integrity verification — exit 137 with no
# output. `mv -f` atomically replaces the directory entry with a fresh
# inode, so the kernel re-verifies the signature from scratch.
#
# A trap cleans up any `.sirtmp.*` residue if we fail between mktemp and mv
# (disk full, signal during cp, etc.) so we don't leave zombie files under
# ~/.local/bin. The trap runs on EXIT, so normal completion (all mvs done)
# finds nothing to clean.
_SIRTMP_GLOB="${INSTALL_DIR}/*.sirtmp.*"
# shellcheck disable=SC2064  # single-quoted $_SIRTMP_GLOB would defer expansion past unset
trap "rm -f ${_SIRTMP_GLOB}" EXIT
_CORE_TMP="$(mktemp "${INSTALL_DIR}/mister-core.sirtmp.XXXXXX")"
cp target/release/mister-core "$_CORE_TMP"
chmod 0750 "$_CORE_TMP"
mv -f "$_CORE_TMP" "$INSTALL_DIR/mister-core"
_SIR_TMP="$(mktemp "${INSTALL_DIR}/sir.sirtmp.XXXXXX")"
cp bin/sir "$_SIR_TMP"
chmod 0750 "$_SIR_TMP"
mv -f "$_SIR_TMP" "$INSTALL_DIR/sir"
trap - EXIT
unset _CORE_TMP _SIR_TMP _SIRTMP_GLOB
# Owner-executable only (0750): prevents other users on the machine from
# reading or executing the binaries. Group access preserved for admin use.
chmod 750 "$INSTALL_DIR/mister-core"
chmod 750 "$INSTALL_DIR/sir"

# Verify installed binaries match built binaries
info "Verifying installed binaries..."
if command -v sha256sum &> /dev/null; then
    BUILT_CORE=$(sha256sum target/release/mister-core | awk '{print $1}')
    BUILT_SIR=$(sha256sum bin/sir | awk '{print $1}')
    INST_CORE=$(sha256sum "$INSTALL_DIR/mister-core" | awk '{print $1}')
    INST_SIR=$(sha256sum "$INSTALL_DIR/sir" | awk '{print $1}')
else
    BUILT_CORE=$(shasum -a 256 target/release/mister-core | awk '{print $1}')
    BUILT_SIR=$(shasum -a 256 bin/sir | awk '{print $1}')
    INST_CORE=$(shasum -a 256 "$INSTALL_DIR/mister-core" | awk '{print $1}')
    INST_SIR=$(shasum -a 256 "$INSTALL_DIR/sir" | awk '{print $1}')
fi

if [ "$BUILT_CORE" != "$INST_CORE" ] || [ "$BUILT_SIR" != "$INST_SIR" ]; then
    error "Checksum mismatch between built and installed binaries. Aborting."
fi
info "Installed binaries verified."

# Write binary integrity manifest — used by `sir verify` and the mister-core
# launch-time integrity check to detect binary tampering after installation.
MANIFEST_DIR="$HOME/.sir"
mkdir -p "$MANIFEST_DIR"
cat > "$MANIFEST_DIR/binary-manifest.json" <<MANIFEST_EOF
{
  "version": "${TARGET_VERSION:-unknown}",
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "install_method": "source",
  "sir_sha256": "${INST_SIR}",
  "mister_core_sha256": "${INST_CORE}",
  "sir_path": "${INSTALL_DIR}/sir",
  "mister_core_path": "${INSTALL_DIR}/mister-core"
}
MANIFEST_EOF
chmod 600 "$MANIFEST_DIR/binary-manifest.json"
# Sentinel records that a manifest has been written. If the manifest is later
# deleted but the sentinel remains, sir treats it as tamper and fails closed.
touch "$MANIFEST_DIR/.manifest-expected"
chmod 600 "$MANIFEST_DIR/.manifest-expected"
info "Binary manifest written to $MANIFEST_DIR/binary-manifest.json"

# Check PATH — sir CLI commands (sir status, sir doctor, sir trace, etc.) need PATH.
# Hook commands use absolute paths (set during `sir install`) so PATH is not required
# for hook execution, but the CLI must be findable for developer use.
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    warn "$INSTALL_DIR is not in your PATH."
    echo ""
    echo "    sir CLI commands need to be on PATH for direct use (sir status, sir trace, etc.)."
    echo "    Hook commands use absolute paths and do not depend on PATH."
    echo ""

    # Auto-add to shell profile
    SHELL_PROFILE=""
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then
        SHELL_PROFILE="$HOME/.bash_profile"
    fi

    if [ -n "$SHELL_PROFILE" ]; then
        echo -n "    Add to $SHELL_PROFILE? [Y/n] "
        read -r REPLY
        if [ -z "$REPLY" ] || [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
            echo '' >> "$SHELL_PROFILE"
            echo '# sir - Sandbox in Reverse' >> "$SHELL_PROFILE"
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_PROFILE"
            export PATH="$HOME/.local/bin:$PATH"
            info "Added to $SHELL_PROFILE. PATH updated for this session."
        else
            echo "    Add this manually to your shell profile:"
            echo '    export PATH="$HOME/.local/bin:$PATH"'
        fi
    else
        echo "    Add this to your shell profile:"
        echo '    export PATH="$HOME/.local/bin:$PATH"'
    fi
    echo ""
fi

if [ "$RUN_SIR_INSTALL" -eq 1 ]; then
    info "Setting up sir hooks for the selected enabled agent..."
    "$INSTALL_DIR/sir" install "${SIR_INSTALL_ARGS[@]}"

    if [ -f "$HOME/.claude/settings.json" ] && grep -q "sir.*guard" "$HOME/.claude/settings.json" 2>/dev/null; then
        INSTALLED_AGENTS+=("claude")
        info "Claude Code hooks installed in $HOME/.claude/settings.json"
    fi

    info "Verifying installation..."
    "$INSTALL_DIR/sir" doctor 2>/dev/null || true
else
    warn "Skipping automatic hook setup. Run 'sir config' to select an enabled agent later."
fi

echo ""
info "sir installed successfully!"
NEW_VERSION=$("$INSTALL_DIR/sir" version 2>/dev/null || echo "sir unknown")
if [ "$CURRENT_VERSION" != "none" ] && [ "$CURRENT_VERSION" != "unknown" ]; then
    info "Updated: $CURRENT_VERSION -> $NEW_VERSION"
else
    info "Installed: $NEW_VERSION"
fi
echo ""
echo "    ┌─────────────────────────────────────────────────────┐"
if [ ${#INSTALLED_AGENTS[@]} -gt 0 ]; then
    if [ ${#INSTALLED_AGENTS[@]} -eq 1 ]; then
        printf "    │  Just type '%-6s' — sir is now watching.        │\n" "$(agent_launch_command "${INSTALLED_AGENTS[0]}")"
    else
        echo "    │  Launch a protected agent — sir watches.         │"
    fi
    echo "    │                                                     │"
    echo "    │  For other projects, run 'sir config' there to     │"
    echo "    │  detect agents and activate protection.            │"
else
    echo "    │  sir binaries are installed.                        │"
    echo "    │                                                     │"
    echo "    │  Run 'sir config' later to detect agents and        │"
    echo "    │  select an enabled protection target.              │"
fi
echo "    └─────────────────────────────────────────────────────┘"
echo ""
echo "    Commands:"
echo "      sir status           Check sir status"
echo "      sir doctor           Verify configuration"
echo "      sir trace            HTML timeline of session events"
echo "      sir audit            Terminal security summary"
echo "      sir trust NAME       Trust an MCP server"
echo "      sir log              View decision log"
echo "      sir unlock           Clear secret session flag"
echo "      sir demo             See detections in action"
echo ""
