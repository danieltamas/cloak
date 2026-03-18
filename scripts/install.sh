#!/bin/bash
set -euo pipefail

# Cloak installer — macOS and Linux
# Usage (manual):    curl -fsSL https://getcloak.dev/install.sh | bash
# Usage (extension): curl -fsSL https://getcloak.dev/install.sh | CLOAK_ACCEPT=1 bash
# Usage (versioned): curl -fsSL https://getcloak.dev/install.sh | bash -s v1.2.3

INSTALLER_VERSION="2026.03.18-1"
VERSION="${1:-latest}"
REPO="danieltamas/cloak"
INSTALL_DIR="${HOME}/.local/bin"

# ── Colours ───────────────────────────────────────────────────────────────────

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
DIM='\033[2m'
NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────

ok()   { echo -e "  ${GREEN}✓${NC}  $1"; }
info() { echo -e "  ${CYAN}→${NC}  $1"; }
warn() { echo -e "  ${YELLOW}!${NC}  $1"; }
fail() { echo -e "  ${RED}✗${NC}  $1"; exit 1; }

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}   ██████╗██╗      ██████╗  █████╗ ██╗  ██╗${NC}"
    echo -e "${CYAN}${BOLD}  ██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝${NC}"
    echo -e "${CYAN}${BOLD}  ██║     ██║     ██║   ██║███████║█████╔╝ ${NC}"
    echo -e "${CYAN}${BOLD}  ██║     ██║     ██║   ██║██╔══██║██╔═██╗ ${NC}"
    echo -e "${CYAN}${BOLD}  ╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗${NC}"
    echo -e "${CYAN}${BOLD}   ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝${NC}"
    echo ""
    echo -e "  ${DIM}Protect .env secrets from AI coding agents${NC}"
    echo ""
}

spinner() {
    local pid=$1
    local label=$2
    local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}%s${NC}  %s..." "${frames[$((i % 10))]}" "$label"
        i=$((i + 1))
        sleep 0.08
    done
    printf "\r\033[K"
}

# ── Rollback ──────────────────────────────────────────────────────────────────

INSTALL_COMPLETED=0
INSTALLED_BINARY=0

rollback() {
    if [[ $INSTALL_COMPLETED -eq 1 ]]; then
        return
    fi
    echo ""
    echo -e "  ${RED}${BOLD}Installation failed — rolling back changes...${NC}"
    if [[ $INSTALLED_BINARY -eq 1 ]]; then
        rm -f "${INSTALL_DIR}/cloak" 2>/dev/null || true
        ok "Rolled back cloak binary"
    fi
    echo ""
    echo -e "  ${DIM}Your system is unchanged.${NC}"
    echo ""
}

trap rollback EXIT

# ── Platform detection ────────────────────────────────────────────────────────

detect_platform() {
    local raw_os raw_arch
    raw_os="$(uname -s)"
    raw_arch="$(uname -m)"

    case "$raw_os" in
        Darwin) OS="macos" ;;
        Linux)  OS="linux" ;;
        *) fail "Unsupported OS: $raw_os. Cloak supports macOS and Linux." ;;
    esac

    case "$raw_arch" in
        x86_64 | amd64)  ARCH="x86_64" ;;
        arm64 | aarch64) ARCH="aarch64" ;;
        *) fail "Unsupported architecture: $raw_arch" ;;
    esac

    ok "Platform: ${OS} / ${ARCH}"
}

# ── Download binary ───────────────────────────────────────────────────────────

install_cloak_binary() {
    local bin="cloak-${OS}-${ARCH}"
    local url

    if [[ "$VERSION" == "latest" ]]; then
        url="https://github.com/${REPO}/releases/latest/download/${bin}"
    else
        url="https://github.com/${REPO}/releases/download/${VERSION}/${bin}"
    fi

    mkdir -p "$INSTALL_DIR"

    local tmp
    tmp="$(mktemp)"

    curl -fsSL "$url" -o "$tmp" &
    spinner $! "Downloading Cloak ${VERSION}"
    wait $! || { rm -f "$tmp"; fail "Download failed — check your network or visit https://github.com/${REPO}/releases"; }

    chmod +x "$tmp"
    mv "$tmp" "${INSTALL_DIR}/cloak"
    INSTALLED_BINARY=1

    # Ad-hoc codesign on macOS — prevents Keychain password prompt on first run.
    if [[ "$OS" == "macos" ]] && command -v codesign &>/dev/null; then
        codesign -s - "${INSTALL_DIR}/cloak" 2>/dev/null && ok "Binary codesigned (ad-hoc)" || true
    fi

    ok "Cloak binary → ${INSTALL_DIR}/cloak"
}

# ── PATH ──────────────────────────────────────────────────────────────────────

configure_path() {
    if echo "$PATH" | grep -q "$INSTALL_DIR"; then
        ok "${INSTALL_DIR} already in PATH"
        return
    fi

    local export_line="export PATH=\"${INSTALL_DIR}:\$PATH\""
    local added=0
    local rc=""

    case "${SHELL:-}" in
        */zsh)
            rc="$HOME/.zshrc"
            echo "$export_line" >> "$rc" && added=1
            ;;
        */bash)
            if [[ "$OS" == "macos" ]]; then
                rc="$HOME/.bash_profile"
            else
                rc="$HOME/.bashrc"
            fi
            echo "$export_line" >> "$rc" && added=1
            ;;
        */fish)
            fish -c "fish_add_path $INSTALL_DIR" 2>/dev/null && added=1
            ;;
    esac

    if [[ $added -eq 1 ]]; then
        ok "Added ${INSTALL_DIR} to PATH in ${rc}"
        info "Run: source ${rc}  (or open a new terminal)"
    else
        warn "${INSTALL_DIR} not in PATH — add it manually:"
        warn "  ${export_line}"
    fi
}

# ── Done ──────────────────────────────────────────────────────────────────────

print_done() {
    echo ""
    echo -e "  ${GREEN}${BOLD}Cloak is installed.${NC}"
    echo ""
    echo -e "  Run ${BOLD}cloak --help${NC} to get started."
    echo -e "  ${DIM}Docs: https://getcloak.dev${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────────────────────────────────────

print_header
echo -e "  ${DIM}installer v${INSTALLER_VERSION}${NC}"
echo ""
detect_platform

# ── What this installer does ──────────────────────────────────────────────────
echo ""
echo -e "  ${YELLOW}${BOLD}This installer will make the following changes:${NC}"
echo ""
echo -e "  ${BOLD}Installs${NC}"
echo -e "  ${DIM}  • cloak binary → ${INSTALL_DIR}/cloak${NC}"
echo ""
echo -e "  ${BOLD}Shell config${NC}"
echo -e "  ${DIM}  • Adds ${INSTALL_DIR} to your PATH (if not already present)${NC}"
echo ""
echo -e "  ${BOLD}At runtime${NC}"
echo -e "  ${DIM}  • Vault + auth files → ~/.config/cloak/ (or ~/Library/Application Support/cloak/)${NC}"
if [[ "$(uname -s)" == "Darwin" ]]; then
echo -e "  ${DIM}  • macOS: compiles a Touch ID helper on first use (~4s, cached)${NC}"
fi
echo ""
echo -e "  ${DIM}No system files, no sudo, no network calls after install.${NC}"
echo -e "  ${DIM}Uninstall: rm ${INSTALL_DIR}/cloak && rm -rf ~/.config/cloak${NC}"
echo ""

# ── Consent ───────────────────────────────────────────────────────────────────
# CLOAK_ACCEPT=1  — set by the VS Code extension to skip the prompt
# --yes / -y      — flag for scripted / CI use
# Otherwise       — interactive prompt (reads from /dev/tty so curl-pipe works)

AUTO_ACCEPT="${CLOAK_ACCEPT:-0}"
for arg in "$@"; do
    case "$arg" in
        --yes|-y) AUTO_ACCEPT=1 ;;
    esac
done

if [[ "$AUTO_ACCEPT" == "1" ]]; then
    info "Non-interactive install (CLOAK_ACCEPT=1 or --yes)"
elif [[ -e /dev/tty ]]; then
    printf "  ${CYAN}Proceed with installation? [Y/n]${NC} "
    read -r REPLY < /dev/tty
    case "$REPLY" in
        [nN] | [nN][oO])
            echo ""
            info "Installation cancelled."
            INSTALL_COMPLETED=1   # suppress rollback noise
            exit 0
            ;;
    esac
else
    warn "No terminal detected and CLOAK_ACCEPT is not set."
    warn "Set CLOAK_ACCEPT=1 to install without a prompt, e.g.:"
    warn "  curl -fsSL https://getcloak.dev/install.sh | CLOAK_ACCEPT=1 bash"
    INSTALL_COMPLETED=1
    exit 1
fi

echo ""
install_cloak_binary
configure_path
INSTALL_COMPLETED=1
print_done
