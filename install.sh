#!/bin/bash
#
# install.sh — install magen and chrome-mcp into ~/.local/bin
#
# Creates symlinks, ensures scripts are executable, warns about missing
# packages (bubblewrap/uidmap on Linux, curl/npx/Chrome for MCP), and
# appends a PATH block to the user shell profile when needed.
#
# Usage:
#   ./install.sh
#

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="$(uname -s)"
MAGEN_LINK="$HOME/.local/bin/magen"
CHROME_MCP_LINK="$HOME/.local/bin/chrome-mcp"

BLOCK_MARKER_START="# BEGIN MAGEN PATH"
BLOCK_MARKER_END="# END MAGEN PATH"

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_info() { echo -e "${BLUE}→ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }

# --- Execution Permissions ---

# Ensure all scripts and library files are executable
chmod +x "$SCRIPT_DIR"/magen "$SCRIPT_DIR"/*.sh 2>/dev/null || true
find "$SCRIPT_DIR"/lib "$SCRIPT_DIR"/proxies "$SCRIPT_DIR"/wrappers "$SCRIPT_DIR"/mcp "$SCRIPT_DIR"/tests \
    -type f \( -name '*.sh' -o -name '*.py' \) -exec chmod +x {} + 2>/dev/null || true

install_link() {
    local name="$1" src="$2" link="$3"
    if [ ! -f "$src" ]; then
        print_warning "$name script not found: $src (skipping)"
        return 1
    fi

    # Ensure source script is executable before linking
    chmod +x "$src" 2>/dev/null || true

    if [ -L "$link" ] && [ "$(readlink "$link")" = "$src" ]; then
        print_success "$name already up to date in ~/.local/bin/"
    else
        ln -sf "$src" "$link"
        print_success "$name installed to ~/.local/bin/ (symlink → ${src#"$SCRIPT_DIR"/})"
    fi
}

# Returns target shell profiles based on OS and installed shells
get_target_profiles() {
    local targets=()
    
    # Zsh profile
    if [[ "${SHELL:-}" == *"zsh"* ]] || command -v zsh &>/dev/null; then
        targets+=("$HOME/.zshrc")
    fi
    
    # Bash profile (OS dependent)
    if [[ "${SHELL:-}" == *"bash"* ]] || command -v bash &>/dev/null; then
        if [[ "$OS" == "Darwin" ]]; then
            targets+=("$HOME/.bash_profile")
        else
            targets+=("$HOME/.bashrc")
        fi
    fi

    # Fallback to .profile if no specific target detected
    if [ ${#targets[@]} -eq 0 ]; then
        targets+=("$HOME/.profile")
    fi

    printf "%s\n" "${targets[@]}" | sort -u
}

# --- Install ---

mkdir -p "$HOME/.local/bin"

echo ""
echo "Magen Setup"
echo "==========="
echo ""

# --- magen CLI ---

MAGEN_SRC="$SCRIPT_DIR/magen"

if install_link "magen" "$MAGEN_SRC" "$MAGEN_LINK"; then
    # bubblewrap: provides bwrap for user-namespace sandbox.
    # uidmap: provides newuidmap/newgidmap setuid helpers required for
    #         uid_map writes on kernels that restrict direct writes
    #         (Ubuntu 6.12+ with apparmor_restrict_unprivileged_userns=1).
    if [[ "$OS" == "Linux" ]]; then
        MISSING_PKGS=()
        command -v bwrap &>/dev/null || MISSING_PKGS+=(bubblewrap)
        command -v newuidmap &>/dev/null || MISSING_PKGS+=(uidmap)

        if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
            print_warning "Missing packages required by magen: ${MISSING_PKGS[*]}"
            if command -v apt &>/dev/null; then
                echo "  Install with: sudo apt install ${MISSING_PKGS[*]}"
            elif command -v dnf &>/dev/null; then
                echo "  Install with: sudo dnf install ${MISSING_PKGS[*]}"
            elif command -v pacman &>/dev/null; then
                echo "  Install with: sudo pacman -S ${MISSING_PKGS[*]}"
            else
                echo "  Install using your system's package manager: ${MISSING_PKGS[*]}"
            fi
        fi
    fi
fi

# --- chrome-mcp wrapper ---

echo ""
echo "Chrome MCP Setup"
echo "================"
echo ""

CHROME_MCP_SRC="$SCRIPT_DIR/mcp/chrome.sh"

if install_link "chrome-mcp" "$CHROME_MCP_SRC" "$CHROME_MCP_LINK"; then
    MISSING_CMDS=()
    command -v curl &>/dev/null || MISSING_CMDS+=(curl)
    command -v npx &>/dev/null || MISSING_CMDS+=(npx)

    if [ ${#MISSING_CMDS[@]} -gt 0 ]; then
        print_warning "Missing commands required by chrome-mcp: ${MISSING_CMDS[*]}"
        for cmd in "${MISSING_CMDS[@]}"; do
            case "$cmd" in
                curl) echo "  curl: install via your system package manager (e.g., sudo apt install curl)" ;;
                npx) echo "  npx:  install Node.js (https://nodejs.org) or via nvm" ;;
            esac
        done
    fi

    # Chrome is only needed inside the bwrap sandbox (Linux).
    # Keep the binary list in sync with find_chrome() in mcp/chrome.sh.
    if [[ "$OS" == "Linux" ]]; then
        CHROME_BIN=""
        for bin in google-chrome google-chrome-stable chromium-browser chromium; do
            command -v "$bin" &>/dev/null && CHROME_BIN="$bin" && break
        done
        if [ -z "$CHROME_BIN" ]; then
            print_warning "No Chrome/Chromium binary found (required for chrome-mcp in sandbox mode)"
            if command -v apt &>/dev/null; then
                echo "  Install with: sudo apt install chromium-browser  (or google-chrome-stable)"
            else
                echo "  Install Chrome or Chromium via your system's package manager"
            fi
        fi
    fi
fi

# --- Cursor sandbox AppArmor check (Linux only) ---

if [[ "$OS" == "Linux" ]]; then
    _cursor_aa_profile="/etc/apparmor.d/cursor-sandbox"
    _aa_restrict="/proc/sys/kernel/apparmor_restrict_unprivileged_userns"

    if [ -f "$_aa_restrict" ] && [ "$(cat "$_aa_restrict" 2>/dev/null)" = "1" ] &&
        [ -f "$_cursor_aa_profile" ] &&
        grep -q '^[[:space:]]*#userns,' "$_cursor_aa_profile" 2>/dev/null; then
        echo ""
        echo "Cursor Sandbox (AppArmor)"
        echo "========================="
        echo ""
        print_warning "Cursor's internal sandbox (cursorsandbox) cannot create user namespaces."
        echo "  The AppArmor profile at $_cursor_aa_profile has 'userns,' commented out,"
        echo "  but this system runs AppArmor $(apparmor_parser --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9.]+' || echo '4.x')."
        echo "  Without this, Cursor shows 'sandbox unsupported' and MCP servers may not start."
        echo ""
        echo "  Fix with:"
        printf '    sudo sed -i '"'"'s/^\\(\\s*\\)#userns,/\\1userns,/'"'"' %s\n' "$_cursor_aa_profile"
        echo "    sudo apparmor_parser -r $_cursor_aa_profile"
    fi
fi

# --- PATH Configuration ---

if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo ""
    echo "PATH Configuration"
    echo "=================="

    while IFS= read -r profile; do
        [ -z "$profile" ] && continue
        if ! grep -qF "$BLOCK_MARKER_START" "$profile" 2>/dev/null; then
            {
                echo ""
                echo "$BLOCK_MARKER_START"
                echo 'export PATH="$HOME/.local/bin:$PATH"'
                echo "$BLOCK_MARKER_END"
            } >> "$profile"
            print_success "Added \$HOME/.local/bin to PATH in $profile"
            print_info "Run 'source $profile' or restart your terminal to activate."
        fi
    done < <(get_target_profiles)
fi

echo ""
print_success "Setup complete!"