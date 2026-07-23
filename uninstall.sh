#!/bin/bash
#
# uninstall.sh — remove magen / chrome-mcp symlinks and PATH blocks
#
# Deletes ~/.local/bin links (including the legacy ``sandbox`` name) and
# strips both current MAGEN and legacy SANDBOX PATH markers from common
# shell profiles.
#
# Usage:
#   ./uninstall.sh
#

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

OS="$(uname -s)"
MAGEN_LINK="$HOME/.local/bin/magen"
CHROME_MCP_LINK="$HOME/.local/bin/chrome-mcp"

BLOCK_MARKER_START="# BEGIN MAGEN PATH"
BLOCK_MARKER_END="# END MAGEN PATH"
LEGACY_BLOCK_START="# BEGIN SANDBOX PATH"
LEGACY_BLOCK_END="# END SANDBOX PATH"

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_info() { echo -e "${BLUE}→ $1${NC}"; }

echo ""
echo "Magen - Uninstall"
echo "================="
echo ""

# --- Remove CLI symlinks ---
for link in "$MAGEN_LINK" "$CHROME_MCP_LINK"; do
    if [ -e "$link" ] || [ -L "$link" ]; then
        rm -f "$link"
        print_success "Removed $link"
    else
        print_info "$(basename "$link") not installed (nothing to remove)"
    fi
done

# --- Strip PATH blocks from shell profiles ---
_remove_block() {
    local profile="$1" start="$2" end="$3"
    if [ -f "$profile" ] && grep -qF "$start" "$profile"; then
        if [[ "$OS" == "Darwin" ]]; then
            sed -i '' "/$start/,/$end/d" "$profile"
        else
            sed -i "/$start/,/$end/d" "$profile"
        fi
        return 0
    fi
    return 1
}

for profile in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
    _changed=false
    _remove_block "$profile" "$BLOCK_MARKER_START" "$BLOCK_MARKER_END" && _changed=true
    _remove_block "$profile" "$LEGACY_BLOCK_START" "$LEGACY_BLOCK_END" && _changed=true
    $_changed && print_success "Removed PATH configuration from $profile"
done

echo ""
print_success "Uninstall complete!"
