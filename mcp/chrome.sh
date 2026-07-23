#!/bin/bash
#
# chrome.sh — Chrome DevTools MCP launcher compatible with magen/bwrap
#
# Inside a bwrap user namespace, Chrome's SUID sandbox is disabled. This
# wrapper detects that case, starts headless Chrome with --no-sandbox, and
# connects chrome-devtools-mcp via --browserUrl.
#
# On macOS (sandbox-exec) Chrome's own sandbox works; this script falls
# through to a normal npx launch.
#
# Environment:
#   CHROME_MCP_PORT    — preferred debugging port (default 9222)
#   CHROME_MCP_VERSION — chrome-devtools-mcp package version
#   MAGEN_ACTIVE       — set by magen when already inside the sandbox
#
# Installed as: ~/.local/bin/chrome-mcp (via install.sh)
#

set -euo pipefail

command -v npx &>/dev/null || {
    echo "Error: npx is required but not found on PATH" >&2
    exit 1
}

MCP_PKG="chrome-devtools-mcp@${CHROME_MCP_VERSION:-0.20.1}"

# --- Detection helpers ---
needs_chrome_workaround() {
    [[ "$(uname -s)" != "Linux" ]] && return 1
    [[ "${MAGEN_ACTIVE:-}" == "1" ]] && return 0
    # Auto-detect: in the initial user namespace the uid_map covers the full
    # 32-bit range (4294967295). A smaller range means we're inside a user
    # namespace where Chrome's SUID sandbox won't work.
    local uid_map
    uid_map="$(cat /proc/self/uid_map 2>/dev/null)" || return 1
    [[ "$uid_map" != *4294967295* ]]
}

is_chrome_devtools() {
    local port=$1 response
    response="$(curl -s --connect-timeout 1 --max-time 1 "http://127.0.0.1:${port}/json/version" 2>/dev/null)" || return 1
    [[ "$response" == *'"webSocketDebuggerUrl"'* ]]
}

read_pid() {
    local port=$1 pid
    [ -f "${LOCK_DIR}/${port}.pid" ] || return 1
    read -r pid <"${LOCK_DIR}/${port}.pid" 2>/dev/null || return 1
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    echo "$pid"
}

is_our_chrome() {
    local port=$1 pid
    pid="$(read_pid "$port")" || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    is_chrome_devtools "$port"
}

# Prefer ss over nc: ss queries the kernel socket table directly (no connection attempt).
# --- Port / process lifecycle ---
port_is_free() {
    local port=$1
    if command -v ss &>/dev/null; then
        if ss -tln sport = :"${port}" 2>/dev/null | grep -q LISTEN; then
            return 1
        fi
    elif command -v nc &>/dev/null; then
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 1
        fi
    else
        echo "Warning: no port-check tool found (ss, nc); assuming port $port is free" >&2
    fi
    return 0
}

find_chrome() {
    local bin bin_path
    # Keep in sync with the binary list in install.sh (Chrome MCP section).
    for bin in google-chrome google-chrome-stable chromium-browser chromium; do
        bin_path="$(command -v "$bin" 2>/dev/null)" || continue
        echo "$bin_path"
        return 0
    done
    # Fallback: wrappers shadowed every PATH hit. Check install dirs directly.
    for bin_path in \
        /opt/google/chrome/google-chrome \
        /usr/lib/chromium-browser/chromium-browser \
        /usr/lib/chromium/chromium; do
        [ -x "$bin_path" ] && echo "$bin_path" && return 0
    done
    return 1
}

graceful_kill() {
    local pid=$1 wait=${2:-1}
    kill "$pid" 2>/dev/null || return 0
    sleep "$wait"
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
}

cleanup_stale_pid() {
    local port=$1 pid
    pid="$(read_pid "$port")" || return 0
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "${LOCK_DIR}/${port}.pid"
    fi
}

find_available_port() {
    cleanup_stale_pid "$PREFERRED_PORT"

    if is_our_chrome "$PREFERRED_PORT" || port_is_free "$PREFERRED_PORT"; then
        echo "$PREFERRED_PORT"
        return 0
    fi

    local port max_port=$((PREFERRED_PORT + 100))
    ((max_port > 65535)) && max_port=65535
    for ((port = PREFERRED_PORT + 1; port <= max_port; port++)); do
        cleanup_stale_pid "$port"
        if is_our_chrome "$port" || port_is_free "$port"; then
            echo "$port"
            return 0
        fi
    done

    echo "Error: no available port in range ${PREFERRED_PORT}–$((PREFERRED_PORT + 100))" >&2
    return 1
}

# --- Launch headless Chrome and wait until DevTools responds ---
start_chrome() {
    local port=$1
    local chrome_bin chrome_pid attempts
    chrome_bin="$(find_chrome)" || {
        echo "Error: no Chrome/Chromium binary found on PATH" >&2
        exit 1
    }

    install -d -m 700 "$LOCK_DIR"

    (
        flock -n 200 || {
            echo "Error: another chrome-mcp instance is starting on port $port" >&2
            exit 1
        }

        "$chrome_bin" \
            --headless=new \
            --no-sandbox \
            --disable-gpu \
            --disable-dev-shm-usage \
            --disable-extensions \
            --user-data-dir="${LOCK_DIR}/profile-${port}" \
            --remote-debugging-port="$port" \
            --remote-debugging-address=127.0.0.1 \
            >>"${MAGEN_SESSION_LOG:-${LOCK_DIR}/chrome-${port}.log}" 2>&1 &

        echo "$!" >"${LOCK_DIR}/${port}.pid"
    ) 200>"${LOCK_DIR}/${port}.lock" || exit 1

    chrome_pid="$(read_pid "$port")" || {
        echo "Error: failed to read Chrome PID for port $port" >&2
        exit 1
    }

    attempts=0
    while ! is_chrome_devtools "$port"; do
        attempts=$((attempts + 1))
        if ((attempts > 30)); then
            graceful_kill "$chrome_pid" 1
            rm -f "${LOCK_DIR}/${port}.pid"
            echo "Error: Chrome failed to start on port $port (killed PID $chrome_pid)" >&2
            exit 1
        fi
        sleep 0.5
    done
}

if needs_chrome_workaround; then
    command -v curl &>/dev/null || {
        echo "Error: curl is required for sandbox mode but not found on PATH" >&2
        exit 1
    }

    PREFERRED_PORT="${CHROME_MCP_PORT:-9222}"
    if ! [[ "$PREFERRED_PORT" =~ ^[0-9]+$ ]] || ((PREFERRED_PORT < 1024 || PREFERRED_PORT > 65535)); then
        echo "Error: invalid CHROME_MCP_PORT=$PREFERRED_PORT (expected 1024–65535)" >&2
        exit 1
    fi

    LOCK_DIR="${XDG_RUNTIME_DIR:-/tmp}/chrome-mcp-${UID}"

    # Clean up orphaned profiles from previous sessions that crashed
    # without running their EXIT trap (e.g. SIGKILL, power loss).
    if [ -d "$LOCK_DIR" ]; then
        for _pidfile in "$LOCK_DIR"/*.pid; do
            [ -f "$_pidfile" ] || continue
            _stale_port="${_pidfile##*/}"
            _stale_port="${_stale_port%.pid}"
            _stale_pid="$(cat "$_pidfile" 2>/dev/null)" || continue
            if ! kill -0 "$_stale_pid" 2>/dev/null; then
                rm -f "$_pidfile" "${LOCK_DIR}/${_stale_port}.lock" "${LOCK_DIR}/chrome-${_stale_port}.log"
                rm -rf "${LOCK_DIR}/profile-${_stale_port}"
            fi
        done
    fi

    port="$(find_available_port)"

    CHROME_STARTED=false
    if ! is_our_chrome "$port"; then
        start_chrome "$port"
        CHROME_STARTED=true
    fi

    cleanup_chrome() {
        if [[ "$CHROME_STARTED" == true ]]; then
            local pid
            pid="$(read_pid "$port")" || return 0
            graceful_kill "$pid" 0.3
            rm -f "${LOCK_DIR}/${port}.pid" "${LOCK_DIR}/${port}.lock"
            [[ -z "${MAGEN_SESSION_LOG:-}" ]] && rm -f "${LOCK_DIR}/chrome-${port}.log"
            rm -rf "${LOCK_DIR}/profile-${port}"
            rmdir "$LOCK_DIR" 2>/dev/null || true
        fi
    }
    trap cleanup_chrome EXIT

    # No exec here — shell must stay alive for the EXIT trap (cleanup_chrome).
    npm_config_registry="${npm_config_registry:-https://registry.npmjs.org}" \
        npx -y "$MCP_PKG" --browserUrl="http://127.0.0.1:${port}" "$@"
else
    exec env npm_config_registry="${npm_config_registry:-https://registry.npmjs.org}" \
        npx -y "$MCP_PKG" "$@"
fi
