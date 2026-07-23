#!/bin/bash
#
# proxies.sh — lifecycle for Docker / npm / Azure sidecars and ssh-agent
#
# Starts host-side proxies that inject credentials without exposing them
# inside the sandbox namespace (ssh-agent pattern). Also manages a local
# ssh-agent when none is available.
#
# Depends on (from magen): LOCKDOWN, DRY_RUN, VERBOSE, log(), SCRIPT_REAL_DIR,
#   PROJECT_DIR, is_rw(), is_allowed_ro(), CONFIG_DENY, CACHE_DENY, MAGEN_LOG_FILE
#
# Sourced by: magen (not executed directly)
#

# Temp directory for proxy sockets and port/env files.
_MAGEN_TMP="/tmp/magen/sandbox"
mkdir -p "$_MAGEN_TMP"

# --- SSH agent (forward socket only; never private keys) ---
SSH_AGENT_STARTED=false

cleanup_ssh_agent() {
    if $SSH_AGENT_STARTED && [ -n "${SSH_AGENT_PID:-}" ]; then
        kill "$SSH_AGENT_PID" 2>/dev/null || true
    fi
}

# Poll until a probe command succeeds or the sidecar PID exits (startup wait for proxies).
_wait_sidecar_ready() {
    local _pid=$1 _max=$2
    shift 2
    local _i
    for _i in $(seq 1 "$_max"); do
        "$@" && return 0
        kill -0 "$_pid" 2>/dev/null || break
        sleep 0.1
    done
    return 1
}

# Stop a background sidecar by PID-from-nameref and unlink temp paths.
_cleanup_sidecar() {
    local _pid="${!1}"
    shift
    if [ -n "$_pid" ]; then
        kill "$_pid" 2>/dev/null || true
        wait "$_pid" 2>/dev/null || true
    fi
    rm -f "$@"
}

# --- Docker proxy (runs outside sandbox, validates container creation) ---
DOCKER_PROXY_PID=""
DOCKER_PROXY_SOCK=""
DOCKER_PROXY_DIR=""

# Start docker.py so the sandbox only sees a filtered Unix socket (creation API enforced).
start_docker_proxy() {
    if $LOCKDOWN || $DRY_RUN; then return 1; fi
    if [[ "${MAGEN_SKIP_VALIDATION:-}" == "1" ]]; then return 1; fi
    if ! command -v python3 &>/dev/null; then
        log "docker proxy: python3 not found, docker not available"
        return 1
    fi

    local _real=""
    for sock in /run/docker.sock /var/run/docker.sock "$HOME/.docker/run/docker.sock"; do
        [ -S "$sock" ] && _real="$(readlink -f "$sock")" && break
    done
    [ -z "$_real" ] && {
        log "docker: socket not found"
        return 1
    }

    DOCKER_PROXY_DIR="$(mktemp -d /tmp/magen/sandbox/docker.XXXXXX)" || return 1
    DOCKER_PROXY_SOCK="$DOCKER_PROXY_DIR/docker.sock"

    local _deny_args=()
    for entry in "$HOME"/.*; do
        [ -d "$entry" ] || continue
        local _dn="${entry##*/}"
        [[ "$_dn" == "." || "$_dn" == ".." ]] && continue
        is_rw "$_dn" && continue
        is_allowed_ro "$_dn" && continue
        _deny_args+=(--deny "$entry")
    done
    for d in "${CONFIG_DENY[@]}"; do
        [ -d "$HOME/.config/$d" ] && _deny_args+=(--deny "$HOME/.config/$d")
    done
    for d in "${CACHE_DENY[@]}"; do
        [ -d "$HOME/.cache/$d" ] && _deny_args+=(--deny "$HOME/.cache/$d")
    done

    local _proxy_args=(
        python3 "$SCRIPT_REAL_DIR/proxies/docker.py"
        --proxy-socket "$DOCKER_PROXY_SOCK"
        --target-socket "$_real"
        --docker-config "$HOME/.docker/config.json"
        ${_deny_args[@]+"${_deny_args[@]}"}
    )
    $VERBOSE && _proxy_args+=(--verbose)

    MAGEN_SESSION_LOG="${MAGEN_LOG_FILE:-}" "${_proxy_args[@]}" &>/dev/null &
    DOCKER_PROXY_PID=$!

    if ! _wait_sidecar_ready "$DOCKER_PROXY_PID" 50 test -S "$DOCKER_PROXY_SOCK"; then
        log "docker proxy: failed to start"
        kill "$DOCKER_PROXY_PID" 2>/dev/null || true
        DOCKER_PROXY_PID=""
        return 1
    fi

    log "docker: proxied ($_real → $DOCKER_PROXY_SOCK)"
    return 0
}

cleanup_docker_proxy() {
    _cleanup_sidecar DOCKER_PROXY_PID "${DOCKER_PROXY_SOCK:-}"
    rm -rf "${DOCKER_PROXY_DIR:-}"
    DOCKER_PROXY_DIR=""
}

# --- npm registry proxy (runs outside sandbox, injects auth headers) ---
# Analogous to ssh-agent: the credential is used but never exposed.
# Read-only: blocks PUT/POST/DELETE (prevents package publishing).
NPM_PROXY_PID=""
NPM_PROXY_PORT_FILE=""
NPM_PROXY_ENV_FILE=""

# Start npm_registry.py when .npmrc has auth; tokens stay on the host, not in the sandbox.
start_npm_proxy() {
    if $LOCKDOWN || $DRY_RUN; then return 1; fi
    if ! command -v python3 &>/dev/null; then return 1; fi

    local _has_tokens=false
    for _rc in "$HOME/.npmrc" "$PROJECT_DIR/.npmrc"; do
        [ -f "$_rc" ] && grep -qE '_(authToken|auth|password)\s*=' "$_rc" && _has_tokens=true
    done
    $_has_tokens || return 1

    NPM_PROXY_PORT_FILE=$(mktemp /tmp/magen/sandbox/npm-port.XXXXXX)
    NPM_PROXY_ENV_FILE=$(mktemp /tmp/magen/sandbox/npm-env.XXXXXX)

    local _npmrc_args=(--npmrc "$HOME/.npmrc")
    [ -f "$PROJECT_DIR/.npmrc" ] && _npmrc_args+=(--npmrc "$PROJECT_DIR/.npmrc")

    local _proxy_args=(
        python3 "$SCRIPT_REAL_DIR/proxies/npm_registry.py"
        "${_npmrc_args[@]}"
        --port-file "$NPM_PROXY_PORT_FILE"
        --env-file "$NPM_PROXY_ENV_FILE"
    )
    $VERBOSE && _proxy_args+=(--verbose)

    "${_proxy_args[@]}" &>/dev/null &
    NPM_PROXY_PID=$!

    if ! _wait_sidecar_ready "$NPM_PROXY_PID" 30 test -s "$NPM_PROXY_PORT_FILE"; then
        log "npm proxy: failed to start"
        kill "$NPM_PROXY_PID" 2>/dev/null || true
        NPM_PROXY_PID=""
        return 1
    fi

    log "npm proxy: listening on port $(cat "$NPM_PROXY_PORT_FILE")"
    return 0
}

cleanup_npm_proxy() {
    _cleanup_sidecar NPM_PROXY_PID "${NPM_PROXY_PORT_FILE:-}" "${NPM_PROXY_ENV_FILE:-}"
}

# --- Azure CLI proxy (runs outside sandbox, executes az commands with real creds) ---
# Same pattern as npm/Docker: credentials stay on the host. The sandbox sends
# full az commands via Unix socket; the proxy runs them and returns only output.
# Token-exposing commands (account get-access-token, login) are blocked.
AZURE_PROXY_PID=""
AZURE_PROXY_SOCK=""
AZURE_PROXY_DIR=""
AZURE_PROXY_WRAPPER_DIR=""

start_azure_proxy() {
    if $LOCKDOWN || $DRY_RUN; then return 1; fi
    if [[ "${MAGEN_SKIP_VALIDATION:-}" == "1" ]]; then return 1; fi
    if ! command -v az &>/dev/null; then return 1; fi
    if ! command -v python3 &>/dev/null; then return 1; fi
    az account show &>/dev/null 2>&1 || {
        log "azure proxy: az not logged in, skipping"
        return 1
    }

    AZURE_PROXY_DIR="$(mktemp -d /tmp/magen/sandbox/azure.XXXXXX)" || return 1
    AZURE_PROXY_SOCK="$AZURE_PROXY_DIR/azure.sock"

    local _proxy_args=(
        python3 "$SCRIPT_REAL_DIR/proxies/azure_cli.py"
        --socket "$AZURE_PROXY_SOCK"
    )
    $VERBOSE && _proxy_args+=(--verbose)

    MAGEN_SESSION_LOG="${MAGEN_LOG_FILE:-}" "${_proxy_args[@]}" &>/dev/null &
    AZURE_PROXY_PID=$!

    if ! _wait_sidecar_ready "$AZURE_PROXY_PID" 30 test -S "$AZURE_PROXY_SOCK"; then
        log "azure proxy: failed to start"
        kill "$AZURE_PROXY_PID" 2>/dev/null || true
        AZURE_PROXY_PID=""
        return 1
    fi

    AZURE_PROXY_WRAPPER_DIR=$(mktemp -d /tmp/magen/sandbox/az-wrapper.XXXXXX)
    cp "$SCRIPT_REAL_DIR/wrappers/az.py" "$AZURE_PROXY_WRAPPER_DIR/az"
    chmod +x "$AZURE_PROXY_WRAPPER_DIR/az"

    log "azure: CLI proxy on $AZURE_PROXY_SOCK"
    return 0
}

cleanup_azure_proxy() {
    _cleanup_sidecar AZURE_PROXY_PID "${AZURE_PROXY_SOCK:-}"
    rm -rf "${AZURE_PROXY_DIR:-}"
    AZURE_PROXY_DIR=""
    rm -rf "${AZURE_PROXY_WRAPPER_DIR:-}"
}
