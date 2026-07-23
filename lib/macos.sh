#!/bin/bash
#
# macos.sh — macOS sandbox backend for magen (sandbox-exec / Seatbelt)
#
# Builds an SBPL deny-default profile, sanitizes env/credentials like the
# Linux path, and execs sandbox-exec. Defines magen_macos(), called by the
# magen hub after shared setup.
#
# Sourced by: magen on Darwin (not executed directly)
#

# macOS entry: build SBPL profile, sanitize env like Linux, run sandbox-exec.
# --- macOS entry point (sandbox-exec / Seatbelt) ---
magen_macos() {
    command -v sandbox-exec &>/dev/null || {
        echo "Error: sandbox-exec not found." >&2
        echo "It should ship with macOS. Check your system." >&2
        exit 1
    }

    # Escape a path for embedding in SBPL (backslashes and quotes).
    sanitize_path() {
        local p="${1//\\/\\\\}"
        printf '%s' "${p//\"/\\\"}"
    }
    sbpl() { PROFILE+=$'\n'"$1"; }
    sbpl_deny() { sbpl "(deny file-read* file-write* (subpath \"$(sanitize_path "$1")\"))"; }
    sbpl_deny_re() { sbpl "(deny file-read* file-write* (regex #\"$1\"))"; }
    sbpl_ro() { sbpl "(allow file-read* (subpath \"$(sanitize_path "$1")\"))"; }
    sbpl_rw() { sbpl "(allow file-read* file-write* (subpath \"$(sanitize_path "$1")\"))"; }
    sbpl_ro_lit() { sbpl "(allow file-read* (literal \"$(sanitize_path "$1")\"))"; }
    sbpl_rw_lit() { sbpl "(allow file-read* file-write* (literal \"$(sanitize_path "$1")\"))"; }
    sbpl_deny_lit() { sbpl "(deny file-read* file-write* (literal \"$(sanitize_path "$1")\"))"; }

    # Assemble PROFILE: allowlists, dotdirs, denies (order matters — last match wins in SBPL).
    _sbpl_build_profile() {
        PROFILE='(version 1)
(deny default)
(allow process*)
(allow signal)
(allow sysctl-read)
(allow mach-lookup)
(allow ipc-posix*)
(allow system-socket)'

        if $LOCKDOWN; then
            log "lockdown: network disabled"
        else
            sbpl '(allow network*)'
        fi

        PROFILE+=$'\n''
(allow file-read* (literal "/"))
(allow file-read* (subpath "/usr"))
(allow file-read* (subpath "/bin"))
(allow file-read* (subpath "/sbin"))
(allow file-read* (subpath "/Library"))
(allow file-read* (subpath "/System"))
(allow file-read* (subpath "/dev"))
(allow file-write* (literal "/dev/null"))
(allow file-write* (literal "/dev/zero"))
(allow file-write* (literal "/dev/random"))
(allow file-write* (literal "/dev/urandom"))
(allow file-write* (subpath "/dev/fd"))
(allow file-write* (regex #"^/dev/(pty|ttys)"))
(allow file-read* (subpath "/Applications"))
(allow file-read* (subpath "/etc"))
(allow file-read* (subpath "/var"))
(allow file-read* (subpath "/private/etc"))
(allow file-read* (subpath "/private/var"))
(allow file-read* file-write* (subpath "/tmp"))
(allow file-read* file-write* (subpath "/private/tmp"))
(allow file-read* file-write* (regex #"^/private/var/folders/"))
(allow file-read* (subpath "/opt/homebrew"))
(allow file-read* (subpath "/usr/local"))'

        if $LOCKDOWN; then
            sbpl_ro "$PROJECT_DIR"
            log "lockdown: project read-only"
        else
            sbpl_rw "$PROJECT_DIR"
            if [[ "$PARENT_DIR" != "/" ]]; then
                sbpl_rw "$PARENT_DIR"
                log "rw: parent directory $PARENT_DIR"
            fi
            if [[ -n "$GIT_WORKTREE_MAIN_GIT" ]] && [ -d "$GIT_WORKTREE_MAIN_GIT" ]; then
                sbpl_rw "$GIT_WORKTREE_MAIN_GIT"
                log "rw worktree main .git: $GIT_WORKTREE_MAIN_GIT"
            fi
        fi

        if ! $LOCKDOWN; then
            if [ -n "$DOCKER_PROXY_SOCK" ] && [ -S "$DOCKER_PROXY_SOCK" ]; then
                sbpl_rw_lit "$DOCKER_PROXY_SOCK"
                log "docker: proxy socket at $DOCKER_PROXY_SOCK"
            else
                log "docker: not available"
            fi

            for entry in "$HOME"/.*; do
                [ -d "$entry" ] || continue
                name="${entry##*/}"
                [[ "$name" == "." || "$name" == ".." ]] && continue
                if is_rw "$name"; then
                    sbpl_rw "$entry"
                elif is_allowed_ro "$name"; then
                    sbpl_ro "$entry"
                fi
            done

            for _rc in .bashrc .profile .bash_logout .bash_aliases .zshrc .gitconfig; do
                if [ -f "$HOME/$_rc" ]; then
                    sbpl_ro_lit "$HOME/$_rc"
                fi
            done
            NVM_REAL="${NVM_DIR:-$HOME/.nvm}"
            if [ -d "$NVM_REAL" ]; then
                sbpl_ro "$NVM_REAL"
            fi

            for p in "${EXTRA_RO_MAPS[@]+"${EXTRA_RO_MAPS[@]}"}"; do
                sbpl_ro "$p"
            done
            for p in "${EXTRA_RW_MAPS[@]+"${EXTRA_RW_MAPS[@]}"}"; do
                sbpl_rw "$p"
            done

            # macOS ~/Library/ — allowlist approach: only specific subdirs are writable.
            if [ -d "$HOME/Library" ]; then
                for d in "${LIBRARY_ALLOW[@]}"; do
                    if [ -d "$HOME/Library/$d" ]; then
                        sbpl_rw "$HOME/Library/$d"
                    fi
                done
                for d in "${LIBRARY_APP_SUPPORT_ALLOW[@]}"; do
                    if [ -d "$HOME/Library/Application Support/$d" ]; then
                        sbpl_rw "$HOME/Library/Application Support/$d"
                    fi
                done
            fi
        else
            log "lockdown: no dotfiles, no extra maps"
        fi

        # SBPL uses "last matching rule wins": deny rules MUST come after
        # broader allows to override them (e.g. .config allowed but .config/gh denied).
        for denied in "${CONFIG_DENY[@]}"; do
            sbpl_deny "$HOME/.config/$denied"
        done
        for denied in "${CACHE_DENY[@]}"; do
            sbpl_deny "$HOME/.cache/$denied"
        done
        if [ -n "$SESSION_LOG_FIFO" ]; then
            sbpl_deny "$_session_log_dir"
        fi
        for entry in "${_SENSITIVE_FILE_PATTERNS[@]}"; do
            sbpl_deny_re "${entry#*|}"
        done

        # Block real Docker sockets (force traffic through proxy).
        if ! $LOCKDOWN; then
            for _dsock in "$HOME/.docker/run/docker.sock" \
                "$HOME/.docker/desktop/docker.sock" \
                "$HOME/.docker/docker.sock"; do
                if [ -S "$_dsock" ]; then
                    sbpl_deny_lit "$_dsock"
                fi
            done
            for _vsock in /var/run/docker.sock /run/docker.sock; do
                if [ -S "$_vsock" ]; then
                    sbpl_deny_lit "$_vsock"
                fi
            done

            # Block Docker TLS client certificates.
            for _dtls in ca.pem cert.pem key.pem; do
                if [ -f "$HOME/.docker/$_dtls" ]; then
                    sbpl_deny_lit "$HOME/.docker/$_dtls"
                fi
            done

            # Block Docker config.json (sanitized copy provided via DOCKER_CONFIG env).
            if [ -f "$HOME/.docker/config.json" ]; then
                sbpl_deny_lit "$HOME/.docker/config.json"
            fi

            # Block Azure credential cache files.
            if [ -d "$HOME/.azure" ]; then
                for _az_file in accessTokens.json msal_token_cache.json msal_http_cache.bin service_principal_entries.json; do
                    if [ -f "$HOME/.azure/$_az_file" ]; then
                        sbpl_deny_lit "$HOME/.azure/$_az_file"
                    fi
                done
            fi
        fi

        # After denies: allow CA bundles and SSH metadata (\.pem$ deny would break TLS otherwise).
        sbpl_ro "/etc/ssl"
        sbpl_ro "/private/etc/ssl"
        if ! $LOCKDOWN; then
            if [ -f "$HOME/.ssh/config" ]; then
                sbpl_ro_lit "$HOME/.ssh/config"
            fi
            if [ -f "$HOME/.ssh/known_hosts" ]; then
                sbpl_ro_lit "$HOME/.ssh/known_hosts"
            fi
        fi

        MODE="normal"
        if $LOCKDOWN; then
            MODE="lockdown"
        fi

        # Detect Electron/.app GUI apps — Chrome's internal sandbox can't nest
        # inside sandbox-exec (SIGSEGV), so --no-sandbox is required.
        # GUI apps also need IOKit (GPU/display) and user-preference access.
        _is_gui=false
        if ! $LOCKDOWN; then
            if _electron_bin="$(resolve_macos_electron "${COMMAND_ARGS[0]}")"; then
                _is_gui=true
                COMMAND_ARGS[0]="$_electron_bin"
                COMMAND_ARGS+=("--no-sandbox")
                sbpl '(allow iokit-open)'
                sbpl '(allow iokit-get-properties)'
                sbpl '(allow iokit-set-properties)'
                sbpl '(allow mach-register)'
                sbpl '(allow mach-task-name)'
                sbpl '(allow user-preference-read)'
                sbpl '(allow user-preference-write)'
                sbpl '(allow appleevent-send)'
                sbpl '(allow lsopen)'
                log "gui: resolved ${COMMAND_ARGS[0]} → Electron binary, added --no-sandbox"
            fi
        fi
    }

    # Match Linux: strip secret-like env, colors, proxies, sanitized Docker/npm config, BASH_ENV logger.
    _macos_prep_env() {
        _macos_env_args=()
        _MACOS_DOCKER_CFG_DIR=""
        _MACOS_NPMRC=""
        TEMP_CMD_LOGGER_MAC=""
        if ! $LOCKDOWN && ! $DRY_RUN; then
            for _prefix in "${_ENV_SENSITIVE_PREFIXES[@]}"; do
                while IFS= read -r _var; do
                    [ -n "$_var" ] || continue
                    if _is_env_safe "$_var"; then
                        log "env: kept $_var (safe)"
                    else
                        _macos_env_args+=(-u "$_var")
                    fi
                done < <(compgen -A export "$_prefix" 2>/dev/null)
            done

            _macos_env_args+=(-u NO_COLOR -u FORCE_COLOR)
            if [ -t 1 ]; then
                _macos_env_args+=("FORCE_COLOR=1" "COLORTERM=truecolor" "DOCKER_CLI_COLOR=always")
                log "env: color enabled (TTY detected)"
            fi

            _macos_env_args+=("DOTNET_BUNDLE_EXTRACT_BASE_DIR=/tmp/.dotnet-bundle-extract")

            if [ -n "$DOCKER_PROXY_SOCK" ] && [ -S "$DOCKER_PROXY_SOCK" ]; then
                _macos_env_args+=("DOCKER_HOST=unix://$DOCKER_PROXY_SOCK")
            fi

            if [ -f "$HOME/.docker/config.json" ] && command -v python3 &>/dev/null; then
                _MACOS_DOCKER_CFG_DIR=$(mktemp -d /tmp/magen/sandbox/docker-cfg.XXXXXX)
                _sanitize_docker_config "$HOME/.docker/config.json" "$_MACOS_DOCKER_CFG_DIR/config.json"
                _macos_env_args+=("DOCKER_CONFIG=$_MACOS_DOCKER_CFG_DIR")
                log "ro: docker config sanitized (auth stripped)"
            fi

            if [ -n "$NPM_PROXY_PID" ] && [ -s "$NPM_PROXY_ENV_FILE" ]; then
                while IFS=$'\t' read -r _key _val; do
                    if [ -n "$_key" ]; then
                        _macos_env_args+=("$_key=$_val")
                    fi
                done <"$NPM_PROXY_ENV_FILE"
                log "npm proxy: env vars injected"
            fi

            # Azure token proxy: prepend wrapper dir to PATH so `az` resolves to the proxy shim.
            if [ -n "$AZURE_PROXY_PID" ] && [ -S "$AZURE_PROXY_SOCK" ]; then
                _macos_env_args+=("AZURE_CLI_PROXY_SOCK=$AZURE_PROXY_SOCK")
                _macos_env_args+=("PATH=${AZURE_PROXY_WRAPPER_DIR}:${PATH}")
                log "azure: CLI proxy → $AZURE_PROXY_SOCK (az wrapper prepended to PATH)"
            fi

            if [ -f "$HOME/.npmrc" ]; then
                _MACOS_NPMRC=$(mktemp /tmp/npmrc-clean.XXXXXX)
                grep -v -E '_(authToken|auth|password)\s*=' "$HOME/.npmrc" >"$_MACOS_NPMRC" 2>/dev/null || true
                if [ -n "$NPM_PROXY_PID" ] && [ -s "$NPM_PROXY_ENV_FILE" ]; then
                    while IFS=$'\t' read -r _key _val; do
                        [ -n "$_key" ] || continue
                        local _npmrc_key="${_key#npm_config_}"
                        printf '%s=%s\n' "$_npmrc_key" "$_val" >>"$_MACOS_NPMRC"
                    done <"$NPM_PROXY_ENV_FILE"
                fi
                _macos_env_args+=("NPM_CONFIG_USERCONFIG=$_MACOS_NPMRC")
                log "ro: ~/.npmrc sanitized (auth tokens stripped)"
            fi

            TEMP_CMD_LOGGER_MAC=$(mktemp /tmp/magen/sandbox/cmd-logger.XXXXXX)
            _write_cmd_logger "$TEMP_CMD_LOGGER_MAC"
            # Pass the logger script directly via ENV and BASH_ENV (read by sh/bash)
            # And add an alias/wrapper to the PATH or inject via ZDOTDIR, forcing ~/.zshrc to be read
            _macos_env_args+=("ENV=$TEMP_CMD_LOGGER_MAC" "BASH_ENV=$TEMP_CMD_LOGGER_MAC")

            TEMP_ZSHENV_MAC=$(mktemp -d /tmp/magen/sandbox/zsh.XXXXXX)
            cat >"$TEMP_ZSHENV_MAC/.zshrc" <<ZSHRC
[[ -f "\$HOME/.zshrc" ]] && source "\$HOME/.zshrc"

[[ -f "$TEMP_CMD_LOGGER_MAC" ]] && source "$TEMP_CMD_LOGGER_MAC"

preexec_functions+=(_sandbox_zsh_logger)

export CLICOLOR=1
export FORCE_COLOR=1
export COLORTERM=truecolor
export TERM="${TERM:-xterm-256color}"
ZSHRC

            _macos_env_args+=("ZDOTDIR=$TEMP_ZSHENV_MAC" "BASH_ENV=$TEMP_CMD_LOGGER_MAC")
        fi
    }

    # Write session header, run sandbox-exec (foreground, lockdown, or background GUI).
    _macos_execute() {
        # shellcheck disable=SC2317
        _macos_cleanup_temps() {
            rm -f "$TEMP_PROFILE" "${TEMP_CMD_LOGGER_MAC:-}" "${_MACOS_NPMRC:-}"
            rm -rf "${TEMP_ZSHENV_MAC:-}"
            if [ -n "${_MACOS_DOCKER_CFG_DIR:-}" ]; then
                rm -rf "$_MACOS_DOCKER_CFG_DIR"
            fi
        }

        trap '_macos_cleanup_temps; cleanup_npm_proxy; cleanup_docker_proxy; cleanup_azure_proxy; cleanup_ssh_agent; cleanup_log_reader' EXIT

        if $DRY_RUN; then
            echo "Dry-run (sandbox-exec/$MODE): $PROJECT_DIR"
            echo ""
            echo "Generated SBPL profile:"
            echo "$PROFILE"
            echo ""
            return
        fi

        _write_session_header \
            "  Library allow:  ${LIBRARY_ALLOW[*]}" \
            "  AppSupport allow: ${LIBRARY_APP_SUPPORT_ALLOW[*]}"

        _show_banner

        cd "$PROJECT_DIR"
        if $LOCKDOWN; then
            env -i HOME="$HOME" USER="${USER:-$(whoami)}" PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
                TERM="${TERM:-xterm}" LANG="${LANG:-C.UTF-8}" \
                MAGEN_ACTIVE=1 PS1="(sandbox:lockdown) \u@\h:\w \$ " \
                sandbox-exec -f "$TEMP_PROFILE" "${COMMAND_ARGS[@]}"
        elif $_is_gui; then
            trap '' EXIT
            # shellcheck disable=SC2094
            MAGEN_ACTIVE=1 MAGEN_SESSION_LOG="${SESSION_LOG_FIFO:-$MAGEN_LOG_FILE}" \
                env ${_macos_env_args[@]+"${_macos_env_args[@]}"} \
                sandbox-exec -f "$TEMP_PROFILE" "${COMMAND_ARGS[@]}" </dev/null >>"$MAGEN_LOG_FILE" 2>&1 &
            _sbx_pid=$!
            disown
            echo "Logs: $MAGEN_LOG_FILE"
            (
                sleep 3
                _macos_cleanup_temps
                while kill -0 "$_sbx_pid" 2>/dev/null; do sleep 5; done
                cleanup_npm_proxy
                cleanup_docker_proxy
                cleanup_azure_proxy
                cleanup_ssh_agent
                cleanup_log_reader
            ) &
            disown
        else
            _user_shell="${COMMAND_ARGS[0]}"
            
            if [[ "$_user_shell" == *"zsh"* ]]; then
                COMMAND_ARGS=("$_user_shell" "+m" "-c" "source '$TEMP_CMD_LOGGER_MAC'; exec $_user_shell +m")
            fi

            BASH_SILENCE_DEPRECATION_WARNING=1 \
            MAGEN_ACTIVE=1 \
            MAGEN_SESSION_LOG="${SESSION_LOG_FIFO:-$MAGEN_LOG_FILE}" \
                env ${_macos_env_args[@]+"${_macos_env_args[@]}"} \
                CLICOLOR=1 FORCE_COLOR=1 COLORTERM=truecolor TERM="${TERM:-xterm-256color}" \
                sandbox-exec -f "$TEMP_PROFILE" "${COMMAND_ARGS[@]}"
        fi
    }

    _sbpl_build_profile
    TEMP_PROFILE="$(mktemp /tmp/magen/sandbox/profile.XXXXXX).sb"
    echo "$PROFILE" >"$TEMP_PROFILE"
    _macos_prep_env
    _macos_execute
}
