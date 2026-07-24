#!/bin/bash
#
# linux.sh — Linux sandbox backend for magen (bubblewrap)
#
# Assembles bwrap mounts, env sanitization, Landlock, cgroups, and session
# logging integration. Defines magen_linux(), called by the magen hub after
# shared setup (CLI, allowlists, proxies, session log).
#
# Sourced by: magen on Linux (not executed directly)
#

# --- Linux entry point (bubblewrap) ---
# Assemble bwrap argv, optional Landlock wrapper, then exec or background GUI.
# shellcheck disable=SC2329
magen_linux() {
    command -v bwrap &>/dev/null || {
        echo "Error: bubblewrap (bwrap) is not installed." >&2
        echo "Run: sudo apt install bubblewrap uidmap" >&2
        exit 1
    }

    _is_gui=false
    if is_chromium_based "${COMMAND_ARGS[0]}"; then
        _is_gui=true
        _gui_name="${COMMAND_ARGS[0]##*/}"
        # Resolve to the real binary so bwrap doesn't pick up the chromium
        # wrapper from PATH. CLI launchers (bin/$name) spawn detached children
        # that die when bwrap's PID namespace tears down — use the raw Electron
        # binary one level up (standard Electron app layout).
        if ! ((_snap_app)); then
            _real="$(find_chromium_binary "$_gui_name")" && {
                _real="$(readlink -f "$_real")"
                _raw="${_real%/bin/"$_gui_name"}/$_gui_name"
                [ -x "$_raw" ] && [[ "$_raw" != "$_real" ]] && _real="$_raw"
                COMMAND_ARGS[0]="$_real"
            }
        fi
        COMMAND_ARGS+=("--no-sandbox")
        ((_snap_app)) && COMMAND_ARGS+=("--disable-gpu")
    fi

    TEMP_HOSTS=$(mktemp /tmp/bwrap-hosts.XXXXXX)
    TEMP_RESOLV=$(mktemp /tmp/bwrap-resolv.XXXXXX)
    TEMP_CMD_LOGGER=$(mktemp /tmp/bwrap-cmd-logger.XXXXXX)
    _write_cmd_logger "$TEMP_CMD_LOGGER" with-stderr

    TEMP_BASHRC_WRAPPER=$(mktemp /tmp/bwrap-bashrc.XXXXXX)
    cat >"$TEMP_BASHRC_WRAPPER" <<'BASHRC'
[[ -f "$HOME/.bashrc.orig" ]] && . "$HOME/.bashrc.orig"
[[ -f /tmp/magen/sandbox/cmd-logger.sh ]] && . /tmp/magen/sandbox/cmd-logger.sh
if [[ "${MAGEN_MODE:-}" == "lockdown" ]]; then
    PS1='\[\e[01;31m\](sandbox:lockdown)\[\e[00m\] \[\e[01;32m\]\u@${MAGEN_HOSTNAME}\[\e[00m\]:\[\e[01;34m\]\w\[\e[00m\]\$ '
else
    PS1='\[\e[01;33m\](sandbox)\[\e[00m\] \[\e[01;32m\]\u@${MAGEN_HOSTNAME}\[\e[00m\]:\[\e[01;34m\]\w\[\e[00m\]\$ '
fi
if [[ -n "${MAGEN_SESSION_LOG:-}" ]]; then
    _MAGEN_STDERR_BUF=$(mktemp /tmp/magen/sandbox/stderr.XXXXXX)
    _MAGEN_STDERR_OFFSET=0
    exec 3>&2 2> >(tee "$_MAGEN_STDERR_BUF" >&3)
    # Flush unflushed stderr on shell exit (covers Ctrl+D / close terminal
    # before PROMPT_COMMAND can fire for the last failed command).
    _sandbox_on_exit() {
        local _rc=$?
        sleep 0.1
        if ! ${_MAGEN_EXIT_LOGGED:-false} && (( _rc != 0 )); then
            printf '[%s] [exit %d]\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_rc" >> "$MAGEN_SESSION_LOG" 2>/dev/null
        fi
        _sandbox_flush_stderr
        rm -f "$_MAGEN_STDERR_BUF" 2>/dev/null
    }
    trap '_sandbox_on_exit' EXIT
fi
BASHRC

    CHROMIUM_WRAPPER_DIR=""
    if ! $LOCKDOWN; then
        CHROMIUM_WRAPPER_DIR="$(create_chromium_wrappers 2>/dev/null)" || true
    fi

    trap 'rm -rf "$TEMP_HOSTS" "$TEMP_RESOLV" "${TEMP_NPMRC:-}" "${TEMP_PROJ_NPMRC:-}" "${TEMP_DOCKER_CONFIG:-}" "${_AZ_EMPTY:-}" "$TEMP_CMD_LOGGER" "$TEMP_BASHRC_WRAPPER" "${MAGEN_XAUTH:-}" "${CHROMIUM_WRAPPER_DIR:-}"; cleanup_npm_proxy; cleanup_docker_proxy; cleanup_azure_proxy; cleanup_ssh_agent; cleanup_log_reader' EXIT
    printf '127.0.0.1 localhost sandbox\n::1       localhost sandbox\n' >"$TEMP_HOSTS"

    # Follow resolv.conf symlink chain (systemd-resolved).
    RESOLV_TARGET="$(readlink -f /etc/resolv.conf 2>/dev/null || echo /etc/resolv.conf)"
    cat "$RESOLV_TARGET" >"$TEMP_RESOLV" 2>/dev/null || true

    BWRAP_ARGS=()
    bw() { BWRAP_ARGS+=("$@"); }

    # Bind sensitive paths to /dev/null at startup; Landlock still covers files created later.
    mask_sensitive_files() {
        local dir="$1"
        [ -d "$dir" ] || return 0
        local _found=0
        while IFS= read -r -d '' _file; do
            bw --ro-bind /dev/null "$_file"
            _found=$((_found + 1))
        done < <(find -L "$dir" -maxdepth 10 -type f \
            -not -path '*/node_modules/*' \
            -not -path '*/.git/objects/*' \
            "${_FIND_NAME_ARGS[@]}" \
            -print0 2>/dev/null)
        ((_found)) && log "masked $_found sensitive file(s) in $dir"
        return 0
    }

    _sandbox_term="${TERM:-xterm-256color}"
    [[ "$_sandbox_term" == "dumb" ]] && _sandbox_term=xterm-256color

    # Core OS tree, /dev, /proc, optional GPU; lockdown uses --clearenv and drops GPU.
    _bwrap_system_mounts() {
        if $LOCKDOWN; then
            bw --clearenv \
                --setenv HOME "$HOME" \
                --setenv USER "${USER:-$(whoami)}" \
                --setenv PATH "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
                --setenv TERM "$_sandbox_term" \
                --setenv LANG "${LANG:-C.UTF-8}"
            log "lockdown: environment cleared"
        fi

        bw --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib
        for p in /lib64 /sbin; do [ -e "$p" ] && bw --ro-bind "$p" "$p"; done
        for p in /opt /snap /var/lib/snapd; do [ -d "$p" ] && bw --ro-bind "$p" "$p"; done
        bw --ro-bind /etc /etc --ro-bind "$TEMP_HOSTS" /etc/hosts --ro-bind /sys /sys --dev /dev

        if ! $LOCKDOWN; then
            for dev in /dev/nvidia* /dev/dri; do [ -e "$dev" ] && bw --dev-bind "$dev" "$dev"; done
        else
            log "lockdown: GPU disabled"
        fi

        [ -d /dev/shm ] && bw --tmpfs /dev/shm
        bw --proc /proc --tmpfs /tmp
    }

    # Unset high-risk env prefixes in normal mode; enable TTY colors; select Landlock helper if present.
    _bwrap_env_and_session() {
        if ! $LOCKDOWN; then
            for _prefix in "${_ENV_SENSITIVE_PREFIXES[@]}"; do
                while IFS= read -r _var; do
                    [ -n "$_var" ] || continue
                    _is_env_safe "$_var" && {
                        log "env: kept $_var (safe)"
                        continue
                    }
                    bw --unsetenv "$_var" && log "env: unset $_var"
                done < <(compgen -A export "$_prefix" 2>/dev/null)
            done
        fi

        # Strip IDE-injected NO_COLOR/FORCE_COLOR=0; re-enable colors on TTY.
        bw --unsetenv NO_COLOR --unsetenv FORCE_COLOR
        if [ -t 1 ]; then
            bw --setenv FORCE_COLOR 1
            bw --setenv COLORTERM truecolor
            bw --setenv DOCKER_CLI_COLOR always
            log "env: color enabled (TTY detected)"
        fi

        # Agent recipe SET_ENV (e.g. AGENT_CLI_CREDENTIAL_STORE=file).
        local _se _sk _sv
        for _se in ${_AGENTS_SET_ENV[@]+"${_AGENTS_SET_ENV[@]}"}; do
            [[ "$_se" == *=* ]] || continue
            _sk="${_se%%=*}"
            _sv="${_se#*=}"
            bw --setenv "$_sk" "$_sv"
        done

        # Landlock tightens FS access after mounts (defense in depth inside bwrap).
        LANDLOCK_INSIDE=""
        if [ -f "${SCRIPT_REAL_DIR}/lib/landlock.py" ] && command -v python3 &>/dev/null; then
            LANDLOCK_INSIDE="/tmp/magen/sandbox/landlock.py"
        else
            log "landlock: not available (python3 or helper not found)"
        fi
    }

    # /run, Docker proxy socket, DNS path for resolved, X11/Wayland, XDG_RUNTIME_DIR, ssh-agent.
    _bwrap_runtime_and_network() {
        # IDE sockets: bind only when owned by current user (reduces accidental cross-user access).
        if ! $LOCKDOWN; then
            _my_uid="$(id -u)"
            for sock in /tmp/cursor-* /tmp/vscode-*; do
                [ -e "$sock" ] || continue
                _sock_uid="$(stat -c %u "$sock" 2>/dev/null)" || continue
                if [[ "$_sock_uid" == "$_my_uid" ]]; then
                    bw --bind "$sock" "$sock"
                else
                    log "WARNING: skipping $sock (owner $_sock_uid != $_my_uid)"
                fi
            done

            # Build sandbox PATH incrementally; a single --setenv PATH at the end
            # avoids later calls overwriting earlier prepends.
            _sandbox_path="${PATH}"

            # Prepend wrapper dir so interactive shells resolve e.g. `cursor` to --no-sandbox shim first.
            if [ -n "$CHROMIUM_WRAPPER_DIR" ] && [ -d "$CHROMIUM_WRAPPER_DIR" ]; then
                bw --ro-bind "$CHROMIUM_WRAPPER_DIR" "$CHROMIUM_WRAPPER_DIR"
                _sandbox_path="${CHROMIUM_WRAPPER_DIR}:${_sandbox_path}"
                log "chromium wrappers: $CHROMIUM_WRAPPER_DIR prepended to PATH"
            fi
        fi

        bw --tmpfs /run

        if ! $LOCKDOWN; then
            [ -d /run/dbus ] && bw --ro-bind /run/dbus /run/dbus
            [ -d /run/snapd ] && bw --ro-bind /run/snapd /run/snapd
            # Only the filtered proxy socket is visible; real docker.sock is never bound in.
            if [ -n "$DOCKER_PROXY_SOCK" ] && [ -S "$DOCKER_PROXY_SOCK" ]; then
                bw --dir /var/run --bind "$DOCKER_PROXY_SOCK" /var/run/docker.sock
                log "docker: proxy socket → /var/run/docker.sock"
            else
                log "docker: not available"
            fi

            # Azure CLI proxy: bind socket + wrapper, set env var, prepend to PATH.
            if [ -n "$AZURE_PROXY_PID" ] && [ -S "$AZURE_PROXY_SOCK" ]; then
                bw --bind "$AZURE_PROXY_SOCK" "$AZURE_PROXY_SOCK"
                bw --ro-bind "$AZURE_PROXY_WRAPPER_DIR" "$AZURE_PROXY_WRAPPER_DIR"
                bw --setenv AZURE_CLI_PROXY_SOCK "$AZURE_PROXY_SOCK"
                _sandbox_path="${AZURE_PROXY_WRAPPER_DIR}:${_sandbox_path}"
                log "azure: CLI proxy → $AZURE_PROXY_SOCK (az wrapper prepended to PATH)"
            fi

            # Set the accumulated PATH once (avoids bwrap last-wins override).
            bw --setenv PATH "$_sandbox_path"

            # Recreate intermediate dirs for systemd-resolved symlink chain.
            if [ -L /etc/resolv.conf ]; then
                RESOLV_DIR="$(dirname "$RESOLV_TARGET")"
                IFS='/' read -ra PARTS <<<"${RESOLV_DIR#/}"
                BUILT=""
                for part in "${PARTS[@]}"; do
                    BUILT="$BUILT/$part"
                    bw --dir "$BUILT"
                done
                bw --ro-bind "$TEMP_RESOLV" "$RESOLV_TARGET"
            else
                bw --ro-bind "$TEMP_RESOLV" /etc/resolv.conf
            fi

            [ -d /tmp/.X11-unix ] && bw --bind /tmp/.X11-unix /tmp/.X11-unix
            [ -n "${DISPLAY:-}" ] && bw --setenv DISPLAY "$DISPLAY"
            if [ -n "${DISPLAY:-}" ] && command -v xauth &>/dev/null; then
                # XSECURITY: generate an untrusted cookie that blocks cross-window
                # keystroke capture, screenshots, and input injection (XTEST).
                MAGEN_XAUTH=$(mktemp /tmp/bwrap-xauth.XXXXXX)
                if xauth -f "$MAGEN_XAUTH" generate "$DISPLAY" . untrusted timeout 86400 2>/dev/null; then
                    bw --ro-bind "$MAGEN_XAUTH" "$MAGEN_XAUTH" \
                        --setenv XAUTHORITY "$MAGEN_XAUTH"
                    log "x11: untrusted cookie (keystroke/screenshot isolation)"
                else
                    log "x11: untrusted cookie failed — X11 disabled (install xauth for secure access)"
                fi
            elif [ -n "${XAUTHORITY:-}" ]; then
                log "x11: xauth not found — X11 disabled (install xauth for secure access)"
            fi
            if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR" ]; then
                bw --bind "$XDG_RUNTIME_DIR" "$XDG_RUNTIME_DIR" --setenv XDG_RUNTIME_DIR "$XDG_RUNTIME_DIR"
                # tmpfs over agent/audio/session/a11y paths to limit creds and input/snoop surfaces.
                for _xdg_deny in gnupg keyring pulse pipewire systemd \
                    at-spi speech-dispatcher dconf doc gvfs gvfsd; do
                    [ -d "$XDG_RUNTIME_DIR/$_xdg_deny" ] && bw --tmpfs "$XDG_RUNTIME_DIR/$_xdg_deny"
                done
                for _xdg_sock in bus pipewire-0; do
                    [ -e "$XDG_RUNTIME_DIR/$_xdg_sock" ] && bw --ro-bind /dev/null "$XDG_RUNTIME_DIR/$_xdg_sock"
                done
                [ -n "${WAYLAND_DISPLAY:-}" ] && bw --setenv WAYLAND_DISPLAY "$WAYLAND_DISPLAY"
                log "rw: $XDG_RUNTIME_DIR (credentials/audio/session/a11y masked)"
            fi

            if [ -n "${SSH_AUTH_SOCK:-}" ] && [ -S "$SSH_AUTH_SOCK" ]; then
                SSH_SOCK_REAL="$(readlink -f "$SSH_AUTH_SOCK")"
                # Mount the agent socket to a fixed path inside /tmp (already
                # a writable tmpfs in the sandbox). This avoids conflicts with
                # XDG_RUNTIME_DIR subdirs masked by tmpfs (e.g. keyring/).
                _MAGEN_SSH_SOCK="/tmp/magen/sandbox/ssh-agent.sock"
                bw --ro-bind "$SSH_SOCK_REAL" "$_MAGEN_SSH_SOCK"
                bw --setenv SSH_AUTH_SOCK "$_MAGEN_SSH_SOCK"
                log "ssh-agent socket: $SSH_SOCK_REAL → $_MAGEN_SSH_SOCK"
            fi
        else
            log "lockdown: D-Bus, display, SSH agent disabled"
        fi
    }

    # Mount allowed dotdirs (RW or RO) and RC files into ephemeral $HOME.
    _bwrap_dotdirs() {
        if $LOCKDOWN; then
            log "lockdown: no dotfiles mounted"
            return
        fi

        for entry in "$HOME"/.*; do
            [ -d "$entry" ] || continue
            name="${entry##*/}"
            [[ "$name" == "." || "$name" == ".." ]] && continue
            if is_rw "$name"; then
                log "rw dotdir: $name"
                bw --bind "$entry" "$HOME/$name"
            elif is_allowed_ro "$name"; then
                log "ro dotdir: $name"
                bw --ro-bind "$entry" "$HOME/$name"
            else
                log "deny dotdir: $name (not in allowlist)"
            fi
        done

        for _rc in .profile .bash_logout .bash_aliases .zshrc .gitconfig; do
            [ -f "$HOME/$_rc" ] && bw --ro-bind "$HOME/$_rc" "$HOME/$_rc"
        done
    }

    # Strip secrets from mounted dotdirs: npmrc, docker, azure, maven, cargo, ssh, config/cache deny.
    _bwrap_credential_sanitization() {
        if $LOCKDOWN; then return; fi

        # .npmrc: strip auth tokens; if npm registry proxy is running,
        # inject registry URLs into the file AND set env vars.
        # Writing to .npmrc is essential because cursor-agent does not
        # propagate env vars to MCP child processes — any npx-based MCP
        # would get E401 without the registry override in the file.
        if [ -f "$HOME/.npmrc" ]; then
            TEMP_NPMRC=$(mktemp /tmp/npmrc-clean.XXXXXX)
            grep -v -E '_(authToken|auth|password)\s*=' "$HOME/.npmrc" >"$TEMP_NPMRC" 2>/dev/null || true
            if [ -n "$NPM_PROXY_PID" ] && [ -s "$NPM_PROXY_ENV_FILE" ]; then
                while IFS=$'\t' read -r _key _val; do
                    [ -n "$_key" ] && bw --setenv "$_key" "$_val"
                    # npm_config_registry → registry=…
                    # npm_config_@scope:registry → @scope:registry=…
                    local _npmrc_key="${_key#npm_config_}"
                    printf '%s=%s\n' "$_npmrc_key" "$_val" >>"$TEMP_NPMRC"
                done <"$NPM_PROXY_ENV_FILE"
                log "ro: ~/.npmrc (auth via npm registry proxy on port $(cat "$NPM_PROXY_PORT_FILE"))"
            else
                log "ro: ~/.npmrc (sanitized — auth tokens stripped)"
            fi
            bw --ro-bind "$TEMP_NPMRC" "$HOME/.npmrc"
        fi

        # .docker/config.json: strip registry auth tokens, keep settings.
        if [ -f "$HOME/.docker/config.json" ] && command -v python3 &>/dev/null; then
            TEMP_DOCKER_CONFIG=$(mktemp /tmp/docker-config-clean.XXXXXX)
            _sanitize_docker_config "$HOME/.docker/config.json" "$TEMP_DOCKER_CONFIG"
            bw --ro-bind "$TEMP_DOCKER_CONFIG" "$HOME/.docker/config.json"
            log "ro: ~/.docker/config.json (sanitized — auth tokens stripped)"
        fi

        for _dtls in ca.pem cert.pem key.pem; do
            [ -f "$HOME/.docker/$_dtls" ] && {
                bw --ro-bind /dev/null "$HOME/.docker/$_dtls"
                log "deny: ~/.docker/$_dtls (TLS credential)"
            }
        done

        # .docker sockets: redirect through proxy or mask to prevent bypass.
        for _dsock in "$HOME/.docker/run/docker.sock" \
            "$HOME/.docker/desktop/docker.sock" \
            "$HOME/.docker/docker.sock"; do
            [ -S "$_dsock" ] || continue
            if [ -n "$DOCKER_PROXY_SOCK" ] && [ -S "$DOCKER_PROXY_SOCK" ]; then
                bw --bind "$DOCKER_PROXY_SOCK" "$_dsock"
                log "docker: proxy redirect → $_dsock"
            else
                bw --ro-bind /dev/null "$_dsock"
                log "docker: masked $_dsock (no proxy)"
            fi
        done

        # .azure: strip credential/token cache files, keep config and profile.
        if [ -d "$HOME/.azure" ]; then
            _AZ_EMPTY=$(mktemp /tmp/az-empty.XXXXXX)
            echo '{}' >"$_AZ_EMPTY"
            for _az_file in accessTokens.json msal_token_cache.json msal_http_cache.bin service_principal_entries.json; do
                if [ -f "$HOME/.azure/$_az_file" ]; then
                    bw --ro-bind "$_AZ_EMPTY" "$HOME/.azure/$_az_file"
                    log "ro: ~/.azure/$_az_file (sanitized — credentials stripped)"
                fi
            done
        fi

        # .m2: Maven settings can contain repository passwords and signing keys.
        for _m2_file in settings.xml settings-security.xml; do
            if [ -f "$HOME/.m2/$_m2_file" ]; then
                bw --ro-bind /dev/null "$HOME/.m2/$_m2_file"
                log "deny: ~/.m2/$_m2_file (may contain credentials)"
            fi
        done

        # .cargo: registry tokens in credentials.toml.
        [ -f "$HOME/.cargo/credentials.toml" ] && {
            bw --ro-bind /dev/null "$HOME/.cargo/credentials.toml"
            log "deny: ~/.cargo/credentials.toml"
        }
        [ -f "$HOME/.cargo/credentials" ] && {
            bw --ro-bind /dev/null "$HOME/.cargo/credentials"
            log "deny: ~/.cargo/credentials"
        }

        # ~/.ssh is denied but config/known_hosts are safe and needed for git.
        if [ -f "$HOME/.ssh/config" ] || [ -f "$HOME/.ssh/known_hosts" ]; then
            bw --dir "$HOME/.ssh"
            [ -f "$HOME/.ssh/config" ] && {
                bw --ro-bind "$HOME/.ssh/config" "$HOME/.ssh/config"
                log "ro: ~/.ssh/config"
            }
            [ -f "$HOME/.ssh/known_hosts" ] && {
                bw --ro-bind "$HOME/.ssh/known_hosts" "$HOME/.ssh/known_hosts"
                log "ro: ~/.ssh/known_hosts"
            }
        fi

        for denied in "${CONFIG_DENY[@]}"; do
            [ -d "$HOME/.config/$denied" ] && bw --tmpfs "$HOME/.config/$denied"
        done
        for denied in "${CACHE_DENY[@]}"; do
            [ -d "$HOME/.cache/$denied" ] && bw --tmpfs "$HOME/.cache/$denied"
        done

        [ -d "$HOME/.local/share/keyrings" ] && {
            bw --tmpfs "$HOME/.local/share/keyrings"
            log "deny: ~/.local/share/keyrings (GNOME keyring)"
        }

        mkdir -p "$HOME/.local/state"
        bw --bind "$HOME/.local/state" "$HOME/.local/state"
        for rw_share in yarn nvm node npm; do
            [ -d "$HOME/.local/share/$rw_share" ] && bw --bind "$HOME/.local/share/$rw_share" "$HOME/.local/share/$rw_share"
        done

        if [ -d "${NVM_DIR:-$HOME/.nvm}" ]; then
            NVM_REAL="${NVM_DIR:-$HOME/.nvm}"
            bw --ro-bind "$NVM_REAL" "$NVM_REAL" --setenv NVM_DIR "$NVM_REAL"
        fi
    }

    # Walk from project dir to root, bind-mounting each ancestor. Parent dir
    # gets RW only if it is not sensitive ($HOME or ancestor of $HOME).
    _bwrap_ancestors() {
        if $LOCKDOWN; then return; fi

        _parent_is_sensitive=false
        if [[ "$PARENT_DIR" == "/" ]] ||
            [[ "$PARENT_DIR" == "$HOME" ]] ||
            [[ "$HOME" == "$PARENT_DIR/"* ]]; then
            _parent_is_sensitive=true
            log "parent: $PARENT_DIR is sensitive (is or contains \$HOME), mounting RO"
        fi

        _ancestors=()
        _dir="$PROJECT_DIR"
        while true; do
            _parent="${_dir%/*}"
            [[ -z "$_parent" ]] && break
            _dir="$_parent"
            [[ "$_dir" == "/" ]] && break
            [ -d "$_dir" ] && _ancestors+=("$_dir")
        done
        for ((_i = ${#_ancestors[@]} - 1; _i >= 0; _i--)); do
            _a="${_ancestors[$_i]}"
            if [[ "$_a" == "$HOME" ]] || [[ "$HOME" == "$_a/"* ]]; then
                log "skip ancestor: $_a (\$HOME tmpfs preserved)"
                continue
            fi
            if [[ "$_a" == "$PARENT_DIR" ]] && ! $_parent_is_sensitive; then
                log "rw ancestor (parent): $_a"
                bw --bind "$_a" "$_a"
            else
                log "ro ancestor: $_a"
                bw --ro-bind "$_a" "$_a"
            fi
        done
    }

    # Ephemeral $HOME with selective dotdirs, credential sanitization, ancestors, project mount.
    _bwrap_home_and_project() {
        bw --tmpfs "$HOME"

        _bwrap_dotdirs
        _bwrap_credential_sanitization

        # Logger wrapper becomes ~/.bashrc; real file is sourced as .bashrc.orig when present.
        if ! $LOCKDOWN && [ -f "$HOME/.bashrc" ]; then
            bw --ro-bind "$HOME/.bashrc" "$HOME/.bashrc.orig"
        fi
        bw --ro-bind "$TEMP_BASHRC_WRAPPER" "$HOME/.bashrc"

        if $LOCKDOWN; then
            _log_dir="$HOME/.local/state/magen/sandbox/logs"
            mkdir -p "$_log_dir"
            bw --dir "$HOME/.local" --dir "$HOME/.local/state" --dir "$_log_dir" \
                --bind "$_log_dir" "$_log_dir"
        fi

        for p in "${EXTRA_RO_MAPS[@]+"${EXTRA_RO_MAPS[@]}"}"; do
            log "ro-map: $p"
            bw --ro-bind "$p" "$p"
        done
        for p in "${EXTRA_RW_MAPS[@]+"${EXTRA_RW_MAPS[@]}"}"; do
            log "rw-map: $p"
            bw --bind "$p" "$p"
        done

        _bwrap_ancestors

        if [[ -n "$GIT_WORKTREE_MAIN_GIT" ]] && [ -d "$GIT_WORKTREE_MAIN_GIT" ]; then
            bw --bind "$GIT_WORKTREE_MAIN_GIT" "$GIT_WORKTREE_MAIN_GIT"
            log "rw worktree main .git: $GIT_WORKTREE_MAIN_GIT"
        fi

        if $LOCKDOWN; then
            bw --ro-bind "$PROJECT_DIR" "$PROJECT_DIR"
            log "lockdown: project mounted read-only"
        else
            bw --bind "$PROJECT_DIR" "$PROJECT_DIR"
            # Mask sensitive file patterns in RW directories (parity with macOS SBPL
            # regex rules). Must come AFTER bind mounts so the masks override them.
            mask_sensitive_files "$PROJECT_DIR"
            if ! $_parent_is_sensitive && [[ "$PARENT_DIR" != "/" ]]; then
                mask_sensitive_files "$PARENT_DIR"
            fi
            for _rw_map in "${EXTRA_RW_MAPS[@]+"${EXTRA_RW_MAPS[@]}"}"; do
                mask_sensitive_files "$_rw_map"
            done
            if [[ -n "$GIT_WORKTREE_MAIN_GIT" ]]; then
                mask_sensitive_files "$GIT_WORKTREE_MAIN_GIT"
            fi
        fi

        # Project .npmrc: strip auth tokens and inject proxy registry.
        # Must come AFTER the project directory bind so the file mount
        # overlays the directory mount (bwrap applies mounts in order).
        if [ -f "$PROJECT_DIR/.npmrc" ]; then
            TEMP_PROJ_NPMRC=$(mktemp /tmp/npmrc-proj-clean.XXXXXX)
            local _proj_strip='_(authToken|auth|password)|always-auth'
            [ -n "$NPM_PROXY_PID" ] && _proj_strip+='|^registry='
            grep -v -E "$_proj_strip" "$PROJECT_DIR/.npmrc" >"$TEMP_PROJ_NPMRC" 2>/dev/null || true
            if [ -n "$NPM_PROXY_PID" ] && [ -s "$NPM_PROXY_ENV_FILE" ]; then
                while IFS=$'\t' read -r _key _val; do
                    [ -n "$_key" ] || continue
                    local _npmrc_key="${_key#npm_config_}"
                    printf '%s=%s\n' "$_npmrc_key" "$_val" >>"$TEMP_PROJ_NPMRC"
                done <"$NPM_PROXY_ENV_FILE"
            fi
            bw --ro-bind "$TEMP_PROJ_NPMRC" "$PROJECT_DIR/.npmrc"
            log "ro: project .npmrc (sanitized + proxy registry)"
        fi
    }

    # Final bwrap flags: namespaces, session log FIFO, Landlock exec wrapper, cgroup limits, run.
    _bwrap_execute() {
        bw --chdir "$PROJECT_DIR" --unshare-uts --unshare-pid --unshare-ipc
        $_is_gui || bw --die-with-parent
        if $LOCKDOWN; then
            bw --unshare-net
            log "lockdown: network disabled (--unshare-net)"
        fi

        if [ -n "$LANDLOCK_INSIDE" ]; then
            bw --ro-bind "${SCRIPT_REAL_DIR}/lib/landlock.py" "$LANDLOCK_INSIDE"
            bw --ro-bind "${SCRIPT_REAL_DIR}/lib/log.py" /tmp/magen/sandbox/log.py
            LANDLOCK_RW=("$HOME" "/tmp" "/run" "/dev")
            if ! $LOCKDOWN; then
                LANDLOCK_RW+=("$PROJECT_DIR")
                [[ "$PARENT_DIR" != "/" ]] && LANDLOCK_RW+=("$PARENT_DIR")
                for p in "${EXTRA_RW_MAPS[@]+"${EXTRA_RW_MAPS[@]}"}"; do
                    LANDLOCK_RW+=("$p")
                done
                [[ -n "$GIT_WORKTREE_MAIN_GIT" ]] && LANDLOCK_RW+=("$GIT_WORKTREE_MAIN_GIT")
            fi
            LANDLOCK_CMD=("python3" "$LANDLOCK_INSIDE")
            $VERBOSE && LANDLOCK_CMD+=("--verbose")
            for rw in "${LANDLOCK_RW[@]}"; do
                LANDLOCK_CMD+=("--rw" "$rw")
            done
            LANDLOCK_CMD+=("--")
            COMMAND_ARGS=("${LANDLOCK_CMD[@]}" "${COMMAND_ARGS[@]}")
            log "landlock: enabled"
        fi

        # Runtime paths under /tmp/magen/sandbox (session log, cmd logger, landlock).
        bw --dir /tmp/magen/sandbox

        if [ -n "$SESSION_LOG_FIFO" ]; then
            bw --bind "$SESSION_LOG_FIFO" /tmp/magen/sandbox/session-log
            bw --setenv MAGEN_SESSION_LOG /tmp/magen/sandbox/session-log
            bw --ro-bind "$_session_log_dir" "$_session_log_dir"
        else
            bw --setenv MAGEN_SESSION_LOG "$MAGEN_LOG_FILE"
        fi
        bw --ro-bind "$TEMP_CMD_LOGGER" /tmp/magen/sandbox/cmd-logger.sh \
            --setenv BASH_ENV /tmp/magen/sandbox/cmd-logger.sh

        bw --setenv TERM "$_sandbox_term"
        # .NET single-file apps (e.g. Azure MCP) need a writable dir to extract
        # embedded binaries. Default locations may be read-only inside bwrap.
        bw --setenv DOTNET_BUNDLE_EXTRACT_BASE_DIR /tmp/.dotnet-bundle-extract

        _REAL_HOSTNAME="$(hostname -s)"
        MODE="normal"
        $LOCKDOWN && MODE="lockdown"
        # shellcheck disable=SC2016
        bw --hostname magen --setenv MAGEN_ACTIVE 1 \
            --setenv MAGEN_HOSTNAME "$_REAL_HOSTNAME" \
            --setenv MAGEN_MODE "$MODE" \
            "${COMMAND_ARGS[@]}"

        if ! $DRY_RUN; then
            local _ll_status="  Landlock: not available"
            [ -n "$LANDLOCK_INSIDE" ] && _ll_status="  Landlock: enabled"
            _write_session_header "$_ll_status"
        fi

        # Resource limits via transient cgroup (fork bomb / OOM protection).
        _cgroup_prefix=()
        _max_pids="${MAGEN_MAX_PIDS:-4096}"
        _max_mem="${MAGEN_MAX_MEM:-8G}"
        if [ "${MAGEN_NO_CGROUP:-}" != "1" ] && command -v systemd-run &>/dev/null &&
            systemd-run --user --scope --quiet -- true 2>/dev/null; then
            _cgroup_prefix=(systemd-run --user --scope --quiet
                -p "TasksMax=$_max_pids" -p "MemoryMax=$_max_mem" --)
            log "cgroup: TasksMax=$_max_pids, MemoryMax=$_max_mem"
        else
            log "cgroup: systemd-run not available, no resource limits"
        fi

        if $DRY_RUN; then
            echo "Dry-run (bwrap/$MODE): $PROJECT_DIR"
            echo ""
            if [ ${#_cgroup_prefix[@]} -gt 0 ]; then
                echo "systemd-run --user --scope --quiet \\"
                echo "    -p TasksMax=$_max_pids -p MemoryMax=$_max_mem -- \\"
            fi
            echo "bwrap \\"
            local i=0
            while [ "$i" -lt ${#BWRAP_ARGS[@]} ]; do
                arg="${BWRAP_ARGS[$i]}"
                if [[ "$arg" == --* ]]; then
                    case "$arg" in
                        --ro-bind | --bind | --dev-bind | --setenv)
                            echo "    $arg ${BWRAP_ARGS[$((i + 1))]} ${BWRAP_ARGS[$((i + 2))]} \\"
                            i=$((i + 3))
                            continue
                            ;;
                        --tmpfs | --proc | --dev | --chdir | --hostname | --dir)
                            echo "    $arg ${BWRAP_ARGS[$((i + 1))]} \\"
                            i=$((i + 2))
                            continue
                            ;;
                        *)
                            echo "    $arg \\"
                            ;;
                    esac
                else
                    echo "    $arg \\"
                fi
                i=$((i + 1))
            done
            echo ""
            return
        fi

        _show_banner
        if $_is_gui; then
            trap '' EXIT
            ${_cgroup_prefix[@]+"${_cgroup_prefix[@]}"} bwrap "${BWRAP_ARGS[@]}" </dev/null >>"$MAGEN_LOG_FILE" 2>&1 &
            _bwrap_pid=$!
            disown
            echo "Logs: $MAGEN_LOG_FILE"
            # Deferred cleanup: proxies and temp files must outlive the script
            # since bwrap runs in the background. Wait for namespace setup (3s),
            # remove temp files, then wait for bwrap to exit before killing proxies.
            (
                sleep 3
                rm -rf "$TEMP_HOSTS" "$TEMP_RESOLV" "${TEMP_NPMRC:-}" "${TEMP_PROJ_NPMRC:-}" "${CHROMIUM_WRAPPER_DIR:-}"
                while kill -0 "$_bwrap_pid" 2>/dev/null; do sleep 5; done
                cleanup_npm_proxy
                cleanup_docker_proxy
                cleanup_azure_proxy
                cleanup_ssh_agent
                cleanup_log_reader
            ) &
            disown
        else
            ${_cgroup_prefix[@]+"${_cgroup_prefix[@]}"} bwrap "${BWRAP_ARGS[@]}"
        fi
    }

    _bwrap_system_mounts
    _bwrap_env_and_session
    _bwrap_runtime_and_network
    _bwrap_home_and_project
    _bwrap_execute
}

