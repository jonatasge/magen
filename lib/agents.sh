#!/bin/bash
#
# agents.sh — config-driven AI agent / provider recipes for magen
#
# Loads config/agents.conf (+ optional ~/.config/magen/agents.conf) and, based
# on COMMAND_ARGS, extends dotdir allowlists, env pass-through, macOS
# Application Support allowlists, SET_ENV, and keychain→file exports.
#
# Sourced by: magen (after lib/config.sh). Not executed directly.
# Compatible with macOS Bash 3.2 (no namerefs / no associative arrays).
#

# shellcheck disable=SC2034

_AGENTS_PASS_ENV=()
_AGENTS_SET_ENV=()
_AGENTS_KEYCHAIN_RULES=() # service|account|relpath|json_field
_AGENTS_MATCHED=()

_agents_conf_paths() {
    printf '%s\n' "$SCRIPT_REAL_DIR/config/agents.conf"
    [ -f "${HOME}/.config/magen/agents.conf" ] && printf '%s\n' "${HOME}/.config/magen/agents.conf"
}

# True when argv looks like an interactive shell (not bash -c / script).
_agents_is_interactive_shell() {
    local cmd="${1##*/}"
    case "$cmd" in
        bash | zsh | sh | fish | dash) ;;
        *) return 1 ;;
    esac
    local i=1 arg
    while [ "$i" -lt "${#COMMAND_ARGS[@]}" ]; do
        arg="${COMMAND_ARGS[$i]}"
        case "$arg" in
            -c | --command) return 1 ;;
            -s) return 1 ;;
            -o | -O)
                i=$((i + 2))
                continue
                ;;
            +m | -m | -i | -l | -login | --login | -n) ;;
            -*) ;;
            *) return 1 ;;
        esac
        i=$((i + 1))
    done
    return 0
}

_agents_list_has() {
    local needle="$1"
    shift
    local x
    for x in "$@"; do
        if [[ "$x" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

# Append items to a global array by name (Bash 3.2-safe; no namerefs).
_agents_append_unique() {
    local _name="$1"
    shift
    local item _exists _i _len
    for item in "$@"; do
        [ -n "$item" ] || continue
        _exists=0
        eval "_len=\${#${_name}[@]}"
        _i=0
        while [ "$_i" -lt "$_len" ]; do
            # Use if (not &&) so set -e does not abort on non-match.
            if eval "[[ \"\${${_name}[$_i]}\" == \"\$item\" ]]"; then
                _exists=1
                break
            fi
            _i=$((_i + 1))
        done
        [ "$_exists" -eq 1 ] && continue
        eval "${_name}+=(\"\$item\")"
    done
}

# Parse conf files and activate recipes for the current command.
agents_resolve() {
    local cmd="${1##*/}"
    cmd="${cmd:-bash}"

    _AGENTS_PASS_ENV=()
    _AGENTS_SET_ENV=()
    _AGENTS_KEYCHAIN_RULES=()
    _AGENTS_MATCHED=()

    if $LOCKDOWN; then
        log "agents: skipped (lockdown)"
        return 0
    fi

    local _want_all=false
    _agents_is_interactive_shell "$cmd" && _want_all=true

    local _in=false
    local _id=""
    local _cmds=() _home_rw=() _home_ro=() _pass=() _app=() _setenv=() _kc=()
    local _activate=false
    local conf line key rest c r

    _agents_flush() {
        $_in || return 0
        _activate=false
        if $_want_all; then
            _activate=true
        else
            for c in ${_cmds[@]+"${_cmds[@]}"}; do
                if [[ "$c" == "$cmd" ]]; then
                    _activate=true
                    break
                fi
            done
        fi
        if $_activate; then
            _AGENTS_MATCHED+=("$_id")
            _agents_append_unique _DOTDIR_RW_LIST ${_home_rw[@]+"${_home_rw[@]}"}
            _agents_append_unique _DOTDIR_RO_LIST ${_home_ro[@]+"${_home_ro[@]}"}
            _agents_append_unique _AGENTS_PASS_ENV ${_pass[@]+"${_pass[@]}"}
            _agents_append_unique LIBRARY_APP_SUPPORT_ALLOW ${_app[@]+"${_app[@]}"}
            _agents_append_unique _AGENTS_SET_ENV ${_setenv[@]+"${_setenv[@]}"}
            for r in ${_kc[@]+"${_kc[@]}"}; do
                _AGENTS_KEYCHAIN_RULES+=("$r")
            done
        fi
        _in=false
        _id=""
        _cmds=()
        _home_rw=()
        _home_ro=()
        _pass=()
        _app=()
        _setenv=()
        _kc=()
    }

    while IFS= read -r conf; do
        [ -f "$conf" ] || continue
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line%%#*}"
            # trim
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            if [ -z "$line" ]; then
                _agents_flush
                continue
            fi
            key="${line%% *}"
            rest="${line#"$key"}"
            rest="${rest#"${rest%%[![:space:]]*}"}"
            case "$key" in
                GLOBAL_PASS_ENV)
                    # shellcheck disable=SC2206
                    _agents_append_unique _AGENTS_PASS_ENV $rest
                    ;;
                AGENT)
                    _agents_flush
                    _in=true
                    _id="$rest"
                    ;;
                CMD)
                    $_in || continue
                    # shellcheck disable=SC2206
                    _cmds+=($rest)
                    ;;
                HOME_RW)
                    $_in || continue
                    # shellcheck disable=SC2206
                    _home_rw+=($rest)
                    ;;
                HOME_RO)
                    $_in || continue
                    # shellcheck disable=SC2206
                    _home_ro+=($rest)
                    ;;
                CONFIG_RW) ;;
                PASS_ENV)
                    $_in || continue
                    # shellcheck disable=SC2206
                    _pass+=($rest)
                    ;;
                APP_SUPPORT)
                    $_in || continue
                    # shellcheck disable=SC2206
                    _app+=($rest)
                    ;;
                SET_ENV)
                    $_in || continue
                    # shellcheck disable=SC2206
                    _setenv+=($rest)
                    ;;
                KEYCHAIN)
                    $_in || continue
                    _kc+=("$rest")
                    ;;
            esac
        done <"$conf"
        _agents_flush
    done < <(_agents_conf_paths)

    _agents_append_unique _ENV_SAFE_KEEP_LIST ${_AGENTS_PASS_ENV[@]+"${_AGENTS_PASS_ENV[@]}"}

    if [ ${#_AGENTS_MATCHED[@]} -gt 0 ]; then
        log "agents: matched ${_AGENTS_MATCHED[*]}"
    else
        log "agents: no recipe for '$cmd' (global pass_env still applied)"
    fi
}

# macOS: export configured keychain items into JSON files under $HOME.
agents_materialize_keychain() {
    if ${ALLOW_KEYCHAIN:-false}; then
        log "agents: keychain materialize skipped (--allow-keychain)"
        return 0
    fi
    command -v security >/dev/null 2>&1 || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    [ ${#_AGENTS_KEYCHAIN_RULES[@]} -eq 0 ] && return 0

    local rule service account relpath field secret dest _kc_tmp mapf pathf _hash
    _kc_tmp="$(mktemp -d /tmp/magen/sandbox/kc-mat.XXXXXX)" || return 0

    for rule in "${_AGENTS_KEYCHAIN_RULES[@]}"; do
        IFS='|' read -r service account relpath field <<<"$rule"
        [ -n "$service" ] && [ -n "$account" ] && [ -n "$relpath" ] && [ -n "$field" ] || continue
        secret="$(security find-generic-password -s "$service" -a "$account" -w 2>/dev/null)" || secret=""
        if [ -z "$secret" ]; then
            log "agents: keychain miss $service/$account"
            continue
        fi
        dest="$HOME/$relpath"
        mkdir -p "$(dirname "$dest")" 2>/dev/null || continue
        _hash="$(printf '%s' "$dest" | shasum -a 256 2>/dev/null | awk '{print $1}')"
        [ -n "$_hash" ] || continue
        printf '%s\t%s\n' "$field" "$secret" >>"$_kc_tmp/${_hash}.map"
        printf '%s\n' "$dest" >"$_kc_tmp/${_hash}.path"
        log "agents: keychain $service → ~/$relpath ($field)"
    done

    for mapf in "$_kc_tmp"/*.map; do
        [ -f "$mapf" ] || continue
        pathf="${mapf%.map}.path"
        dest="$(cat "$pathf")"
        MAGEN_KC_DEST="$dest" MAGEN_KC_MAP="$mapf" python3 - <<'PY'
import json, os
dest = os.environ["MAGEN_KC_DEST"]
path = os.environ["MAGEN_KC_MAP"]
data = {}
try:
    with open(dest, encoding="utf-8") as f:
        data = json.load(f) or {}
except Exception:
    data = {}
with open(path, encoding="utf-8") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line or "\t" not in line:
            continue
        field, secret = line.split("\t", 1)
        data[field] = secret
with open(dest, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
os.chmod(dest, 0o600)
PY
    done
    rm -rf "$_kc_tmp"
}
