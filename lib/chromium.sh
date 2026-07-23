#!/bin/bash
#
# chromium.sh — Chromium/Electron binary resolution for magen
#
# Locates real Chrome/Electron binaries (bypassing snap wrappers), detects
# Chromium-based apps via crashpad handlers, and can create temporary
# PATH shims that inject --no-sandbox (required inside bwrap PID namespaces).
#
# Sourced by: magen (not executed directly)
#

# Resolve the real binary behind snap-confine (returns path or fails).
resolve_snap_binary() {
    local cmd="$1" cmd_real snap_base snap_bin
    command -v "$cmd" &>/dev/null || return 1
    cmd_real="$(readlink -f "$(command -v "$cmd")" 2>/dev/null || true)"
    [[ "$cmd_real" == */usr/bin/snap ]] || return 1
    snap_base="/snap/${cmd}/current"
    [ -d "$snap_base" ] || return 1
    for snap_bin in \
        "$snap_base/usr/share/${cmd}/${cmd}" \
        "$snap_base/usr/share/${cmd}/bin/${cmd}" \
        "$snap_base/bin/${cmd}" \
        "$snap_base/${cmd}"; do
        [ -x "$snap_bin" ] && echo "$snap_bin" && return 0
    done
    return 1
}

# Resolve first non-snap, non-wrapper $app on PATH.
find_chromium_binary() {
    local app="$1" dir snap_bin
    snap_bin="$(resolve_snap_binary "$app")" && {
        echo "$snap_bin"
        return 0
    }
    while IFS= read -d: -r dir || [ -n "$dir" ]; do
        [ -x "$dir/$app" ] || continue
        [[ "$dir" == "$HOME/.local/bin" ]] && continue
        [[ "$dir" == /tmp/magen/sandbox/chromium-wrappers* ]] && continue
        echo "$dir/$app"
        return 0
    done <<<"$PATH"
    return 1
}

# True if $cmd resolves to a Chrome/Electron-family binary (crashpad handler nearby).
is_chromium_based() {
    local cmd="${1##*/}" bin_path bin_dir
    bin_path="$(find_chromium_binary "$cmd")" || return 1
    bin_path="$(readlink -f "$bin_path" 2>/dev/null || echo "$bin_path")"
    bin_dir="$(dirname "$bin_path")"
    compgen -G "$bin_dir/*_crashpad_handler" &>/dev/null && return 0
    compgen -G "${bin_dir%/*}/*_crashpad_handler" &>/dev/null && return 0
    return 1
}

# macOS: walk symlinks (no readlink -f) to the real binary under Foo.app/Contents/MacOS/.
resolve_macos_electron() {
    local cmd="${1##*/}" bin_path
    bin_path="$(find_chromium_binary "$cmd")" || return 1

    local dir link
    while [ -L "$bin_path" ]; do
        dir="$(dirname "$bin_path")"
        link="$(readlink "$bin_path")"
        [[ "$link" != /* ]] && link="$dir/$link"
        bin_path="$link"
    done

    case "$bin_path" in
        *.app/Contents/*)
            local app_path="${bin_path%%/Contents/*}"
            local app_name
            app_name="$(basename "$app_path" .app)"
            local electron="$app_path/Contents/MacOS/$app_name"
            [ -x "$electron" ] && {
                echo "$electron"
                return 0
            }
            ;;
    esac
    return 1
}

# --- Temporary PATH shims that force --no-sandbox ---
# Scans for *_crashpad_handler markers and creates wrappers for each
# Chromium-based binary found (bypasses snap-confine). Returns the
# wrapper directory path (caller must bind-mount and prepend PATH).
create_chromium_wrappers() {
    local _wrapper_dir
    mkdir -p /tmp/magen/sandbox
    _wrapper_dir=$(mktemp -d /tmp/magen/sandbox/chromium-wrappers.XXXXXX)

    local search_dirs=()
    for d in /opt /usr/share /usr/lib; do
        [ -d "$d" ] && search_dirs+=("$d")
    done
    if [ -d /snap ]; then
        for d in /snap/*/current; do
            [ -d "$d" ] && search_dirs+=("$d")
        done
    fi
    [ ${#search_dirs[@]} -eq 0 ] && return 1

    while IFS= read -r handler_path; do
        local app_dir candidate name
        app_dir="$(dirname "$handler_path")"

        for candidate in "$app_dir"/*; do
            [ -x "$candidate" ] && [ -f "$candidate" ] || continue
            name="${candidate##*/}"
            case "$name" in
                *_crashpad_handler | *-sandbox | nacl_helper*) continue ;;
                *-management-service) continue ;;
                xdg-* | *.desktop | cron) continue ;;
                lib* | *.so | *.so.* | *.pak | *.bin | *.dat | *.json | *.html | *.png) continue ;;
            esac
            command -v "$name" &>/dev/null || continue
            [[ "$candidate" =~ ^[a-zA-Z0-9/._-]+$ ]] || continue
            # shellcheck disable=SC2016
            printf '#!/bin/sh\n"%s" --no-sandbox "$@" </dev/null >>"${MAGEN_SESSION_LOG:-/dev/null}" 2>&1 &\n' \
                "$candidate" >"$_wrapper_dir/$name"
            chmod +x "$_wrapper_dir/$name"
            log "chromium wrapper: $name → $candidate --no-sandbox"
        done
    done < <(find -L "${search_dirs[@]}" -maxdepth 4 -name '*_crashpad_handler' -type f 2>/dev/null)

    if compgen -G "$_wrapper_dir/*" &>/dev/null; then
        echo "$_wrapper_dir"
    else
        rmdir "$_wrapper_dir" 2>/dev/null
        return 1
    fi
}
