#!/bin/bash
#
# test.sh — end-to-end isolation test suite for magen
#
# Runs commands inside real sandboxes (and proxy stubs) and asserts that
# filesystem, environment, credential, and API protections hold.
#
# Usage:
#   ./tests/test.sh [OPTIONS]
#   magen --self-test [--verbose] [--normal-only] [--lockdown-only]
#

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$TESTS_DIR/.." && pwd)"
MAGEN="$ROOT_DIR/magen"
OS="$(uname -s)"
MAGEN_TIMEOUT=30

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
YELLOW=$'\033[1;33m'
DIM=$'\033[2m'
BOLD=$'\033[1m'
BG_PASS=$'\033[30;42m'
BG_FAIL=$'\033[97;41m'
NC=$'\033[0m'

PASS=0 FAIL=0 SKIP=0
FAILURES=()
SUITE_PASS=0 SUITE_FAIL=0
RUN_NORMAL=true
RUN_LOCKDOWN=true
VERBOSE=false

_SEC_T=0 _SEC_P=0 _SEC_F=0 _SEC_S=0
_SEC_NAME=""
_SEC_BUF=""
_IN_SUBGROUP=false

_sec_prefix() {
    $_IN_SUBGROUP && printf "    " || printf "  "
}

pass() {
    _SEC_BUF+="$(_sec_prefix)${GREEN}✓${NC} $1"$'\n'
    PASS=$((PASS + 1))
    _SEC_P=$((_SEC_P + 1))
}
fail() {
    _SEC_BUF+="$(_sec_prefix)${RED}✗${NC} $1"$'\n'
    FAIL=$((FAIL + 1))
    _SEC_F=$((_SEC_F + 1))
    FAILURES+=("$1")
}
skip() {
    _SEC_BUF+="$(_sec_prefix)${YELLOW}○${NC} ${DIM}skipped${NC} $1"$'\n'
    SKIP=$((SKIP + 1))
    _SEC_S=$((_SEC_S + 1))
}

subgroup() {
    _SEC_BUF+="  $1"$'\n'
    _IN_SUBGROUP=true
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        pass "$desc"
    else
        fail "$desc (expected '$expected', got '${actual:-<empty>}')"
    fi
}

assert_ok() {
    local desc="$1"
    shift
    if $VERBOSE; then
        if "$@" >/dev/null; then pass "$desc"; else fail "$desc"; fi
    else
        if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
    fi
}

_val() { echo "$2" | grep "^$1=" | head -1 | cut -d= -f2-; }

section() {
    _SEC_NAME="$1"
    _SEC_BUF=""
    _IN_SUBGROUP=false
    _SEC_T=$(now_ms) _SEC_P=0 _SEC_F=0 _SEC_S=0
}

section_end() {
    local _el=$(($(now_ms) - _SEC_T))
    local _time
    _time=$(LC_NUMERIC=C awk -v ms="$_el" 'BEGIN {printf "%.2f", ms/1000}')
    echo ""
    if [ $_SEC_F -eq 0 ]; then
        printf " %s %s (%ss)\n" "${BG_PASS}${BOLD} PASS ${NC}" "${BOLD}${_SEC_NAME}${NC}" "$_time"
        SUITE_PASS=$((SUITE_PASS + 1))
    else
        printf " %s %s (%ss)\n" "${BG_FAIL}${BOLD} FAIL ${NC}" "${BOLD}${_SEC_NAME}${NC}" "$_time"
        SUITE_FAIL=$((SUITE_FAIL + 1))
    fi
    printf '%s' "$_SEC_BUF"
    _IN_SUBGROUP=false
}

# Assert HTTP status from curl via docker-proxy Unix socket ($_proxy_sock).
assert_docker() {
    local desc="$1" expected="$2" method="$3" path="$4" body="${5:-}"
    local _args=(-s -o /dev/null -w '%{http_code}' --unix-socket "$_proxy_sock" -X "$method")
    [ -n "$body" ] && _args+=(-H "Content-Type: application/json" -d "$body")
    local _code
    _code=$(curl "${_args[@]}" "http://localhost/v1.45/$path" 2>/dev/null)
    assert_eq "$desc" "$expected" "$_code"
}

# Minimal Docker API stub on a Unix socket; optional capture_file stores X-Registry-Auth.
start_fake_docker_daemon() {
    local _sock="$1" _capture="${2:-}"
    python3 - "$_sock" "$_capture" <<'PYEOF' &
import socket, os, sys
sock_path = sys.argv[1]
capture_path = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(8)
s.settimeout(30)
resp = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 15\r\n"
    b"Connection: close\r\n\r\n"
    b'{"Id":"test123"}'
)
try:
    while True:
        c, _ = s.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
        hdr = data.split(b"\r\n\r\n")[0].decode(errors="replace")
        cl = 0
        for line in hdr.split("\r\n"):
            if line.lower().startswith("content-length:"):
                cl = int(line.split(":")[1].strip())
        if cl > 0:
            body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
            rem = cl - len(body)
            while rem > 0:
                chunk = c.recv(min(rem, 4096))
                if not chunk:
                    break
                rem -= len(chunk)
        if capture_path:
            auth = ""
            for line in data.split(b"\r\n"):
                decoded = line.decode(errors="replace")
                if decoded.lower().startswith("x-registry-auth:"):
                    auth = decoded.split(":", 1)[1].strip()
            with open(capture_path, "w") as f:
                f.write(auth)
        c.sendall(resp)
        c.close()
except socket.timeout:
    pass
finally:
    s.close()
    try:
        os.unlink(sock_path)
    except OSError:
        pass
PYEOF
    _FAKE_DAEMON_PID=$!
}

# Category toggles (parallel workers). Defaults: all on.
CAT_SANDBOX=true
CAT_AGENTS=true
CAT_ISOLATION=true
CAT_PROXIES=true
CAT_LOCKDOWN=true

show_help() {
    cat <<EOF
Validates that the sandbox correctly isolates processes.

Usage: $(basename "$0") [OPTIONS]

Options:
    --normal-only           Run normal-mode categories (skip lockdown)
    --lockdown-only         Run only lockdown tests
    --category LIST         Comma-separated categories only:
                            sandbox, agents, isolation, proxies, lockdown
    --verbose, -v           Show command, stdout, stderr and exit code per test
    -h, --help              Show this help message

Categories run in parallel workers (each with its own TEMP dir).
EOF
}

_set_categories_from_list() {
    local list="$1" item
    CAT_SANDBOX=false
    CAT_AGENTS=false
    CAT_ISOLATION=false
    CAT_PROXIES=false
    CAT_LOCKDOWN=false
    IFS=',' read -r -a _cats <<<"$list"
    for item in "${_cats[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        case "$item" in
            sandbox) CAT_SANDBOX=true ;;
            agents) CAT_AGENTS=true ;;
            isolation) CAT_ISOLATION=true ;;
            proxies) CAT_PROXIES=true ;;
            lockdown) CAT_LOCKDOWN=true ;;
            *)
                echo "Error: unknown category '$item' (sandbox|agents|isolation|proxies|lockdown)" >&2
                exit 1
                ;;
        esac
    done
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --normal-only)
            CAT_LOCKDOWN=false
            shift
            ;;
        --lockdown-only)
            CAT_SANDBOX=false
            CAT_AGENTS=false
            CAT_ISOLATION=false
            CAT_PROXIES=false
            CAT_LOCKDOWN=true
            shift
            ;;
        --category)
            [ -n "${2:-}" ] || {
                echo "Error: --category requires a list" >&2
                exit 1
            }
            _set_categories_from_list "$2"
            shift 2
            ;;
        --verbose | -v)
            VERBOSE=true
            shift
            ;;
        --help | -h)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if ! $CAT_SANDBOX && ! $CAT_AGENTS && ! $CAT_ISOLATION && ! $CAT_PROXIES && ! $CAT_LOCKDOWN; then
    echo "Error: no test categories selected" >&2
    exit 1
fi

# Compatibility: magen --self-test still documents --normal-only / --lockdown-only.
# Category flags above are the source of truth.

# --- Pre-flight ---

if [[ "${MAGEN_ACTIVE:-}" == "1" ]]; then
    echo "Error: cannot run inside a sandbox (nesting is not supported)" >&2
    exit 1
fi

[ -x "$MAGEN" ] || {
    echo "Error: magen not found: $MAGEN" >&2
    exit 1
}

if [[ "$OS" == "Linux" ]]; then
    command -v bwrap &>/dev/null || {
        echo "Error: bubblewrap is required" >&2
        exit 1
    }
elif [[ "$OS" == "Darwin" ]]; then
    command -v sandbox-exec &>/dev/null || {
        echo "Error: sandbox-exec is required" >&2
        exit 1
    }
else
    echo "Error: unsupported OS '$OS'" >&2
    exit 1
fi

TIMEOUT_CMD=""
if command -v timeout &>/dev/null; then
    TIMEOUT_CMD="timeout"
elif command -v gtimeout &>/dev/null; then
    TIMEOUT_CMD="gtimeout"
fi

# Portable millisecond timestamp (macOS date doesn't support %N).
now_ms() {
    local _val
    _val="$(date +%s%3N 2>/dev/null)" || true
    if [[ "$_val" =~ ^[0-9]+$ ]]; then
        echo "$_val"
    elif command -v perl &>/dev/null; then
        perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000'
    elif command -v python3 &>/dev/null; then
        python3 -c 'import time; print(int(time.time()*1000))'
    else
        echo $(($(date +%s) * 1000))
    fi
}

# --- Setup ---

# Use /var/tmp so a project under /tmp does not hide the sandbox tmpfs (parent bind mount).
TEST_DIR=$(mktemp -d /var/tmp/magen-sandbox-test.XXXXXX)
STDERR_LOG="$TEST_DIR/stderr.log"
trap 'rm -rf "$TEST_DIR"' EXIT
echo "test-content" >"$TEST_DIR/test-file.txt"

# Run sandbox from TEST_DIR (or --from); strip banner; stderr → $TEST_DIR/stderr.log
# (or $MAGEN_RUN_STDERR). Path is fixed so callers after `out=$(magen_run …)` can grep it.
magen_run() {
    local _wd="$TEST_DIR"
    if [[ "${1:-}" == "--from" ]]; then
        _wd="$2"
        shift 2
    fi
    local _out _rc=0 _cmd=("$MAGEN" "$@") _stderr
    _stderr="${MAGEN_RUN_STDERR:-$TEST_DIR/stderr.log}"
    STDERR_LOG="$_stderr"
    [ -n "$TIMEOUT_CMD" ] && _cmd=("$TIMEOUT_CMD" "$MAGEN_TIMEOUT" "${_cmd[@]}")
    $VERBOSE && echo -e "    ${YELLOW}> sandbox $*${NC}" >&2
    _out=$( (cd "$_wd" && MAGEN_SKIP_VALIDATION=1 "${_cmd[@]}") 2>"$_stderr") || _rc=$?
    if [ -n "$_out" ]; then
        _out=$(printf '%s\n' "$_out" | grep -v '██' || true)
    fi
    if $VERBOSE; then
        if [ -n "$_out" ]; then
            echo -e "    ${YELLOW}stdout:${NC}" >&2
            echo "$_out" | head -5 | sed 's/^/      /' >&2
        fi
        if [ -s "$_stderr" ]; then
            echo -e "    ${YELLOW}stderr:${NC}" >&2
            head -5 "$_stderr" | sed 's/^/      /' >&2
        fi
        echo -e "    ${YELLOW}exit:${NC} $_rc" >&2
    fi
    if [ -n "$_out" ]; then
        printf '%s\n' "$_out"
    fi
    return "$_rc"
}

START_TIME=$(now_ms)

echo ""

# =============================================================================
# Normal Mode (shared batch + split suites)
# =============================================================================

NM_OUT=""
NM_BATCH_OK=false
_NM_BATCH_RAN=""
NM_TMP_LEAK="/tmp/magen/sandbox/leak-test"
declare -a NM_SENSITIVE_FILES=()

# Single expensive normal-mode run: populate NM_OUT for filesystem/env/sensitive tests.
# shellcheck disable=SC2016
_normal_mode_run_batch_once() {
    [[ -n "$_NM_BATCH_RAN" ]] && return 0
    _NM_BATCH_RAN=1
    NM_BATCH_OK=false

    local out

    if [[ "$OS" == "Linux" ]]; then
        NM_SENSITIVE_FILES=(
            test-secret.pem test-secret.key test_id_rsa_backup credentials.json
            .env.local .env.production test-secret.pfx service-account-key.json
            .env.staging test.p8 .env test.jks test.kdbx test.tfstate
            kubeconfig .netrc .env.development .env.test
        )
        for _f in "${NM_SENSITIVE_FILES[@]}"; do
            echo "test-key-data" >"$TEST_DIR/$_f"
        done
        rm -f "$NM_TMP_LEAK"

        cp "$ROOT_DIR/tests/batch_linux.sh" "$TEST_DIR/.test-batch.sh"
        out=$(AWS_SECRET_ACCESS_KEY=strip-test AZURE_CLIENT_SECRET=strip-test \
            magen_run bash .test-batch.sh) || true

    elif [[ "$OS" == "Darwin" ]]; then
        NM_SENSITIVE_FILES=()
        out=$(magen_run sh -c '
            printf "SA=%s\n" "$MAGEN_ACTIVE"
            printf "PR=%s\n" "$(cat test-file.txt 2>/dev/null)"
            printf "SYS=%s\n" "$([ -d /usr ] && [ -d /bin ] && command -v ls >/dev/null && echo ok)"
            printf "GIT=%s\n" "$(git --version >/dev/null 2>&1 && echo ok)"
            echo written > write-test.txt
            touch "$HOME/.ephemeral-marker" 2>/dev/null && printf "EPH=writable\n" || printf "EPH=denied\n"
            printf "GNUPG=%s\n" "$([ -d "$HOME/.gnupg" ] && echo visible || echo hidden)"
            printf "AWS=%s\n" "$([ -d "$HOME/.aws" ] && echo visible || echo hidden)"
            printf "MOZILLA=%s\n" "$([ -d "$HOME/.mozilla" ] && echo visible || echo hidden)"
            printf "SPARROW=%s\n" "$([ -d "$HOME/.sparrow" ] && echo visible || echo hidden)"
            printf "KUBE=%s\n" "$([ -d "$HOME/.kube" ] && echo visible || echo hidden)"
            printf "PASSWORD_STORE=%s\n" "$([ -d "$HOME/.password-store" ] && echo visible || echo hidden)"
            printf "VAULT_TOKEN=%s\n" "$([ -e "$HOME/.vault-token" ] && echo visible || echo hidden)"
            printf "TERRAFORM_D=%s\n" "$([ -d "$HOME/.terraform.d" ] && echo visible || echo hidden)"
            printf "GEMINI=%s\n" "$([ -d "$HOME/.gemini" ] && echo visible || echo hidden)"
            printf "CLAUDE=%s\n" "$([ -d "$HOME/.claude" ] && echo visible || echo hidden)"
            printf "PKI=%s\n" "$([ -d "$HOME/.pki" ] && echo visible || echo hidden)"
            printf "KEYRINGS=%s\n" "$(ls "$HOME/.local/share/keyrings/" 2>/dev/null | head -1)"
            printf "SSH_KEYS=%s\n" "$(ls "$HOME/.ssh/id_"* 2>/dev/null && echo found || echo none)"
            printf "SSH_CFG=%s\n" "$(cat "$HOME/.ssh/config" >/dev/null 2>&1 && echo ok || echo no)"
            printf "SSH_KH=%s\n" "$(cat "$HOME/.ssh/known_hosts" >/dev/null 2>&1 && echo ok || echo no)"
            printf "BRAVE=%s\n" "$(ls "$HOME/.config/BraveSoftware/" 2>/dev/null | head -1)"
            printf "CHROME=%s\n" "$(ls "$HOME/.config/google-chrome/" 2>/dev/null | head -1)"
            printf "CHROMIUM=%s\n" "$(ls "$HOME/.config/chromium/" 2>/dev/null | head -1)"
            printf "LIB_KEYCHAINS=%s\n" "$(ls "$HOME/Library/Keychains/" 2>/dev/null | head -1)"
            printf "LIB_MAIL=%s\n" "$(ls "$HOME/Library/Mail/" 2>/dev/null | head -1)"
            printf "LIB_MESSAGES=%s\n" "$(ls "$HOME/Library/Messages/" 2>/dev/null | head -1)"
            printf "LIB_PREFS=%s\n" "$(ls "$HOME/Library/Preferences/" 2>/dev/null | head -1)"
            printf "GITCFG=%s\n" "$(cat "$HOME/.gitconfig" >/dev/null 2>&1 && echo ok || echo no)"
            printf "DEVNULL=%s\n" "$(echo x > /dev/null 2>&1 && echo ok || echo no)"
            printf "REGEX_PEM=%s\n" "$(touch /tmp/test.pem 2>/dev/null && echo writable || echo blocked)"
            printf "REGEX_IDRSA=%s\n" "$(touch /tmp/id_rsa_test 2>/dev/null && echo writable || echo blocked)"
            printf "REGEX_JKS=%s\n" "$(touch /tmp/test.jks 2>/dev/null && echo writable || echo blocked)"
            printf "REGEX_KDBX=%s\n" "$(touch /tmp/test.kdbx 2>/dev/null && echo writable || echo blocked)"
            printf "REGEX_TFSTATE=%s\n" "$(touch /tmp/test.tfstate 2>/dev/null && echo writable || echo blocked)"
            printf "REGEX_SAFE=%s\n" "$(touch /tmp/safe-file.txt 2>/dev/null && echo writable || echo blocked)"
            printf "DNS=%s\n" "$(cat /etc/resolv.conf >/dev/null 2>&1 && echo ok || echo no)"
            printf "_OK=1\n"
        ') || true
    fi

    NM_OUT="$out"
    [[ "$(_val _OK "$NM_OUT")" == "1" ]] && NM_BATCH_OK=true
}

# When batch output is missing, fail with optional verbose hint.
_normal_mode_fail_batch_hint() {
    fail "Sandbox execution failed (no output received)"
    $VERBOSE || _SEC_BUF+="    ${DIM}Hint: run with --verbose to see sandbox stderr${NC}"$'\n'
}

# Normal mode: project read/write, system tools, git availability.
# shellcheck disable=SC2016
test_project_access() {
    section "Sandbox — Project access"
    _normal_mode_run_batch_once
    local out="$NM_OUT"

    if ! $NM_BATCH_OK; then
        _normal_mode_fail_batch_hint
        section_end
        return
    fi

    assert_eq "Can read project files" "test-content" "$(_val PR "$out")"
    assert_eq "System dirs and tools accessible" "ok" "$(_val SYS "$out")"
    command -v git &>/dev/null && assert_eq "Git is available" "ok" "$(_val GIT "$out")"

    if [ -f "$TEST_DIR/write-test.txt" ]; then
        pass "Can write to project directory"
        rm -f "$TEST_DIR/write-test.txt"
    else
        fail "Can write to project directory"
    fi

    section_end
}

# Normal mode: $HOME/tmp isolation, denied dotdirs, SSH/browser paths, XDG, Docker/Azure sanitization.
# shellcheck disable=SC2016
test_filesystem_isolation() {
    section "Sandbox — Filesystem isolation"
    _normal_mode_run_batch_once
    local out="$NM_OUT"

    if ! $NM_BATCH_OK; then
        skip "filesystem checks (normal mode batch unavailable)"
        section_end
        return
    fi

    if [[ "$OS" == "Linux" ]]; then
        if [ -f "$TEST_DIR/write-test.txt" ]; then
            rm -f "$TEST_DIR/write-test.txt"
        fi
        if [ ! -f "$HOME/.ephemeral-marker" ]; then
            pass "\$HOME is ephemeral (writes don't persist)"
        else
            fail "\$HOME is ephemeral (writes don't persist)"
            rm -f "$HOME/.ephemeral-marker"
        fi
        if [ ! -f "$NM_TMP_LEAK" ]; then
            pass "/tmp writes don't leak to host"
        else
            fail "/tmp writes don't leak to host"
            rm -f "$NM_TMP_LEAK"
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        assert_eq "\$HOME non-allowed writes are denied" "denied" "$(_val EPH "$out")"
        rm -f "$HOME/.ephemeral-marker" 2>/dev/null || true
    fi

    subgroup "Known sensitive dotdirs (deny)"
    local dir key
    for dir in .gnupg .aws .mozilla .sparrow .kube .password-store .vault-token .terraform.d; do
        key="${dir#.}"
        key=$(printf '%s' "$key" | tr '[:lower:].' '[:upper:]_' | tr -- '-' '_')
        if [ -e "$HOME/$dir" ]; then
            assert_eq "$dir is hidden" "hidden" "$(_val "$key" "$out")"
        else
            skip "$dir (not present on host)"
        fi
    done

    subgroup "Unknown dotdirs blocked by allowlist"
    for dir in .gemini .claude .pki; do
        key="${dir#.}"
        key=$(printf '%s' "$key" | tr '[:lower:].' '[:upper:]_' | tr -- '-' '_')
        if [ -e "$HOME/$dir" ]; then
            assert_eq "$dir is blocked (not in allowlist)" "hidden" "$(_val "$key" "$out")"
        else
            skip "$dir (not present on host)"
        fi
    done

    if [ -d "$HOME/.ssh" ]; then
        assert_eq "SSH private keys are hidden" "none" "$(_val SSH_KEYS "$out")"
        if [ -f "$HOME/.ssh/config" ]; then
            assert_eq ".ssh/config is readable" "ok" "$(_val SSH_CFG "$out")"
        else
            skip ".ssh/config (not present on host)"
        fi
        if [ -f "$HOME/.ssh/known_hosts" ]; then
            assert_eq ".ssh/known_hosts is readable" "ok" "$(_val SSH_KH "$out")"
        else
            skip ".ssh/known_hosts (not present on host)"
        fi
    else
        skip "SSH directory tests (not present on host)"
    fi

    local denied browser_key
    for denied in BraveSoftware google-chrome chromium; do
        case "$denied" in
            BraveSoftware) browser_key="BRAVE" ;;
            google-chrome) browser_key="CHROME" ;;
            chromium) browser_key="CHROMIUM" ;;
        esac
        if [ -d "$HOME/.config/$denied" ]; then
            assert_eq ".config/$denied is masked" "" "$(_val "$browser_key" "$out")"
        else
            skip ".config/$denied (not present on host)"
        fi
    done

    if [[ "$OS" == "Darwin" ]]; then
        local lib_denied lib_key
        for lib_denied in Mail Messages; do
            lib_key="LIB_$(printf '%s' "$lib_denied" | tr '[:lower:]' '[:upper:]')"
            if [ -d "$HOME/Library/$lib_denied" ]; then
                assert_eq "Library/$lib_denied is blocked" "" "$(_val "$lib_key" "$out")"
            else
                skip "Library/$lib_denied (not present on host)"
            fi
        done
        if [ -d "$HOME/Library/Keychains" ]; then
            assert_eq "Library/Keychains is blocked" "" "$(_val LIB_KEYCHAINS "$out")"
        else
            skip "Library/Keychains (not present on host)"
        fi
        if [ -d "$HOME/Library/Preferences" ]; then
            local _lib_prefs
            _lib_prefs="$(_val LIB_PREFS "$out")"
            if [ -n "$_lib_prefs" ]; then
                pass "Library/Preferences is accessible (allowlist)"
            else
                fail "Library/Preferences is accessible (allowlist)"
            fi
        else
            skip "Library/Preferences (not present on host)"
        fi
    fi

    if [ -f "$HOME/.gitconfig" ]; then
        assert_eq ".gitconfig is readable" "ok" "$(_val GITCFG "$out")"
    else
        skip ".gitconfig (not present on host)"
    fi

    if [ -d "$HOME/.local/share/keyrings" ]; then
        assert_eq "GNOME keyring is masked" "" "$(_val KEYRINGS "$out")"
    else
        skip "GNOME keyring (not present on host)"
    fi

    if [[ "$OS" == "Linux" ]] && [ -n "${XDG_RUNTIME_DIR:-}" ]; then
        local _xdg_items=()
        for _xdg_test in pulse systemd at-spi; do
            [ -d "$XDG_RUNTIME_DIR/$_xdg_test" ] && _xdg_items+=("$_xdg_test")
        done
        if [ ${#_xdg_items[@]} -gt 0 ]; then
            for _xdg_test in "${_xdg_items[@]}"; do
                assert_eq "XDG $XDG_RUNTIME_DIR/$_xdg_test is masked" "empty" "$(_val "$_xdg_test" "$out")"
            done
        else
            skip "XDG_RUNTIME_DIR masking (no sensitive dirs present)"
        fi
    fi

    if [[ "$OS" == "Linux" ]]; then
        if [ -f "$HOME/.docker/config.json" ]; then
            assert_eq ".docker/config.json auth stripped" "stripped" "$(_val DOCKER "$out")"
        else
            skip ".docker/config.json (not present on host)"
        fi
        if [ -f "$HOME/.azure/msal_token_cache.json" ]; then
            assert_eq ".azure credentials stripped" "stripped" "$(_val AZ_MSAL "$out")"
        else
            skip ".azure credential files (not present on host)"
        fi
    fi

    section_end
}

# Normal mode: MAGEN_ACTIVE, hostname, stripped secrets, DNS; macOS HTTPS smoke when online.
# shellcheck disable=SC2016
test_environment() {
    section "Sandbox — Environment"
    _normal_mode_run_batch_once
    local out="$NM_OUT"

    if ! $NM_BATCH_OK; then
        skip "environment checks (normal mode batch unavailable)"
        section_end
        return
    fi

    assert_eq "MAGEN_ACTIVE=1" "1" "$(_val SA "$out")"
    [[ "$OS" == "Linux" ]] && assert_eq "Hostname is 'sandbox'" "sandbox" "$(_val HN "$out")"

    if [[ "$OS" == "Linux" ]]; then
        assert_eq "AWS env var stripped" "unset" "$(_val ENV_AWS "$out")"
        assert_eq "Azure env var stripped" "unset" "$(_val ENV_AZURE "$out")"
        if [ -f "$HOME/.npmrc" ]; then
            assert_eq ".npmrc auth tokens stripped" "stripped" "$(_val NPMRC_AUTH "$out")"
        else
            skip ".npmrc auth stripped (not present on host)"
        fi
        assert_eq "/etc/resolv.conf is accessible" "ok" "$(_val DNS "$out")"
    elif [[ "$OS" == "Darwin" ]]; then
        assert_eq "/etc is accessible (symlink fix)" "ok" "$(_val DNS "$out")"

        if command -v curl &>/dev/null; then
            if curl -s --connect-timeout 2 --max-time 3 https://example.com >/dev/null 2>&1; then
                local net_out
                net_out=$(magen_run curl -sI --connect-timeout 5 --max-time 8 https://example.com) || true
                if echo "$net_out" | grep -qi "HTTP/"; then
                    pass "HTTPS works in normal mode (DNS + TLS)"
                else
                    fail "HTTPS works in normal mode (DNS + TLS)"
                fi
            else
                skip "HTTPS works in normal mode (host has no connectivity)"
            fi
        else
            skip "HTTPS works in normal mode (curl not available)"
        fi
    fi

    section_end
}

# Agent recipes: command-scoped homes / SET_ENV; sh -c keeps agent homes hidden.
# Three sandboxes run in parallel to cut wall-clock time.
# shellcheck disable=SC2016
test_agent_recipes() {
    section "Agents — recipes"
    local _adir _out_agent _out_claude _out_shc
    local _f_agent _f_claude _f_shc _p_agent _p_claude _p_shc

    mkdir -p /tmp/magen/sandbox
    _adir=$(mktemp -d /tmp/magen/sandbox/agent-test.XXXXXX) || {
        skip "agent recipe checks (mktemp failed)"
        section_end
        return
    }
    printf '%s\n' '#!/bin/sh' \
        'printf "AGENT_CLI=%s\n" "${AGENT_CLI_CREDENTIAL_STORE:-unset}"' \
        'printf "OPENAI=%s\n" "${OPENAI_API_KEY:-unset}"' \
        'printf "AZURE_SECRET=%s\n" "${AZURE_CLIENT_SECRET:-unset}"' \
        'printf "CLAUDE_HOME=%s\n" "$([ -d "$HOME/.claude" ] && echo visible || echo hidden)"' \
        >"$_adir/agent"
    printf '%s\n' '#!/bin/sh' \
        'printf "CLAUDE_HOME=%s\n" "$([ -d "$HOME/.claude" ] && echo visible || echo hidden)"' \
        >"$_adir/claude"
    chmod +x "$_adir/agent" "$_adir/claude"

    _f_agent="$TEST_DIR/agent-recipe.out"
    _f_claude="$TEST_DIR/claude-recipe.out"
    _f_shc="$TEST_DIR/shc-recipe.out"

    (MAGEN_RUN_STDERR="$TEST_DIR/agent.err" OPENAI_API_KEY=keep-me AZURE_CLIENT_SECRET=strip-me \
        magen_run "$_adir/agent" >"$_f_agent" || true) &
    _p_agent=$!
    if [ -d "$HOME/.claude" ]; then
        (MAGEN_RUN_STDERR="$TEST_DIR/claude.err" magen_run "$_adir/claude" >"$_f_claude" || true) &
        _p_claude=$!
    else
        _p_claude=""
    fi
    (MAGEN_RUN_STDERR="$TEST_DIR/shc.err" magen_run sh -c \
        'printf "CLAUDE_HOME=%s\n" "$([ -d "$HOME/.claude" ] && echo visible || echo hidden)"' \
        >"$_f_shc" || true) &
    _p_shc=$!

    wait "$_p_agent" || true
    [ -n "$_p_claude" ] && wait "$_p_claude" || true
    wait "$_p_shc" || true

    _out_agent=$(cat "$_f_agent" 2>/dev/null || true)
    assert_eq "cursor recipe sets AGENT_CLI_CREDENTIAL_STORE=file" "file" "$(_val AGENT_CLI "$_out_agent")"
    assert_eq "GLOBAL_PASS_ENV keeps OPENAI_API_KEY" "keep-me" "$(_val OPENAI "$_out_agent")"
    assert_eq "non-allowlisted AZURE_CLIENT_SECRET stripped" "unset" "$(_val AZURE_SECRET "$_out_agent")"
    assert_eq "cursor recipe does not mount .claude" "hidden" "$(_val CLAUDE_HOME "$_out_agent")"

    if [ -d "$HOME/.claude" ]; then
        _out_claude=$(cat "$_f_claude" 2>/dev/null || true)
        assert_eq "claude recipe mounts .claude" "visible" "$(_val CLAUDE_HOME "$_out_claude")"
    else
        skip "claude recipe mounts .claude (not present on host)"
    fi

    _out_shc=$(cat "$_f_shc" 2>/dev/null || true)
    if [ -d "$HOME/.claude" ]; then
        assert_eq "sh -c does not activate agent homes" "hidden" "$(_val CLAUDE_HOME "$_out_shc")"
    else
        skip "sh -c agent-home isolation (.claude not present on host)"
    fi

    rm -rf "$_adir"
    section_end
}

# Normal mode: project-dir secret globs masked (Linux); macOS SBPL regex parity for /tmp.
# shellcheck disable=SC2016
test_sensitive_files() {
    section "Sandbox — Sensitive files"
    _normal_mode_run_batch_once
    local out="$NM_OUT"

    if ! $NM_BATCH_OK; then
        skip "sensitive file checks (normal mode batch unavailable)"
        section_end
        return
    fi

    if [[ "$OS" == "Linux" ]]; then
        local _mask_pairs=(
            "PEM:*.pem" "KEY:*.key" "IDRSA:id_rsa*" "CREDS:credentials.json"
            "ENVLOCAL:.env.local" "ENVPROD:.env.production" "PFX:*.pfx"
            "SVCACCT:service-account*.json" "ENVSTAG:.env.staging" "P8:*.p8"
            "DOTENV:.env" "JKS:*.jks" "KDBX:*.kdbx" "TFSTATE:*.tfstate"
            "KUBECONFIG:kubeconfig" "NETRC:.netrc" "ENVDEV:.env.development"
            "ENVTEST:.env.test"
        )
        local _mask_pass=0 _mask_fail=0 _mask_total=${#_mask_pairs[@]}
        for _mp in "${_mask_pairs[@]}"; do
            local _mkey="${_mp%%:*}"
            local _mval
            _mval=$(_val "$_mkey" "$out")
            if [ -z "$_mval" ]; then
                _mask_pass=$((_mask_pass + 1))
            else
                _mask_fail=$((_mask_fail + 1))
            fi
        done

        if [ $_mask_fail -eq 0 ]; then
            if $VERBOSE; then
                for _mp in "${_mask_pairs[@]}"; do
                    pass "${_mp#*:} is masked in project dir"
                done
            else
                pass "Sensitive file masking ($_mask_pass/$_mask_total patterns blocked)"
                PASS=$((PASS + _mask_total - 1))
                _SEC_P=$((_SEC_P + _mask_total - 1))
            fi
        else
            for _mp in "${_mask_pairs[@]}"; do
                local _mkey="${_mp%%:*}" _mdesc="${_mp#*:}"
                assert_eq "$_mdesc is masked in project dir" "" "$(_val "$_mkey" "$out")"
            done
        fi

        assert_eq "Normal files still readable after masking" "test-content" "$(_val SAFE "$out")"

        if [ ${#NM_SENSITIVE_FILES[@]} -gt 0 ]; then
            rm -f "${NM_SENSITIVE_FILES[@]/#/$TEST_DIR/}"
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        assert_eq "/dev/null is writable" "ok" "$(_val DEVNULL "$out")"
        assert_eq "Regex blocks *.pem in /tmp" "blocked" "$(_val REGEX_PEM "$out")"
        assert_eq "Regex blocks id_rsa* in /tmp" "blocked" "$(_val REGEX_IDRSA "$out")"
        assert_eq "Regex blocks *.jks in /tmp" "blocked" "$(_val REGEX_JKS "$out")"
        assert_eq "Regex blocks *.kdbx in /tmp" "blocked" "$(_val REGEX_KDBX "$out")"
        assert_eq "Regex blocks *.tfstate in /tmp" "blocked" "$(_val REGEX_TFSTATE "$out")"
        assert_eq "Normal files in /tmp are writable" "writable" "$(_val REGEX_SAFE "$out")"
    fi

    section_end
}

# Normal mode: session log under ~/.local/state/magen/sandbox/logs (Linux + macOS).
# Linux also checks bashrc EXIT-trap stderr flush (macOS cmd-logger has no stderr tee).
test_session_logging() {
    section "Isolation — Session logging"

    local _log_dir="$HOME/.local/state/magen/sandbox/logs"
    mkdir -p "$_log_dir"

    local _test_log
    _test_log="$(mktemp "$_log_dir/sess-test.XXXXXX")"

    local _rc=0
    (cd "$TEST_DIR" && MAGEN_SKIP_VALIDATION=1 MAGEN_LOG_FILE="$_test_log" "$MAGEN" sh -c 'echo session-log-probe') \
        >/dev/null 2>"$STDERR_LOG" || _rc=$?

    if [ -s "$_test_log" ] && grep -q '=== Sandbox Session ===' "$_test_log" 2>/dev/null; then
        pass "Session log created with header"
    else
        fail "Session log created with header"
        $VERBOSE && {
            echo "    log=$_test_log rc=$_rc size=$(wc -c <"$_test_log" 2>/dev/null || echo 0)" >&2
            head -20 "$_test_log" 2>/dev/null | sed 's/^/      /' >&2
        }
    fi

    if [ -s "$_test_log" ] && grep -qE 'Mode:[[:space:]]+(normal|lockdown)' "$_test_log" 2>/dev/null; then
        pass "Session log records mode"
    else
        fail "Session log records mode"
    fi

    rm -f "$_test_log"

    # Linux-only: EXIT trap must flush remaining stderr when the shell exits
    # before PROMPT_COMMAND (uses the with-stderr bashrc wrapper).
    if [[ "$OS" == "Linux" ]]; then
        local _exit_log
        _exit_log=$(mktemp /tmp/sandbox-exit-log-test.XXXXXX)
        MAGEN_SESSION_LOG="$_exit_log" bash --norc --noprofile <<'EXITEOF' 2>/dev/null || true
_MAGEN_EXIT_LOGGED=false
_sandbox_flush_stderr() {
    [[ -n "${_MAGEN_STDERR_BUF:-}" && -f "$_MAGEN_STDERR_BUF" ]] || return 0
    local _size
    _size=$(stat -c %s "$_MAGEN_STDERR_BUF" 2>/dev/null) || return 0
    (( _size > ${_MAGEN_STDERR_OFFSET:-0} )) || return 0
    tail -c +"$((${_MAGEN_STDERR_OFFSET:-0} + 1))" "$_MAGEN_STDERR_BUF" 2>/dev/null | \
        tail -50 >> "$MAGEN_SESSION_LOG" 2>/dev/null
    _MAGEN_STDERR_OFFSET=$_size
}
_MAGEN_STDERR_BUF=$(mktemp /tmp/magen/sandbox/stderr-test.XXXXXX)
_MAGEN_STDERR_OFFSET=0
exec 3>&2 2> >(tee "$_MAGEN_STDERR_BUF" >&3)
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
echo "DOCKER_BUILD_ERROR: nginx.conf not found" >&2
exit 1
EXITEOF
        sleep 0.05
        if [ -s "$_exit_log" ] && grep -q "DOCKER_BUILD_ERROR" "$_exit_log" 2>/dev/null; then
            pass "EXIT trap flushes stderr on early exit"
        else
            fail "EXIT trap flushes stderr on early exit"
        fi
        if grep -q '\[exit 1\]' "$_exit_log" 2>/dev/null; then
            pass "EXIT trap logs exit code"
        else
            fail "EXIT trap logs exit code"
        fi
        rm -f "$_exit_log"
    fi

    section_end
}

# =============================================================================
# Home Directory Isolation
# =============================================================================

# Project under $HOME: isolation must still hide non-allowlisted dotdirs and
# prevent host $HOME pollution.
#   Linux  — ephemeral tmpfs $HOME (writes succeed inside, never hit the host)
#   macOS  — Seatbelt deny-default (writes to non-allowlisted home paths fail)

# shellcheck disable=SC2016
test_home_project_isolation() {
    section "Isolation — Home project"

    local _htd="$HOME/.magen-iso-test-$$"
    local _hpd="$_htd/project"
    mkdir -p "$_hpd"
    echo "home-test" >"$_hpd/test-file.txt"
    rm -f "$HOME/.eph-marker" 2>/dev/null || true

    local out
    out=$(magen_run --from "$_hpd" sh -c '
        printf "SA=%s\n" "$MAGEN_ACTIVE"
        printf "GNUPG=%s\n" "$([ -d "$HOME/.gnupg" ] && echo visible || echo hidden)"
        printf "AWS=%s\n" "$([ -d "$HOME/.aws" ] && echo visible || echo hidden)"
        printf "PR=%s\n" "$(cat test-file.txt 2>/dev/null)"
        printf "WR=%s\n" "$(echo ok > write-check.txt 2>/dev/null && echo ok || echo denied)"
        printf "PARENT=%s\n" "$(touch ../parent-write-check 2>/dev/null && echo rw || echo ro)"
        touch "$HOME/.eph-marker" 2>/dev/null
        printf "HOME_WRITE=%s\n" "$([ -f "$HOME/.eph-marker" ] && echo wrote || echo blocked)"
        printf "_OK=1\n"
    ') || true

    local _sa
    _sa="$(_val SA "$out")"

    if [[ "$_sa" != "1" ]]; then
        fail "Sandbox runs from \$HOME project"
        skip ".gnupg hidden (sandbox did not execute)"
        skip ".aws hidden (sandbox did not execute)"
        skip "Project readable (sandbox did not execute)"
        skip "Project writable (sandbox did not execute)"
        skip "Parent dir writable (sandbox did not execute)"
        skip "\$HOME writes don't leak (sandbox did not execute)"
    else
        pass "Sandbox runs from \$HOME project"

        if [ -d "$HOME/.gnupg" ]; then
            assert_eq ".gnupg hidden (\$HOME project)" "hidden" "$(_val GNUPG "$out")"
        else
            skip ".gnupg hidden (not present on host)"
        fi

        if [ -d "$HOME/.aws" ]; then
            assert_eq ".aws hidden (\$HOME project)" "hidden" "$(_val AWS "$out")"
        else
            skip ".aws hidden (not present on host)"
        fi

        assert_eq "Project readable (\$HOME project)" "home-test" "$(_val PR "$out")"
        assert_eq "Project writable (\$HOME project)" "ok" "$(_val WR "$out")"
        assert_eq "Parent dir writable (\$HOME project)" "rw" "$(_val PARENT "$out")"

        # Host must never see the marker. On Linux the write hit tmpfs; on macOS
        # Seatbelt blocks the write (HOME_WRITE=blocked) or it stays ephemeral.
        if [ ! -f "$HOME/.eph-marker" ]; then
            pass "\$HOME writes don't leak (\$HOME project)"
        else
            fail "\$HOME writes don't leak (\$HOME project)"
            rm -f "$HOME/.eph-marker"
        fi

        if [[ "$OS" == "Darwin" ]]; then
            # Extra macOS signal: writing directly under $HOME should be denied.
            assert_eq "\$HOME root write blocked (Seatbelt)" "blocked" "$(_val HOME_WRITE "$out")"
        fi
    fi

    rm -rf "$_htd"
    section_end
}

# =============================================================================
# GUI / Background Mode
# =============================================================================

# GUI dry-run: Linux Chromium gets --no-sandbox and no --die-with-parent; macOS Electron + SBPL allowances.
# shellcheck disable=SC2016
test_gui_mode() {
    section "Isolation — GUI / background"

    if [[ "$OS" == "Linux" ]]; then
        local fake_app_dir="$TEST_DIR/fake-chromium"
        mkdir -p "$fake_app_dir"
        touch "$fake_app_dir/chrome_crashpad_handler"
        printf '#!/bin/sh\ntrue\n' >"$fake_app_dir/fake-chrome"
        chmod +x "$fake_app_dir/fake-chrome"

        local _saved_path="$PATH"
        export PATH="$fake_app_dir:$PATH"

        local dry_out
        dry_out=$(magen_run --dry-run --verbose fake-chrome) || true

        if echo "$dry_out" | grep -q -- '--die-with-parent'; then
            fail "--die-with-parent excluded in GUI mode"
        else
            pass "--die-with-parent excluded in GUI mode"
        fi

        if echo "$dry_out" | grep -q -- '--no-sandbox'; then
            pass "--no-sandbox added for Chromium-based app"
        else
            fail "--no-sandbox added for Chromium-based app"
        fi

        export PATH="$_saved_path"

    elif [[ "$OS" == "Darwin" ]]; then
        local fake_app="$TEST_DIR/FakeElectron.app"
        mkdir -p "$fake_app/Contents/MacOS"
        mkdir -p "$fake_app/Contents/Resources/app/bin"
        printf '#!/bin/sh\ntrue\n' >"$fake_app/Contents/MacOS/FakeElectron"
        chmod +x "$fake_app/Contents/MacOS/FakeElectron"
        printf '#!/bin/sh\ntrue\n' >"$fake_app/Contents/Resources/app/bin/fake-electron"
        chmod +x "$fake_app/Contents/Resources/app/bin/fake-electron"

        local fake_bin_dir="$TEST_DIR/fake-bin"
        mkdir -p "$fake_bin_dir"
        ln -sf "$fake_app/Contents/Resources/app/bin/fake-electron" "$fake_bin_dir/fake-electron"

        local _saved_path="$PATH"
        export PATH="$fake_bin_dir:$PATH"

        local gui_dry_out
        gui_dry_out=$(magen_run --dry-run --verbose fake-electron) || true

        if grep -q 'gui:.*Electron binary.*--no-sandbox' "$TEST_DIR/stderr.log"; then
            pass "macOS Electron app detected and --no-sandbox logged"
        else
            fail "macOS Electron app detected and --no-sandbox logged"
        fi

        if echo "$gui_dry_out" | grep -q '(allow iokit-open)'; then
            pass "GUI profile includes IOKit permissions"
        else
            fail "GUI profile includes IOKit permissions"
        fi

        if echo "$gui_dry_out" | grep -q '(allow user-preference-read)'; then
            pass "GUI profile includes user-preference access"
        else
            fail "GUI profile includes user-preference access"
        fi

        export PATH="$_saved_path"
    else
        skip "GUI mode (unsupported OS)"
    fi

    section_end
}

# =============================================================================
# Docker Proxy
# =============================================================================

# Start docker.py against a fake daemon; sets _DOCKER_MAIN_* PIDs.
# shellcheck disable=SC2016
_docker_proxy_start_main() {
    local _proxy_sock="$1" _target_sock="$2"
    start_fake_docker_daemon "$_target_sock"
    _DOCKER_MAIN_FAKE_PID=$_FAKE_DAEMON_PID
    python3 "$ROOT_DIR/proxies/docker.py" \
        --proxy-socket "$_proxy_sock" \
        --target-socket "$_target_sock" \
        --deny "$HOME/.gnupg" \
        --deny "$HOME/.aws" \
        --deny "$HOME/.ssh" \
        2>/dev/null &
    _DOCKER_MAIN_PROXY_PID=$!
    local _i
    for _i in $(seq 1 20); do
        [ -S "$_proxy_sock" ] && return 0
        sleep 0.05
    done
    return 1
}

# Tear down docker-proxy + fake daemon from _docker_proxy_start_main.
_docker_proxy_stop_main() {
    kill "${_DOCKER_MAIN_PROXY_PID:-}" "${_DOCKER_MAIN_FAKE_PID:-}" 2>/dev/null || true
    wait "${_DOCKER_MAIN_PROXY_PID:-}" 2>/dev/null || true
    wait "${_DOCKER_MAIN_FAKE_PID:-}" 2>/dev/null || true
}

# docker-proxy: allowlist + denylist + exec/auth (single proxy lifecycle for speed).
# shellcheck disable=SC2016
test_docker_proxy() {
    section "Proxies — Docker"

    if ! command -v python3 &>/dev/null; then
        skip "Docker proxy tests (python3 not found)"
        section_end
        return
    fi

    if ! command -v curl &>/dev/null; then
        skip "Docker proxy tests (curl not found)"
        section_end
        return
    fi

    local _proxy_sock="$TEST_DIR/docker-proxy.sock"
    local _target_sock="$TEST_DIR/docker-fake.sock"
    _DOCKER_MAIN_PROXY_PID=""
    _DOCKER_MAIN_FAKE_PID=""

    if ! _docker_proxy_start_main "$_proxy_sock" "$_target_sock"; then
        fail "Docker proxy failed to start"
        kill "$_DOCKER_MAIN_FAKE_PID" 2>/dev/null || true
        wait "$_DOCKER_MAIN_FAKE_PID" 2>/dev/null || true
        section_end
        return
    fi

    subgroup "Allowed operations"
    assert_docker "Allows safe bind mount" "200" \
        POST "containers/create" \
        '{"HostConfig":{"Binds":["/tmp/safe-test:/mnt"]}}'
    assert_docker "Allows simple container create" "200" \
        POST "containers/create" \
        '{"Image":"alpine"}'
    assert_docker "Allows default Runtime (runc)" "200" \
        POST "containers/create" \
        '{"HostConfig":{"Runtime":"runc"}}'
    assert_docker "Passes through non-create requests" "200" \
        GET "version"

    subgroup "Restart policy (allowed)"
    assert_docker "Allows RestartPolicy on-failure" "200" \
        POST "containers/create" \
        '{"HostConfig":{"RestartPolicy":{"Name":"on-failure","MaximumRetryCount":3}}}'
    assert_docker "Allows RestartPolicy no" "200" \
        POST "containers/create" \
        '{"HostConfig":{"RestartPolicy":{"Name":"no"}}}'

    subgroup "Volume & network (allowed)"
    assert_docker "Allows safe volume create" "200" \
        POST "volumes/create" \
        '{"Name":"safe-vol"}'
    assert_docker "Allows bridge network driver" "200" \
        POST "networks/create" \
        '{"Name":"safe-net","Driver":"bridge"}'

    subgroup "Container security"
    assert_docker "Blocks mount to denied path" "403" \
        POST "containers/create" \
        "{\"HostConfig\":{\"Binds\":[\"$HOME/.gnupg:/mnt\"]}}"
    assert_docker "Blocks ancestor mount exposing denied path" "403" \
        POST "containers/create" \
        "{\"HostConfig\":{\"Binds\":[\"$HOME:/mnt\"]}}"
    assert_docker "Blocks root mount exposing denied paths" "403" \
        POST "containers/create" \
        '{"HostConfig":{"Binds":["/:/ host"]}}'
    assert_docker "Blocks structured Mount to denied path" "403" \
        POST "containers/create" \
        "{\"HostConfig\":{\"Mounts\":[{\"Type\":\"bind\",\"Source\":\"$HOME/.ssh\",\"Target\":\"/mnt\"}]}}"
    assert_docker "Blocks --privileged" "403" \
        POST "containers/create" \
        '{"HostConfig":{"Privileged":true}}'
    assert_docker "Blocks --cap-add=SYS_ADMIN" "403" \
        POST "containers/create" \
        '{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}'
    assert_docker "Blocks --cap-add=CAP_SYS_ADMIN" "403" \
        POST "containers/create" \
        '{"HostConfig":{"CapAdd":["CAP_SYS_ADMIN"]}}'
    assert_docker "Blocks --cap-add=SYS_PTRACE" "403" \
        POST "containers/create" \
        '{"HostConfig":{"CapAdd":["SYS_PTRACE"]}}'
    assert_docker "Blocks device mapping" "403" \
        POST "containers/create" \
        '{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda","PathInContainer":"/dev/xda","CgroupPermissions":"rwm"}]}}'
    assert_docker "Blocks apparmor=unconfined" "403" \
        POST "containers/create" \
        '{"HostConfig":{"SecurityOpt":["apparmor=unconfined"]}}'
    assert_docker "Blocks sysctls" "403" \
        POST "containers/create" \
        '{"HostConfig":{"Sysctls":{"net.ipv4.ip_forward":"1"}}}'
    assert_docker "Blocks custom CgroupParent" "403" \
        POST "containers/create" \
        '{"HostConfig":{"CgroupParent":"/custom"}}'
    assert_docker "Blocks GroupAdd" "403" \
        POST "containers/create" \
        '{"HostConfig":{"GroupAdd":["docker"]}}'
    assert_docker "Blocks custom Runtime" "403" \
        POST "containers/create" \
        '{"HostConfig":{"Runtime":"nvidia"}}'

    subgroup "Namespace isolation"
    assert_docker "Blocks --pid=host" "403" \
        POST "containers/create" \
        '{"HostConfig":{"PidMode":"host"}}'
    assert_docker "Blocks --network=host" "403" \
        POST "containers/create" \
        '{"HostConfig":{"NetworkMode":"host"}}'
    assert_docker "Blocks --userns=host" "403" \
        POST "containers/create" \
        '{"HostConfig":{"UsernsMode":"host"}}'
    assert_docker "Blocks --ipc=host" "403" \
        POST "containers/create" \
        '{"HostConfig":{"IpcMode":"host"}}'

    subgroup "Restart policy (blocked)"
    assert_docker "Blocks RestartPolicy always" "403" \
        POST "containers/create" \
        '{"HostConfig":{"RestartPolicy":{"Name":"always"}}}'
    assert_docker "Blocks RestartPolicy unless-stopped" "403" \
        POST "containers/create" \
        '{"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}}}'

    subgroup "Blocked API endpoints"
    assert_docker "Blocks privileged exec" "403" \
        POST "containers/test123/exec" \
        '{"Privileged":true,"Cmd":["sh"]}'
    assert_docker "Blocks container update" "403" \
        POST "containers/test123/update" \
        '{"Memory":1073741824}'
    assert_docker "Blocks container commit" "403" \
        POST "containers/test123/commit"
    assert_docker "Blocks container archive upload" "403" \
        PUT "containers/test123/archive?path=/tmp" \
        'fake-tar-data'
    assert_docker "Blocks container archive download" "403" \
        GET "containers/test123/archive?path=/etc"

    subgroup "Image operations"
    assert_docker "Blocks image push" "403" \
        POST "images/myimage/push"
    assert_docker "Blocks scoped image push" "403" \
        POST "images/registry.io%2Forg%2Fimg/push"
    assert_docker "Blocks image build" "403" \
        POST "build?t=myimage"
    assert_docker "Blocks image load" "403" \
        POST "images/load"

    subgroup "Volume & network (blocked)"
    assert_docker "Blocks volume with denied device path" "403" \
        POST "volumes/create" \
        "{\"Name\":\"evil\",\"DriverOpts\":{\"device\":\"$HOME/.gnupg\"}}"
    assert_docker "Blocks host network driver" "403" \
        POST "networks/create" \
        '{"Name":"evil-net","Driver":"host"}'

    subgroup "Swarm, plugins & secrets"
    assert_docker "Blocks swarm init" "403" \
        POST "swarm/init" \
        '{}'
    assert_docker "Blocks plugin install" "403" \
        POST "plugins/pull?remote=evil-plugin"
    assert_docker "Blocks secrets creation" "403" \
        POST "secrets/create" \
        '{"Name":"evil-secret","Data":"c2VjcmV0"}'
    assert_docker "Blocks configs creation" "403" \
        POST "configs/create" \
        '{"Name":"evil-config","Data":"c2VjcmV0"}'

    subgroup "Exec (allowed)"
    assert_docker "Allows non-privileged exec" "200" \
        POST "containers/test123/exec" \
        '{"Cmd":["date"]}'

    _docker_proxy_stop_main
    rm -f "$_proxy_sock" "$_target_sock"

    subgroup "Registry auth injection"
    local _test_docker_config
    _test_docker_config=$(mktemp "$TEST_DIR/docker-config.XXXXXX.json")
    python3 -c '
import json, base64
config = {"auths": {"test-reg.example.com": {"auth": base64.b64encode(b"testuser:testpass").decode()}}}
print(json.dumps(config))
' >"$_test_docker_config"

    local _auth_capture="$TEST_DIR/docker-auth-capture.txt"
    local _target_sock2="$TEST_DIR/docker-fake2.sock"
    local _proxy_sock2="$TEST_DIR/docker-proxy2.sock"

    start_fake_docker_daemon "$_target_sock2" "$_auth_capture"
    local _fake2_pid=$_FAKE_DAEMON_PID

    python3 "$ROOT_DIR/proxies/docker.py" \
        --proxy-socket "$_proxy_sock2" \
        --target-socket "$_target_sock2" \
        --docker-config "$_test_docker_config" \
        2>/dev/null &
    local _proxy2_pid=$!

    local _i
    for _i in $(seq 1 20); do
        [ -S "$_proxy_sock2" ] && break
        sleep 0.05
    done

    if [ -S "$_proxy_sock2" ]; then
        curl -s -o /dev/null --unix-socket "$_proxy_sock2" \
            -X POST "http://localhost/v1.45/images/create?fromImage=test-reg.example.com%2Fmyimage&tag=latest" 2>/dev/null
        sleep 0.05

        if [ -f "$_auth_capture" ] && [ -s "$_auth_capture" ]; then
            local _decoded_user
            _decoded_user=$(python3 -c '
import base64, json, sys
raw = sys.argv[1]
raw += "=" * (4 - len(raw) % 4)
data = json.loads(base64.urlsafe_b64decode(raw))
print(data.get("username", ""))
' "$(cat "$_auth_capture")" 2>/dev/null)
            assert_eq "Injects X-Registry-Auth for pull" "testuser" "$_decoded_user"
        else
            fail "X-Registry-Auth not injected for image pull"
        fi

        : >"$_auth_capture"
        curl -s -o /dev/null --unix-socket "$_proxy_sock2" \
            -X POST "http://localhost/v1.45/images/create?fromImage=unknown-reg.io%2Fimg&tag=v1" 2>/dev/null
        sleep 0.05

        local _no_auth
        _no_auth=$(cat "$_auth_capture" 2>/dev/null)
        assert_eq "No auth for unknown registry" "" "$_no_auth"
    else
        skip "Registry auth injection (proxy failed to start)"
    fi

    kill "$_proxy2_pid" "$_fake2_pid" 2>/dev/null || true
    wait "$_proxy2_pid" 2>/dev/null || true
    wait "$_fake2_pid" 2>/dev/null || true
    rm -f "$_proxy_sock2" "$_target_sock2" "$_test_docker_config" "$_auth_capture"

    section_end
}

# =============================================================================
# npm Registry Proxy
# =============================================================================

# npm_registry proxy: forwards GET with auth, blocks mutating methods, writes registry env file.
# shellcheck disable=SC2016
test_npm_proxy() {
    section "Proxies — npm"

    if ! command -v python3 &>/dev/null; then
        skip "npm proxy tests (python3 not found)"
        section_end
        return
    fi

    if ! command -v curl &>/dev/null; then
        skip "npm proxy tests (curl not found)"
        section_end
        return
    fi

    local _upstream_port_file="$TEST_DIR/npm-upstream-port"
    python3 - "$_upstream_port_file" <<'PYEOF' &
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        body = json.dumps({"auth": auth, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_PUT(self):
        self.do_GET()
srv = http.server.HTTPServer(("127.0.0.1", 0), H)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_address[1]))
srv.timeout = 30
while True:
    srv.handle_request()
    try:
        srv.handle_request()
    except Exception:
        break
PYEOF
    local _upstream_pid=$!

    local _j
    for _j in $(seq 1 20); do
        [ -s "$_upstream_port_file" ] && break
        sleep 0.05
    done

    if [ ! -s "$_upstream_port_file" ]; then
        fail "Fake npm upstream failed to start"
        kill "$_upstream_pid" 2>/dev/null || true
        section_end
        return
    fi
    local _upstream_port
    _upstream_port=$(cat "$_upstream_port_file")

    local _test_npmrc="$TEST_DIR/test-npmrc"
    cat >"$_test_npmrc" <<EOF
registry=http://127.0.0.1:$_upstream_port/
//127.0.0.1:$_upstream_port/:_authToken=test-secret-token-12345
EOF

    local _port_file="$TEST_DIR/npm-proxy-port"
    local _env_file="$TEST_DIR/npm-proxy-env"

    python3 "$ROOT_DIR/proxies/npm_registry.py" \
        --npmrc "$_test_npmrc" \
        --port-file "$_port_file" \
        --env-file "$_env_file" \
        2>/dev/null &
    local _proxy_pid=$!

    local _i
    for _i in $(seq 1 20); do
        [ -s "$_port_file" ] && break
        sleep 0.05
    done

    if [ ! -s "$_port_file" ]; then
        fail "npm registry proxy failed to start"
        kill "$_upstream_pid" "$_proxy_pid" 2>/dev/null || true
        section_end
        return
    fi
    local _proxy_port
    _proxy_port=$(cat "$_port_file")

    local _resp _auth
    _resp=$(curl -s "http://127.0.0.1:$_proxy_port/test-package" 2>/dev/null)
    _auth=$(echo "$_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('auth',''))" 2>/dev/null)
    assert_eq "Injects auth header on GET" "Bearer test-secret-token-12345" "$_auth"

    local _code
    _code=$(curl -s -o /dev/null -w '%{http_code}' \
        -X PUT -H "Content-Type: application/json" -d '{}' \
        "http://127.0.0.1:$_proxy_port/test-package" 2>/dev/null)
    assert_eq "Blocks PUT (publish)" "403" "$_code"

    _code=$(curl -s -o /dev/null -w '%{http_code}' \
        -X POST -H "Content-Type: application/json" -d '{}' \
        "http://127.0.0.1:$_proxy_port/test-package" 2>/dev/null)
    assert_eq "Blocks POST" "403" "$_code"

    _code=$(curl -s -o /dev/null -w '%{http_code}' \
        -X DELETE "http://127.0.0.1:$_proxy_port/test-package" 2>/dev/null)
    assert_eq "Blocks DELETE (unpublish)" "403" "$_code"

    _code=$(curl -s -o /dev/null -w '%{http_code}' \
        -X PATCH -H "Content-Type: application/json" -d '{}' \
        "http://127.0.0.1:$_proxy_port/test-package" 2>/dev/null)
    assert_eq "Blocks PATCH" "403" "$_code"

    assert_ok "Env file contains registry override" \
        grep -q "npm_config_registry" "$_env_file"

    kill "$_proxy_pid" "$_upstream_pid" 2>/dev/null || true
    wait "$_proxy_pid" 2>/dev/null || true
    wait "$_upstream_pid" 2>/dev/null || true
    rm -f "$_port_file" "$_env_file" "$_test_npmrc" "$_upstream_port_file"

    section_end
}

# =============================================================================
# Azure CLI Proxy
# =============================================================================

# Azure CLI proxy: allowed commands forwarded, credential-exposing commands blocked.
# shellcheck disable=SC2016,SC2154
test_azure_proxy() {
    section "Proxies — Azure CLI"

    if ! command -v python3 &>/dev/null; then
        skip "Azure proxy tests (python3 not found)"
        section_end
        return
    fi

    local _fake_az_dir="$TEST_DIR/fake-az-bin"
    mkdir -p "$_fake_az_dir"
    cat >"$_fake_az_dir/az" <<'AZEOF'
#!/bin/bash
printf 'az-output: %s\n' "$*"
AZEOF
    chmod +x "$_fake_az_dir/az"

    local _proxy_sock="$TEST_DIR/azure-proxy-test.sock"

    PATH="$_fake_az_dir:$PATH" \
        python3 "$ROOT_DIR/proxies/azure_cli.py" \
        --socket "$_proxy_sock" \
        --timeout 5 \
        2>/dev/null &
    local _proxy_pid=$!

    local _i
    for _i in $(seq 1 20); do
        [ -S "$_proxy_sock" ] && break
        sleep 0.05
    done

    if [ ! -S "$_proxy_sock" ]; then
        fail "Azure CLI proxy failed to start"
        kill "$_proxy_pid" 2>/dev/null || true
        section_end
        return
    fi

    echo '{"name":"TestLabel"}' >"$TEST_DIR/label.json"

    # Batch all requests in a single Python process instead of spawning
    # python3 per request+field (~24 processes → 1).
    local _results_file="$TEST_DIR/az-proxy-results.sh"
    python3 - "$_proxy_sock" "$TEST_DIR/label.json" "$_results_file" <<'PYEOF'
import json, socket, sys

sock_path, label_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]

def az_req(payload_str):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(sock_path)
    s.sendall(payload_str.encode())
    s.shutdown(socket.SHUT_WR)
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    return json.loads(buf)

requests = [
    ("repos_pr_list", '{"args": ["repos", "pr", "list", "--output", "json"]}'),
    ("devops_project", '{"args": ["devops", "project", "list"]}'),
    ("account_show", '{"args": ["account", "show"]}'),
    ("rest_devops", '{"args": ["rest", "--method", "POST", "--uri", '
     '"https://dev.azure.com/org/proj/_apis/git/repositories/repo/'
     'pullRequests/1/labels?api-version=7.0", "--body", "{\\"name\\":\\"Tag\\"}"]}'),
    ("rest_denied", '{"args": ["rest", "--method", "GET", "--uri", '
     '"https://management.azure.com/subscriptions?api-version=2020-01-01"]}'),
    ("infile", json.dumps({"args": ["devops", "invoke", "--in-file", label_file],
                           "files": {"--in-file": '{"name":"TestLabel"}'}})),
    ("get_token", '{"args": ["account", "get-access-token"]}'),
    ("vm_list", '{"args": ["vm", "list"]}'),
    ("invalid_json", "not-valid-json"),
]

lines = []
for name, payload in requests:
    data = az_req(payload)
    for key in ("exitcode", "stdout", "stderr"):
        val = str(data.get(key, "")).rstrip("\n").replace("'", "'\\''")
        lines.append(f"_AZ_{name}_{key}='{val}'")

with open(out_file, "w") as f:
    f.write("\n".join(lines) + "\n")
PYEOF

    # shellcheck disable=SC1090
    source "$_results_file"

    subgroup "Allowed commands (DevOps)"
    assert_eq "Allows az repos pr list" "0" "$_AZ_repos_pr_list_exitcode"
    assert_eq "Forwards args to real az" "az-output: repos pr list --output json" "$_AZ_repos_pr_list_stdout"
    assert_eq "Allows az devops project list" "0" "$_AZ_devops_project_exitcode"
    assert_eq "Allows az account show" "0" "$_AZ_account_show_exitcode"

    subgroup "az rest (URL-filtered)"
    assert_eq "Allows az rest to dev.azure.com" "0" "$_AZ_rest_devops_exitcode"
    assert_eq "Denies az rest to non-DevOps endpoint" "1" "$_AZ_rest_denied_exitcode"

    subgroup "File transfer (--in-file)"
    assert_eq "Allows devops invoke with --in-file" "0" "$_AZ_infile_exitcode"
    assert_ok "Proxy materialised file for az" \
        bash -c '[[ "$1" != *"does not point"* ]]' _ "$_AZ_infile_stdout"

    subgroup "Denied commands (cloud resources / credentials)"
    assert_eq "Denies account get-access-token" "1" "$_AZ_get_token_exitcode"
    assert_ok "Deny message mentions not allowed" \
        bash -c '[[ "$1" == *not\ allowed* ]]' _ "$_AZ_get_token_stderr"
    assert_eq "Denies cloud resource commands (vm)" "1" "$_AZ_vm_list_exitcode"

    subgroup "Error handling"
    assert_eq "Rejects invalid JSON request" "1" "$_AZ_invalid_json_exitcode"

    kill "$_proxy_pid" 2>/dev/null || true
    wait "$_proxy_pid" 2>/dev/null || true
    rm -f "$_proxy_sock" "$_results_file" "$TEST_DIR/label.json"
    rm -rf "$_fake_az_dir"

    section_end
}

# =============================================================================
# Lockdown Mode
# =============================================================================

# Lockdown: read-only project, minimal PATH, no secret env leak, blocked network when host can reach internet.
# shellcheck disable=SC2016
test_lockdown_mode() {
    section "Lockdown"

    local out

    # Skip network assertion when the host itself cannot reach the probe (avoid false failures).
    local _host_has_net=false _has_curl=false _has_wget=false
    if command -v curl &>/dev/null; then
        _has_curl=true
        curl -s --connect-timeout 2 --max-time 3 http://1.1.1.1 >/dev/null 2>&1 && _host_has_net=true
    elif command -v wget &>/dev/null; then
        _has_wget=true
        wget -q --timeout=3 -O /dev/null http://1.1.1.1 2>/dev/null && _host_has_net=true
    fi

    if [[ "$OS" == "Darwin" ]]; then
        # macOS: merge dotfile + Library checks into the single sandbox call.
        out=$(CUSTOM_SECRET=hunter2 magen_run --lockdown sh -c '
            printf "SA=%s\n" "$MAGEN_ACTIVE"
            printf "PR=%s\n" "$(cat test-file.txt 2>/dev/null)"
            printf "PW=%s\n" "$(echo x > lockdown-rw-test.txt 2>/dev/null && echo writable || echo readonly)"
            printf "HOME_LS=%s\n" "$(ls -A "$HOME" 2>/dev/null | grep -v "^\.bashrc$\|^\.local$" | head -1)"
            printf "PATH=%s\n" "$PATH"
            printf "SECRET=%s\n" "${CUSTOM_SECRET:-unset}"
            printf "GITCFG=%s\n" "$(cat "$HOME/.gitconfig" >/dev/null 2>&1 && echo readable || echo denied)"
            printf "LIB_MAIL=%s\n" "$(ls "$HOME/Library/Mail/" >/dev/null 2>&1 && echo readable || echo denied)"
            if command -v curl >/dev/null 2>&1; then
                printf "NET=%s\n" "$(curl -s --connect-timeout 2 --max-time 3 http://1.1.1.1 >/dev/null 2>&1 && echo open || echo blocked)"
            elif command -v wget >/dev/null 2>&1; then
                printf "NET=%s\n" "$(wget -q --timeout=3 -O /dev/null http://1.1.1.1 2>/dev/null && echo open || echo blocked)"
            fi
        ') || true
    else
        out=$(CUSTOM_SECRET=hunter2 magen_run --lockdown sh -c '
            printf "SA=%s\n" "$MAGEN_ACTIVE"
            printf "PR=%s\n" "$(cat test-file.txt 2>/dev/null)"
            printf "PW=%s\n" "$(echo x > lockdown-rw-test.txt 2>/dev/null && echo writable || echo readonly)"
            printf "HOME_LS=%s\n" "$(ls -A "$HOME" 2>/dev/null | grep -v "^\.bashrc$\|^\.local$" | head -1)"
            printf "PATH=%s\n" "$PATH"
            printf "SECRET=%s\n" "${CUSTOM_SECRET:-unset}"
            if command -v curl >/dev/null 2>&1; then
                printf "NET=%s\n" "$(curl -s --connect-timeout 2 --max-time 3 http://1.1.1.1 >/dev/null 2>&1 && echo open || echo blocked)"
            elif command -v wget >/dev/null 2>&1; then
                printf "NET=%s\n" "$(wget -q --timeout=3 -O /dev/null http://1.1.1.1 2>/dev/null && echo open || echo blocked)"
            fi
        ') || true
    fi
    rm -f "$TEST_DIR/lockdown-rw-test.txt"

    local _batch_sa
    _batch_sa="$(_val SA "$out")"
    assert_eq "MAGEN_ACTIVE=1" "1" "$_batch_sa"
    assert_eq "Project is read-only" "readonly" "$(_val PW "$out")"
    assert_eq "Can still read project files" "test-content" "$(_val PR "$out")"

    if [[ "$OS" == "Linux" ]]; then
        if [[ "$_batch_sa" == "1" ]]; then
            local home_ls
            home_ls="$(_val HOME_LS "$out")"
            if [ -z "$home_ls" ]; then
                pass "No dotfiles mounted"
            else
                fail "No dotfiles mounted (found: '$home_ls')"
            fi
        else
            skip "No dotfiles mounted (sandbox did not execute)"
        fi
    elif [[ "$OS" == "Darwin" ]]; then
        if [ -f "$HOME/.gitconfig" ]; then
            assert_eq "Dotfiles are inaccessible" "denied" "$(_val GITCFG "$out")"
        elif [ -d "$HOME/.config" ]; then
            local _cfg_out
            _cfg_out=$(magen_run --lockdown sh -c 'ls "$HOME/.config" >/dev/null 2>&1 && echo readable || echo denied') || true
            assert_eq "Dotfiles are inaccessible" "denied" "$_cfg_out"
        else
            skip "Dotfiles are inaccessible (no dotfiles to verify)"
        fi
    fi

    assert_eq "PATH is minimal" "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" "$(_val PATH "$out")"
    assert_eq "Host env vars don't leak" "unset" "$(_val SECRET "$out")"

    if [[ "$OS" == "Darwin" ]] && [ -d "$HOME/Library/Mail" ]; then
        assert_eq "Library/Mail is inaccessible in lockdown" "denied" "$(_val LIB_MAIL "$out")"
    fi

    if $_host_has_net; then
        assert_eq "Network is blocked" "blocked" "$(_val NET "$out")"
    elif $_has_curl || $_has_wget; then
        skip "Network is blocked (host has no connectivity)"
    else
        skip "Network is blocked (no curl/wget available)"
    fi

    section_end
}

# =============================================================================
# Parallel category runner
# =============================================================================

_WPIDS=()
_WOUTS=()
_WSTATS=()

# Spawn a category worker with its own TEST_DIR (avoids cwd races).
# Args: display-name then test functions to run.
_spawn_category() {
    local _name="$1"
    shift
    local _wdir _out _stats
    _wdir=$(mktemp -d /var/tmp/magen-sandbox-test.XXXXXX)
    echo "test-content" >"$_wdir/test-file.txt"
    _out=$(mktemp "$TEST_DIR/wout.XXXXXX")
    _stats=$(mktemp "$TEST_DIR/wstats.XXXXXX")
    # shellcheck disable=SC2030
    (
        set +e
        TEST_DIR="$_wdir"
        STDERR_LOG="$_wdir/stderr.log"
        NM_BATCH_OK=false
        _NM_BATCH_RAN=""
        NM_OUT=""
        NM_SENSITIVE_FILES=()
        NM_TMP_LEAK=""
        PASS=0
        FAIL=0
        SKIP=0
        SUITE_PASS=0
        SUITE_FAIL=0
        FAILURES=()
        printf '\n%s━━ %s ━━%s\n' "$BOLD" "$_name" "$NC"
        "$@"
        {
            echo "$PASS $FAIL $SKIP $SUITE_PASS $SUITE_FAIL"
            if [ ${#FAILURES[@]} -gt 0 ]; then
                printf '%s\n' "${FAILURES[@]}"
            fi
        } >"$_stats"
        rm -rf "$_wdir"
        exit 0
    ) >"$_out" 2>&1 &
    _WPIDS+=("$!")
    _WOUTS+=("$_out")
    _WSTATS+=("$_stats")
}

_await_categories() {
    local _i=0 _n=${#_WPIDS[@]} _pp _pf _ps _psp _psf _fl
    while [ "$_i" -lt "$_n" ]; do
        wait "${_WPIDS[$_i]}" || true
        cat "${_WOUTS[$_i]}"
        # shellcheck disable=SC2031
        if [ -s "${_WSTATS[$_i]}" ]; then
            {
                read -r _pp _pf _ps _psp _psf || true
                PASS=$((PASS + ${_pp:-0}))
                FAIL=$((FAIL + ${_pf:-0}))
                SKIP=$((SKIP + ${_ps:-0}))
                SUITE_PASS=$((SUITE_PASS + ${_psp:-0}))
                SUITE_FAIL=$((SUITE_FAIL + ${_psf:-0}))
                while IFS= read -r _fl || [ -n "${_fl:-}" ]; do
                    [ -n "${_fl:-}" ] && FAILURES+=("$_fl")
                done
            } <"${_WSTATS[$_i]}"
        fi
        rm -f "${_WOUTS[$_i]}" "${_WSTATS[$_i]}"
        _i=$((_i + 1))
    done
    _WPIDS=()
    _WOUTS=()
    _WSTATS=()
}

_run_sandbox_category() {
    test_project_access
    test_filesystem_isolation
    test_environment
    test_sensitive_files
}

_run_agents_category() {
    test_agent_recipes
}

_run_isolation_category() {
    test_session_logging
    test_home_project_isolation
    test_gui_mode
}

_run_proxies_docker() {
    test_docker_proxy
}

_run_proxies_npm() {
    test_npm_proxy
}

_run_proxies_azure() {
    test_azure_proxy
}

# =============================================================================
# Run
# =============================================================================

$CAT_SANDBOX && _spawn_category "Sandbox" _run_sandbox_category
$CAT_AGENTS && _spawn_category "Agents" _run_agents_category
$CAT_ISOLATION && _spawn_category "Isolation" _run_isolation_category
if $CAT_PROXIES; then
    _spawn_category "Proxies · Docker" _run_proxies_docker
    _spawn_category "Proxies · npm" _run_proxies_npm
    _spawn_category "Proxies · Azure" _run_proxies_azure
fi
$CAT_LOCKDOWN && _spawn_category "Lockdown" test_lockdown_mode

_await_categories

# =============================================================================
# Summary
# =============================================================================

ELAPSED=$(($(now_ms) - START_TIME))
_total_time=$(LC_NUMERIC=C awk -v ms="$ELAPSED" 'BEGIN {printf "%.2f", ms/1000}')
TOTAL=$((PASS + FAIL + SKIP))
SUITE_TOTAL=$((SUITE_PASS + SUITE_FAIL))

echo ""

_suite_summary=""
if [ $SUITE_FAIL -gt 0 ]; then
    _suite_summary="${RED}${BOLD}$SUITE_FAIL failed${NC}, "
fi
_suite_summary+="${GREEN}${BOLD}$SUITE_PASS passed${NC}, $SUITE_TOTAL total"

_test_summary=""
if [ $FAIL -gt 0 ]; then
    _test_summary="${RED}${BOLD}$FAIL failed${NC}, "
fi
if [ $SKIP -gt 0 ]; then
    _test_summary+="${YELLOW}${BOLD}$SKIP skipped${NC}, "
fi
_test_summary+="${GREEN}${BOLD}$PASS passed${NC}, $TOTAL total"

printf "Test Suites:  %s\n" "$_suite_summary"
printf "Tests:        %s\n" "$_test_summary"
printf "Time:         %ss\n" "$_total_time"

if [ ${#FAILURES[@]} -gt 0 ]; then
    echo ""
    for _f in "${FAILURES[@]}"; do
        printf "  ${RED}✗${NC} %s\n" "$_f"
    done
    $VERBOSE || printf "\n%sTip: run with --verbose (-v) for detailed output%s\n" "$DIM" "$NC"
fi

echo ""

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
