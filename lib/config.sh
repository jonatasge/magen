#!/bin/bash
#
# config.sh — allowlists, deny lists, and shared helpers for magen
#
# Single source of truth for what the sandbox may mount or expose:
# home dotdirs (RW/RO), config/cache denylists, macOS Library allowlists,
# sensitive env prefixes, and sensitive file patterns (glob|regex).
#
# Sourced by: magen (not executed directly)
#

# --- Dotdir access control (allowlist model) ---
# Only explicitly listed directories under $HOME are mounted.
# Everything else stays on the ephemeral/tmpfs home and is unreachable.
_DOTDIR_RW_LIST=(.cursor .config .cache .npm .yarn .mcp-auth .docker)
_DOTDIR_RO_LIST=(
    .local .vscode .nvm .sdkman .rustup .cargo .pyenv .rbenv .goenv
    .asdf .mise .volta .fnm .jabba .jenv .openjfx .dotnet .net
    .redhat .antigravity .m2 .azure
)

# Subtrees masked even when the parent (.config / .cache) is RW.
# shellcheck disable=SC2034
CONFIG_DENY=(BraveSoftware Bitwarden google-chrome chromium gh gcloud helm)
# shellcheck disable=SC2034
CACHE_DENY=(BraveSoftware chromium google-chrome)

# macOS ~/Library paths that may be written (Seatbelt allowlist).
# shellcheck disable=SC2034
LIBRARY_ALLOW=(Caches Preferences Logs Fonts Developer LaunchAgents)
# shellcheck disable=SC2034
LIBRARY_APP_SUPPORT_ALLOW=(Cursor Code)

# --- Environment sanitization ---
# Variables matching these prefixes are stripped before entering the sandbox.
_ENV_SENSITIVE_PREFIXES=(
    AWS_ AZURE_ GCP_ GOOGLE_CLOUD_ GOOGLE_APPLICATION_
    GITHUB_ GH_ GITLAB_ BITBUCKET_
    NPM_TOKEN NPM_AUTH
    DOCKER_
    DATABASE_ DB_PASSWORD DB_USER
    OPENAI_ ANTHROPIC_
    SENTRY_ CODECOV_ SONAR_ SNYK_
    VAULT_ CONSUL_
    HEROKU_ NETLIFY_ VERCEL_
    SLACK_ TWILIO_ SENDGRID_ STRIPE_ DATADOG_
    SECRET_ TOKEN_ PASSWORD_ PRIVATE_KEY
    CI_ CIRCLE_ TRAVIS_ JENKINS_
    PYPI_TOKEN CARGO_REGISTRY_TOKEN KUBECONFIG
    MAVEN_ GRADLE_ ARTIFACTORY_ NEXUS_
    PULUMI_ACCESS_TOKEN TERRAFORM_ TF_VAR_
)

# --- Sensitive file patterns ---
# Single source for Linux (find -name) and macOS (SBPL regex).
# Format: "glob|regex"
_SENSITIVE_FILE_PATTERNS=(
    '*.pem|\.pem$'
    '*.key|\.key$'
    '*.p12|\.p12$'
    '*.keystore|\.keystore$'
    '*.pfx|\.pfx$'
    '*.p8|\.p8$'
    '*.jks|\.jks$'
    '*.asc|\.asc$'
    '*.gpg|\.gpg$'
    '*.kdbx|\.kdbx$'
    '*.tfstate|\.tfstate$'
    '*id_rsa*|id_rsa'
    '*id_ed25519*|id_ed25519'
    '*id_ecdsa*|id_ecdsa'
    '*id_dsa*|id_dsa'
    'credentials.json|credentials\.json$'
    'service-account*.json|service-account.*\.json$'
    'serviceAccountKey.json|serviceAccountKey\.json$'
    'kubeconfig|/kubeconfig$'
    'token.json|/token\.json$'
    '.netrc|/\.netrc$'
    '.env.local|\.env\.local$'
    '.env.production|\.env\.production$'
    '.env.staging|\.env\.staging$'
    '.env.development|\.env\.development$'
    '.env.test|\.env\.test$'
    '.env|\.env$'
)

# Build find(1) -name expression from the glob half of each pattern.
_FIND_NAME_ARGS=()
_build_find_name_args() {
    _FIND_NAME_ARGS=('(')
    local first=1 entry glob
    for entry in "${_SENSITIVE_FILE_PATTERNS[@]}"; do
        glob="${entry%%|*}"
        ((first)) || _FIND_NAME_ARGS+=(-o)
        _FIND_NAME_ARGS+=(-name "$glob")
        first=0
    done
    _FIND_NAME_ARGS+=(')')
}
_build_find_name_args

# Vars that match a sensitive prefix but are safe build-tool settings (keep them).
_ENV_SAFE_KEEP_LIST=(
    DOCKER_BUILDKIT DOCKER_DEFAULT_PLATFORM DOCKER_SCAN_SUGGEST
    DOCKER_CLI_COLOR DOCKER_CLI_HINTS DOCKER_HIDE_LEGACY_COMMANDS
    MAVEN_OPTS MAVEN_HOME MAVEN_ARGS MAVEN_BATCH_MODE
    GRADLE_OPTS GRADLE_HOME GRADLE_USER_HOME
    SENTRY_ENVIRONMENT SENTRY_RELEASE
)

_is_env_safe() {
    [[ " ${_ENV_SAFE_KEEP_LIST[*]} " == *" $1 "* ]]
}

# Strip registry auth from a host Docker config while keeping other settings.
_sanitize_docker_config() {
    python3 -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    for k in ("auths", "credsStore", "credHelpers"):
        data.pop(k, None)
    json.dump(data, sys.stdout, indent=2)
except Exception:
    sys.stdout.write("{}")
' "$1" >"$2" 2>/dev/null || echo '{}' >"$2"
}

# True if the named home dotdir should be mounted read-write.
is_rw() {
    $LOCKDOWN && return 1
    [[ " ${_DOTDIR_RW_LIST[*]} " == *" $1 "* ]]
}

# True if the named home dotdir should be mounted read-only.
is_allowed_ro() {
    [[ " ${_DOTDIR_RO_LIST[*]} " == *" $1 "* ]]
}
