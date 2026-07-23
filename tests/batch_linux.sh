#!/bin/bash
#
# batch_linux.sh — in-sandbox probe script for Linux normal-mode tests.
#
# Copied into a temp project and executed inside magen. Prints KEY=VALUE
# lines that tests/test.sh parses to assert isolation (HOME, secrets,
# credential stripping, XDG masking, DNS, etc.).
#
# Invoked by: tests/test.sh (not run directly on the host).
#

# --- Runtime / project basics ---
printf "SA=%s\n" "$MAGEN_ACTIVE"
printf "HN=%s\n" "$(hostname 2>/dev/null)"
printf "PR=%s\n" "$(cat test-file.txt 2>/dev/null)"
printf "SYS=%s\n" "$([ -d /usr ] && [ -d /bin ] && command -v ls >/dev/null && echo ok)"
printf "GIT=%s\n" "$(git --version >/dev/null 2>&1 && echo ok)"

# --- Writable project + ephemeral HOME /tmp leak probes ---
echo written >write-test.txt
touch "$HOME/.ephemeral-marker"
echo leak >/tmp/magen/sandbox/leak-test

# --- Sensitive / non-allowlisted home paths should be hidden ---
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
# shellcheck disable=SC2012
printf "KEYRINGS=%s\n" "$(ls "$HOME/.local/share/keyrings/" 2>/dev/null | head -1)"

# --- SSH: keys denied; config / known_hosts readable ---
printf "SSH_KEYS=%s\n" "$(ls "$HOME/.ssh/id_"* 2>/dev/null && echo found || echo none)"
printf "SSH_CFG=%s\n" "$(cat "$HOME/.ssh/config" >/dev/null 2>&1 && echo ok || echo no)"
printf "SSH_KH=%s\n" "$(cat "$HOME/.ssh/known_hosts" >/dev/null 2>&1 && echo ok || echo no)"

# --- Browser config trees under ~/.config should be masked ---
# shellcheck disable=SC2012
printf "BRAVE=%s\n" "$(ls "$HOME/.config/BraveSoftware/" 2>/dev/null | head -1)"
# shellcheck disable=SC2012
printf "CHROME=%s\n" "$(ls "$HOME/.config/google-chrome/" 2>/dev/null | head -1)"
# shellcheck disable=SC2012
printf "CHROMIUM=%s\n" "$(ls "$HOME/.config/chromium/" 2>/dev/null | head -1)"
printf "GITCFG=%s\n" "$(cat "$HOME/.gitconfig" >/dev/null 2>&1 && echo ok || echo no)"

# --- Project-dir sensitive files should be unreadable (bound to /dev/null) ---
printf "PEM=%s\n" "$(cat test-secret.pem 2>/dev/null)"
printf "KEY=%s\n" "$(cat test-secret.key 2>/dev/null)"
printf "IDRSA=%s\n" "$(cat test_id_rsa_backup 2>/dev/null)"
printf "CREDS=%s\n" "$(cat credentials.json 2>/dev/null)"
printf "ENVLOCAL=%s\n" "$(cat .env.local 2>/dev/null)"
printf "ENVPROD=%s\n" "$(cat .env.production 2>/dev/null)"
printf "PFX=%s\n" "$(cat test-secret.pfx 2>/dev/null)"
printf "SVCACCT=%s\n" "$(cat service-account-key.json 2>/dev/null)"
printf "SAFE=%s\n" "$(cat test-file.txt 2>/dev/null)"

# --- XDG runtime masking ---
for d in pulse systemd at-spi; do
    if [ -d "$XDG_RUNTIME_DIR/$d" ]; then
        # shellcheck disable=SC2012
        c=$(ls "$XDG_RUNTIME_DIR/$d" 2>/dev/null | head -1)
        printf "%s=%s\n" "$d" "${c:-empty}"
    fi
done
if [ -e "$XDG_RUNTIME_DIR/bus" ]; then
    printf "dbus=%s\n" "$(cat "$XDG_RUNTIME_DIR/bus" 2>/dev/null | head -c 1 && echo ok || echo masked)"
fi

# --- Credential files mounted but sanitized ---
if [ -f "$HOME/.docker/config.json" ]; then
    if grep -q "\"auths\"" "$HOME/.docker/config.json" 2>/dev/null; then
        printf "DOCKER=present\n"
    else
        printf "DOCKER=stripped\n"
    fi
else
    printf "DOCKER=absent\n"
fi
if [ -f "$HOME/.azure/msal_token_cache.json" ]; then
    _c=$(cat "$HOME/.azure/msal_token_cache.json" 2>/dev/null)
    if [ "$_c" = "{}" ]; then
        printf "AZ_MSAL=stripped\n"
    else
        printf "AZ_MSAL=present\n"
    fi
else
    printf "AZ_MSAL=absent\n"
fi

# --- Additional sensitive-pattern probes ---
printf "ENVSTAG=%s\n" "$(cat .env.staging 2>/dev/null)"
printf "P8=%s\n" "$(cat test.p8 2>/dev/null)"
printf "DOTENV=%s\n" "$(cat .env 2>/dev/null)"
printf "JKS=%s\n" "$(cat test.jks 2>/dev/null)"
printf "KDBX=%s\n" "$(cat test.kdbx 2>/dev/null)"
printf "TFSTATE=%s\n" "$(cat test.tfstate 2>/dev/null)"
printf "KUBECONFIG=%s\n" "$(cat kubeconfig 2>/dev/null)"
printf "NETRC=%s\n" "$(cat .netrc 2>/dev/null)"
printf "ENVDEV=%s\n" "$(cat .env.development 2>/dev/null)"
printf "ENVTEST=%s\n" "$(cat .env.test 2>/dev/null)"

# --- Environment sanitization ---
printf "ENV_AWS=%s\n" "${AWS_SECRET_ACCESS_KEY:-unset}"
printf "ENV_AZURE=%s\n" "${AZURE_CLIENT_SECRET:-unset}"
if [ -f "$HOME/.npmrc" ]; then
    if grep -q "_authToken" "$HOME/.npmrc" 2>/dev/null; then
        printf "NPMRC_AUTH=present\n"
    else
        printf "NPMRC_AUTH=stripped\n"
    fi
else
    printf "NPMRC_AUTH=absent\n"
fi

# --- DNS still works in normal mode ---
printf "DNS=%s\n" "$(cat /etc/resolv.conf >/dev/null 2>&1 && echo ok || echo no)"
printf "_OK=1\n"
