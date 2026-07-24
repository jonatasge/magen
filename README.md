```
  █████     █████       ███        ▄█████████▄  █████████████ █████     █████ 
   █████   █████       █████      ███       ███  ███      ███  █████     ███  
   ██████ ██████      ███ ███     ███            ███      ███  ███ ███   ███  
   ███ █████ ███     ███   ███    ███   ███████  ███████       ███  ███  ███  
   ███  ███  ███    ███████████   ███       ███  ███      ███  ███   ███ ███  
   ███       ███   ███       ███  ███       ███  ███      ███  ███     █████  
  █████     █████ █████     █████  ▀█████████▀  █████████████ █████     █████ 
```

OS-level sandbox for AI coding agents. Isolates processes using kernel-native mechanisms so credentials, browser data, and sensitive files are never exposed — even if the agent is compromised or hallucinating destructive commands.

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Usage](#4-usage)
5. [Modes](#5-modes)
6. [Security Model](#6-security-model)
7. [Proxy Architecture](#7-proxy-architecture)
8. [Chrome MCP](#8-chrome-mcp)
9. [Session Logging](#9-session-logging)
10. [Environment Variables](#10-environment-variables)
11. [Configuration Reference](#11-configuration-reference)
12. [Testing](#12-testing)
13. [Architecture](#13-architecture)
14. [File Reference](#14-file-reference)
15. [Troubleshooting](#15-troubleshooting)
16. [FAQ](#16-faq)
17. [References](#17-references)

---

## 1. Overview

AI coding agents need filesystem and shell access to be useful, but this creates risk:

- **LLM hallucination** — Models can generate destructive commands (`rm -rf /`) by mistake.
- **Supply-chain attacks** — Compromised dependencies can execute malicious code through the agent's shell access.
- **Data exfiltration** — Without restrictions, a compromised agent could send source code or credentials to external servers.
- **Credential theft** — Agents with access to `~/.ssh`, `~/.aws`, `~/.gnupg`, or browser profiles can exfiltrate authentication material.

The sandbox follows the principle of **least privilege**: the agent gets only the access it needs, nothing more. It works on both Linux and macOS using platform-native isolation primitives — no Docker, no VMs.

| Platform | Mechanism                                                      | Isolation level                                                 |
| -------- | -------------------------------------------------------------- | --------------------------------------------------------------- |
| Linux    | [bubblewrap](https://github.com/containers/bubblewrap) (bwrap) | Kernel namespaces (UTS, PID, IPC) + bind mounts + tmpfs `$HOME` |
| macOS    | sandbox-exec (Seatbelt / SBPL)                                 | Deny-by-default syscall policy + per-path file access control   |
| Windows  | Not natively supported                                         | Use WSL2 (`wsl --install`), then run inside the Linux distro    |

---

## 2. Prerequisites

### Linux

```bash
sudo apt install bubblewrap uidmap
```

- **bubblewrap** — Provides the `bwrap` binary for user-namespace sandbox.
- **uidmap** — Provides `newuidmap`/`newgidmap` setuid helpers required for `uid_map` writes on kernels that restrict direct writes (Ubuntu 6.12+ with `apparmor_restrict_unprivileged_userns=1`).

Optional:

- **python3** — Required for Docker proxy, npm proxy, Azure CLI proxy, and Landlock helper.
- **xauth** — Required for secure X11 forwarding (untrusted cookie isolation).
- **systemd** — Required for cgroup-based resource limits (fork bomb / OOM protection).

### macOS

No additional installation required. `sandbox-exec` ships with macOS.

Optional:

- **python3** — Required for Docker proxy, npm proxy, and Azure CLI proxy.

### Chrome MCP (optional)

- **curl** — Required for health-checking headless Chrome in sandbox mode.
- **npx** (Node.js) — Required for running the `chrome-devtools-mcp` package.
- **Chrome/Chromium** — Required on Linux for the headless Chrome instance.

---

## 3. Installation

The sandbox is automatically installed by the repository's root `install.sh`. To install separately:

```bash
# Install symlinks to ~/.local/bin/
chmod +x ./install.sh
./install.sh

# Uninstall
./uninstall.sh
```

The installer:

1. Creates a `magen` symlink in `~/.local/bin/` pointing to the `magen` script.
2. Creates a `chrome-mcp` symlink in `~/.local/bin/` pointing to `mcp/chrome.sh`.
3. Checks for required system packages and prints install instructions if missing.
4. Detects AppArmor issues with Cursor's internal sandbox on recent Ubuntu kernels (provides fix command).
5. Warns if `~/.local/bin` is not in your `$PATH`.

> Make sure `~/.local/bin` is in your `$PATH`. Add to your shell profile if needed:
>
> ```bash
> export PATH="$HOME/.local/bin:$PATH"
> ```

---

## 4. Usage

### Basic usage

```bash
# Launch an interactive shell inside the sandbox
magen bash

# Launch Cursor inside the sandbox
magen cursor

# Run a specific command
magen node server.js

# Show version
magen --version
```

### Mounting additional paths

```bash
# Mount an extra path as read-only
magen --map /opt/extra-tools bash

# Mount an extra path as read-write
magen --rw-map /tmp/shared-cache bash

# Multiple mounts
magen --map /opt/libs --rw-map /tmp/builds bash
```

### Lockdown mode

```bash
# Paranoid mode: read-only project, no network, no GPU, no dotfiles, clean env
magen --lockdown bash
```

### Debugging

```bash
# See what the sandbox would do without executing
magen --dry-run bash

# Show detailed mount and configuration info
magen --verbose bash

# Combine both for full visibility
magen --dry-run --verbose bash
```

### Validation

```bash
# Run the full test suite
magen --self-test

# Run with verbose output
magen --self-test --verbose

# Categories (run in parallel workers): sandbox, agents, isolation, proxies, lockdown
magen --self-test --normal-only
magen --self-test --lockdown-only
magen --self-test --category sandbox,agents
magen --self-test --category proxies
```

### CLI reference

| Flag                | Description                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `--lockdown`        | Paranoid mode: project read-only, no network, no GPU, no dotfiles, clean env                         |
| `--allow-keychain`  | (macOS) Mount `~/Library/Keychains`. Default off; recipes sync keychain→file (see `config/agents.conf`) |
| `--map PATH`        | Mount PATH as read-only inside the sandbox                                                           |
| `--rw-map PATH`     | Mount PATH as read-write inside the sandbox                                                          |
| `--dry-run`         | Show what the sandbox would do without executing                                                     |
| `--verbose`, `-v`   | Show detailed mount and configuration info                                                           |
| `--self-test`       | Run the validation suite and exit                                                                    |
| `--version`         | Show version and exit                                                                                |
| `--help`, `-h`      | Show help message                                                                                    |

---

## 5. Modes

The sandbox operates in two modes that control the security/usability trade-off:

| Aspect                | Normal mode                         | Lockdown mode                                  |
| --------------------- | ----------------------------------- | ---------------------------------------------- |
| **Project directory** | Read-write                          | Read-only                                      |
| **Parent directory**  | Read-write (when not sensitive)     | Not mounted                                    |
| **Network**           | Allowed                             | Blocked (`--unshare-net`)                      |
| **GPU/Display**       | Auto-detected and mounted           | Disabled                                       |
| **Dotfiles**          | Selective (allowlist-based)         | None mounted                                   |
| **Environment**       | Inherited (sensitive vars stripped) | Clean (`--clearenv`, minimal PATH)             |
| **SSH agent**         | Forwarded (socket only)             | Disabled                                       |
| **Docker proxy**      | Started (filtered API access)       | Not started                                    |
| **npm proxy**         | Started (read-only, auth injected)  | Not started                                    |
| **Azure CLI proxy**   | Started (allowlisted commands)      | Not started                                    |
| **Extra maps**        | Applied (`--map`, `--rw-map`)       | Ignored (cleared on lockdown)                  |
| **Session logging**   | Active                              | Active (limited to log dir)                    |
| **Landlock**          | Applied (defense-in-depth)          | Applied (defense-in-depth)                     |
| **Cgroup limits**     | Applied (fork bomb/OOM protection)  | Applied (fork bomb/OOM protection)             |
| **PATH**              | Inherited                           | `/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin` |

### Normal mode

Default mode. The project directory is writable, dotfiles are selectively mounted, and proxies provide filtered access to Docker, npm registries, and Azure CLI. Sensitive environment variables and files are stripped/masked.

### Lockdown mode

Maximum isolation. The project is read-only, the network is blocked, environment is wiped to a minimal set, and no dotfiles are mounted. Useful for auditing untrusted code or running tests in a pristine environment.

---

## 6. Security Model

The sandbox implements **defense in depth** — multiple independent layers that each reduce risk:

### 6.1. Ephemeral `$HOME`

On Linux, `$HOME` is a `tmpfs` — a fresh in-memory filesystem created at sandbox startup. Writes to `$HOME` inside the sandbox never touch the real home directory. On macOS, a deny-default SBPL policy blocks writes to non-allowlisted paths.

Only explicitly allowlisted dotdirs are mounted back from the real `$HOME` (see [Configuration Reference](#11-configuration-reference)).

### 6.2. Credential stripping

Even for mounted dotdirs, credential files are sanitized before being exposed:

| Path                             | Treatment                                                   |
| -------------------------------- | ----------------------------------------------------------- |
| `~/.npmrc`                       | Auth tokens (`_authToken`, `_auth`, `_password`) stripped   |
| `~/.docker/config.json`          | `auths`, `credsStore`, `credHelpers` keys removed           |
| `~/.docker/*.pem`                | TLS certificates bound to `/dev/null`                       |
| `~/.azure/msal_token_cache.json` | Replaced with `{}`                                          |
| `~/.azure/accessTokens.json`     | Replaced with `{}`                                          |
| `~/.m2/settings.xml`             | Bound to `/dev/null` (may contain repo passwords)           |
| `~/.m2/settings-security.xml`    | Bound to `/dev/null`                                        |
| `~/.cargo/credentials.toml`      | Bound to `/dev/null`                                        |
| `~/.ssh/id_*`                    | Never mounted (only `config` and `known_hosts` are exposed) |
| `~/.local/share/keyrings/`       | Masked with tmpfs (GNOME keyring)                           |

### 6.3. Proxy-based auth

Credentials are _used_ but never _exposed_ inside the sandbox. Sidecar proxies run outside the sandbox namespace and inject auth headers transparently. This follows the same pattern as `ssh-agent`:

- **npm registry proxy** — Injects `Authorization` headers for `GET`/`HEAD`; blocks `PUT`/`POST`/`DELETE`/`PATCH` (no accidental publish)
- **Docker proxy** — Injects `X-Registry-Auth` for image pulls; blocks privilege escalation, dangerous mounts, and risky API endpoints
- **Azure CLI proxy** — Runs `az` commands with real MSAL cache; only DevOps commands are allowed

See [Proxy Architecture](#7-proxy-architecture) for details.

### 6.4. Sensitive file masking

Files matching dangerous patterns are bound to `/dev/null` (Linux) or blocked via SBPL regex (macOS). This applies to the project directory, parent directory, and any `--rw-map` paths:

| Pattern                   | Examples                                          |
| ------------------------- | ------------------------------------------------- |
| `*.pem`, `*.key`, `*.p12` | TLS certificates, private keys                    |
| `*.keystore`, `*.pfx`     | Java/Windows keystores                            |
| `*.p8`, `*.jks`           | Apple push keys, Java keystores                   |
| `*.asc`, `*.gpg`          | GPG encrypted/signed files                        |
| `*.kdbx`                  | KeePass databases                                 |
| `*.tfstate`               | Terraform state (contains cloud credentials)      |
| `id_rsa*`, `id_ed25519*`  | SSH private keys                                  |
| `credentials.json`        | GCP/generic credential files                      |
| `service-account*.json`   | GCP service account keys                          |
| `kubeconfig`              | Kubernetes cluster credentials                    |
| `.env`, `.env.*`          | Environment files (`.local`, `.production`, etc.) |
| `.netrc`                  | Machine credentials for HTTP auth                 |

### 6.5. Landlock LSM (Linux only)

[Landlock](https://landlock.io/) provides kernel-level filesystem restrictions inside bwrap as a second layer of defense. Even if a process escapes the bind-mount isolation, Landlock prevents access to non-allowlisted paths:

- All visible top-level directories (`/usr`, `/bin`, `/lib`, etc.) get **read-only** access
- Paths passed via `--rw` (project dir, `$HOME`, `/tmp`, `/run`, `/dev`) get **full** access
- Supports ABI versions 1-4 (auto-detects kernel support)
- Falls back gracefully if the kernel does not support Landlock

### 6.6. Environment sanitization

Variables matching sensitive prefixes are stripped from the sandbox environment:

| Prefix group                          | Examples                                                      |
| ------------------------------------- | ------------------------------------------------------------- |
| Cloud providers                       | `AWS_*`, `AZURE_*`, `GCP_*`, `GOOGLE_CLOUD_*`                 |
| Source control / CI                   | `GITHUB_*`, `GITLAB_*`, `CI_*`, `CIRCLE_*`                    |
| Package registries                    | `NPM_TOKEN`, `NPM_AUTH`, `PYPI_TOKEN`, `CARGO_REGISTRY_TOKEN` |
| Docker                                | `DOCKER_*` (except build-tool vars)                           |
| Database                              | `DATABASE_*`, `DB_PASSWORD`, `DB_USER`                        |
| AI APIs                               | `OPENAI_*`, `ANTHROPIC_*`                                     |
| SaaS / monitoring                     | `SENTRY_*`, `DATADOG_*`, `STRIPE_*`, `SLACK_*`                |
| Generic secrets                       | `SECRET_*`, `TOKEN_*`, `PASSWORD_*`, `PRIVATE_KEY`            |
| IaC / orchestration                   | `TERRAFORM_*`, `TF_VAR_*`, `PULUMI_ACCESS_TOKEN`              |
| Build tools (passwords, not settings) | `MAVEN_*`, `GRADLE_*`, `ARTIFACTORY_*`, `NEXUS_*`             |

**Safe exceptions** — Build-tool configuration vars that match a sensitive prefix but do not contain secrets are preserved:

`DOCKER_BUILDKIT`, `DOCKER_DEFAULT_PLATFORM`, `DOCKER_SCAN_SUGGEST`, `DOCKER_CLI_COLOR`, `DOCKER_CLI_HINTS`, `DOCKER_HIDE_LEGACY_COMMANDS`, `MAVEN_OPTS`, `MAVEN_HOME`, `MAVEN_ARGS`, `MAVEN_BATCH_MODE`, `GRADLE_OPTS`, `GRADLE_HOME`, `GRADLE_USER_HOME`, `SENTRY_ENVIRONMENT`, `SENTRY_RELEASE`.

### 6.7. Docker API filtering

The Docker proxy blocks container configurations that would bypass the sandbox:

| Category              | Blocked configurations                                                                                   |
| --------------------- | -------------------------------------------------------------------------------------------------------- |
| Privilege escalation  | `--privileged`, `SYS_ADMIN`, `SYS_PTRACE`, `SYS_RAWIO`, `SYS_MODULE`, `DAC_READ_SEARCH`, `ALL`           |
| Host namespace access | `--pid=host`, `--network=host`, `--userns=host`, `--ipc=host`                                            |
| Mount bypass          | Bind mounts to denied paths, ancestor mounts that would expose denied paths, Docker socket mount         |
| Security weakening    | `apparmor=unconfined`, `seccomp=unconfined`, custom runtimes, sysctls, `CgroupParent`, `GroupAdd`        |
| Persistent containers | `RestartPolicy: always`, `RestartPolicy: unless-stopped`                                                 |
| Blocked API endpoints | Image push/build/load, container update/commit, archive upload/download, swarm, plugins, secrets/configs |
| Device access         | All device mappings                                                                                      |

### 6.8. Cgroup resource limits (Linux only)

When `systemd-run` is available, the sandbox applies resource limits via a transient user cgroup:

| Limit       | Default | Environment variable | Description                                   |
| ----------- | ------- | -------------------- | --------------------------------------------- |
| `TasksMax`  | 4096    | `MAGEN_MAX_PIDS`   | Maximum number of processes (fork bomb guard) |
| `MemoryMax` | 8G      | `MAGEN_MAX_MEM`    | Maximum memory usage (OOM protection)         |

Disable cgroup limits entirely with `MAGEN_NO_CGROUP=1`.

### 6.9. X11 security (Linux only)

When `xauth` is installed and `DISPLAY` is set, the sandbox generates an **untrusted X11 cookie** that blocks:

- Cross-window keystroke capture (XTEST extension)
- Screenshots of other windows
- Input injection to other applications

Without `xauth`, X11 access is disabled entirely rather than exposing an unprotected display.

### 6.10. Namespace isolation (Linux only)

The sandbox creates isolated namespaces:

| Namespace | Effect                                                       |
| --------- | ------------------------------------------------------------ |
| UTS       | Hostname set to `magen`                                    |
| PID       | Process ID namespace (sandbox processes can't see host PIDs) |
| IPC       | Inter-process communication isolated from host               |
| Network   | Isolated in lockdown mode (`--unshare-net`)                  |
| User      | Implicit via bubblewrap (no root inside the sandbox)         |

### 6.11. Nested sandbox detection

If `MAGEN_ACTIVE=1` is already set (indicating the process is already inside a sandbox), the hub clears any inherited session `DEBUG` trap immediately (Linux `BASH_ENV` would otherwise log every hub line into the outer session log), parses the CLI, then pass-through-execs the command without re-sandboxing. Chromium-based commands still get `--no-sandbox` so Chrome's internal sandbox does not conflict with the outer namespace.

---

## 7. Proxy Architecture

Three sidecar proxies run **outside** the sandbox namespace and provide filtered access to services that require credentials. Each proxy follows the `ssh-agent` pattern: credentials are _used_ but never _exposed_.

### 7.1. Docker proxy (`proxies/docker.py`)

Intercepts Docker Engine API calls via a Unix socket:

```text
Sandbox process → proxy socket (/tmp/magen/sandbox/docker.XXXXXX.sock)
                    → validation (block/allow)
                        → real Docker socket (/var/run/docker.sock)
```

**Features:**

- Validates `POST /containers/create` against security rules
- Validates `POST /containers/{id}/exec` (blocks privileged exec)
- Validates `POST /volumes/create` (blocks mounts to denied paths)
- Validates `POST /networks/create` (blocks host driver)
- Blocks risky API paths (push, build, commit, archive, swarm, plugins, secrets)
- Injects `X-Registry-Auth` for image pulls (reads `~/.docker/config.json`, supports credHelpers, credsStore, and auths)
- Non-create requests are passed through without inspection
- Connection: close injected per-request to prevent keep-alive bypass
- HTTP/1.1 upgrade support for streams (attach, logs)
- Concurrent connection limiting (max 64)
- Request size limits: 256 KB headers, 10 MB body

**Deny list construction:** Denied paths are derived dynamically from the dotdir config — any dotdir not in the RW or RO allowlist is added to the deny list, plus all `CONFIG_DENY` and `CACHE_DENY` entries.

### 7.2. npm registry proxy (`proxies/npm_registry.py`)

Read-only HTTP proxy that injects auth headers for npm registry requests:

```text
Sandbox process → http://127.0.0.1:<port>/package-name
                    → inject Authorization header
                        → upstream registry (e.g. https://registry.npmjs.org)
```

**Features:**

- Parses `.npmrc` files (home + project) for registry URLs and auth tokens
- Supports auth formats: `_authToken` (Bearer), `_auth` (Basic), `_password` + `username` (Azure DevOps Artifacts)
- Handles scoped registries (`@scope:registry=...`)
- Forwards only `GET`/`HEAD` — `PUT`/`POST`/`DELETE`/`PATCH` return 403 (prevents accidental `npm publish`)
- Rewrites tarball URLs in metadata responses to route downloads through the proxy (prevents npm from bypassing the proxy for tarball fetches)
- Listens on `127.0.0.1` only (not exposed to the network)
- Registry env vars (`npm_config_registry`) are written to both an env file (for bwrap `--setenv`) and injected into the sanitized `.npmrc` (for MCP child processes that don't inherit env vars)
- Response size limit: 50 MB

### 7.3. Azure CLI proxy (`proxies/azure_cli.py`)

Executes `az` commands outside the sandbox with real MSAL credentials:

```text
Sandbox process → az wrapper (wrappers/az.py)
                    → Unix socket (/tmp/magen/sandbox/azure.XXXXXX.sock)
                        → proxy validates command
                            → real `az` CLI
```

**Security model:** Allowlist-only. Only Azure DevOps commands needed by developers are permitted:

| Allowed commands             | Description                                                 |
| ---------------------------- | ----------------------------------------------------------- |
| `az devops`                  | Organization and project operations                         |
| `az repos`                   | Repositories and pull requests                              |
| `az boards`                  | Work items and sprints                                      |
| `az pipelines`               | Pipeline runs and definitions                               |
| `az artifacts`               | Package feeds                                               |
| `az account show`            | Current account info (no credentials)                       |
| `az account list`            | List subscriptions                                          |
| `az extension`               | Manage CLI extensions                                       |
| `az version`                 | CLI version                                                 |
| `az rest --uri <DevOps URL>` | REST calls (only to `dev.azure.com` and related subdomains) |

**Denied by default:** All cloud resource commands (`vm`, `group`, `storage`, `keyvault`, etc.) and credential-exposing commands (`account get-access-token`, `login`).

**File transfer:** When the command includes `--in-file`, the wrapper reads the file inside the sandbox and sends its content over the socket. The proxy materializes it in a host temp file and replaces the path in the args — bridging the sandbox `/tmp` isolation.

**Protocol:** Newline-delimited JSON over Unix socket:

```json
// Request
{"args": ["repos", "pr", "list", "--output", "json"]}

// Response
{"exitcode": 0, "stdout": "...", "stderr": "..."}

// With file transfer
{"args": ["devops", "invoke", "--in-file", "/tmp/x.json"],
 "files": {"--in-file": "{\"name\":\"Tag\"}"}}
```

---

## 8. Chrome MCP

The `mcp/chrome.sh` wrapper enables the [Chrome DevTools MCP](https://www.npmjs.com/package/chrome-devtools-mcp) server inside bwrap sandboxes.

### Problem

Inside a bwrap user namespace, Chrome's SUID sandbox is disabled (the setuid bit is ignored). Launching Chrome normally causes a crash.

### Solution

On Linux inside a sandbox, the wrapper:

1. Starts a headless Chrome with `--no-sandbox --disable-gpu --disable-dev-shm-usage`
2. Allocates a debugging port (default: 9222, with fallback range of +100 ports)
3. Connects the MCP server to Chrome via `--browserUrl`
4. Manages Chrome lifecycle (PID lock files, cleanup on exit, orphan detection)

On macOS, `sandbox-exec` does not use user namespaces, so Chrome's internal sandbox works normally — the wrapper falls through to the standard MCP launch.

### Detection

The wrapper detects whether it needs the workaround by:

1. Checking `MAGEN_ACTIVE=1` (explicit signal from the sandbox script)
2. Auto-detecting via `/proc/self/uid_map` — in the initial user namespace the range covers the full 32-bit range (4294967295); a smaller range means we're inside a user namespace

### Usage

```bash
# Standard usage (auto-detects sandbox)
chrome-mcp

# Custom debugging port
CHROME_MCP_PORT=9333 chrome-mcp

# Custom MCP package version
CHROME_MCP_VERSION=0.21.0 chrome-mcp
```

### Environment variables

| Variable             | Default | Description                                  |
| -------------------- | ------- | -------------------------------------------- |
| `CHROME_MCP_PORT`    | 9222    | Preferred debugging port (range: 1024-65535) |
| `CHROME_MCP_VERSION` | 0.20.1  | Override MCP package version                 |
| `MAGEN_ACTIVE`     | -       | Set by the sandbox; used as explicit signal  |

---

## 9. Session Logging

Every sandbox session creates a log file under `~/.local/state/magen/sandbox/logs/`. Logs older than 7 days are automatically pruned.

### What is logged

- **Session header** — timestamp, mode, project path, command, RW/RO dirs, masked configs/caches, proxy status
- **Commands** — Every command executed in the shell (via `DEBUG` trap in bash), with timestamp and working directory
- **Exit codes** — Non-zero exit codes with timestamps
- **Stderr capture** — On failed commands, the last 50 lines of stderr (ANSI-stripped) are flushed to the log
- **Proxy activity** — Docker API requests (allowed/blocked), npm registry requests, Azure CLI commands

### FIFO architecture

The session log uses a FIFO (named pipe) to ensure **append-only** access from inside the sandbox:

```text
Sandbox process → writes to /tmp/magen/sandbox/session-log (FIFO)
                    → cat reader (outside sandbox) → appends to ~/.local/state/magen/sandbox/logs/<timestamp>.log
```

This prevents a compromised process inside the sandbox from truncating or rewriting prior log entries.

### Command logging integration

A custom `.bashrc` wrapper is injected into the sandbox that:

1. Sources the original `.bashrc` (as `.bashrc.orig`)
2. Sets a `DEBUG` trap to log every command with timestamp and working directory
3. Chains with other `DEBUG` traps (e.g., Cursor/VSCode shell integration) without breaking them via `PROMPT_COMMAND` re-chaining
4. Captures stderr via `tee` to a buffer file for non-zero exit code logging
5. Flushes unflushed stderr on shell `EXIT` (covers `Ctrl+D` / close terminal before `PROMPT_COMMAND` fires)

Non-interactive commands (e.g., `magen node server.js`) also get logging via `BASH_ENV` pointing to the command logger script.

---

## 10. Environment Variables

### Variables set by the sandbox

| Variable                         | Value                         | Description                                                |
| -------------------------------- | ----------------------------- | ---------------------------------------------------------- |
| `MAGEN_ACTIVE`                 | `1`                           | Indicates the process is inside a sandbox                  |
| `MAGEN_MODE`                   | `normal` / `lockdown`         | Current sandbox mode                                       |
| `MAGEN_HOSTNAME`               | Real hostname                 | The original hostname (before UTS namespace change)        |
| `MAGEN_SESSION_LOG`            | Path to FIFO or file          | Session log target for command/error logging               |
| `BASH_ENV`                       | `/tmp/magen/sandbox/cmd-logger.sh` | Auto-sources the command logger for non-interactive shells |
| `DOTNET_BUNDLE_EXTRACT_BASE_DIR` | `/tmp/.dotnet-bundle-extract` | Writable dir for .NET single-file apps (e.g., Azure MCP)   |
| `AZURE_CLI_PROXY_SOCK`           | Socket path                   | Unix socket for the Azure CLI proxy                        |
| `FORCE_COLOR`                    | `1` (when TTY)                | Re-enables colors (strips IDE-injected `NO_COLOR`)         |
| `COLORTERM`                      | `truecolor` (when TTY)        | Enables 24-bit color                                       |
| `DOCKER_CLI_COLOR`               | `always` (when TTY)           | Enables Docker CLI colors                                  |

### Variables that control sandbox behavior

| Variable                  | Default | Description                                   |
| ------------------------- | ------- | --------------------------------------------- |
| `MAGEN_MAX_PIDS`        | `4096`  | Maximum processes in cgroup (fork bomb guard) |
| `MAGEN_MAX_MEM`         | `8G`    | Maximum memory in cgroup (OOM protection)     |
| `MAGEN_NO_CGROUP`       | `0`     | Set to `1` to disable cgroup limits entirely  |
| `MAGEN_SKIP_VALIDATION` | `0`     | Set to `1` to skip pre-flight validation      |
| `MAGEN_LOG_FILE`             | Auto    | Override session log file path                |

---

## 11. Configuration Reference

### Dotdir access control

The sandbox uses an **allowlist model**: only explicitly listed dotdirs are mounted. Everything else is blocked by default.

#### Read-write dotdirs

Mounted with full write access. These are directories that tools actively write to during development:

`.cursor`, `.config`, `.cache`, `.npm`, `.yarn`, `.mcp-auth`, `.docker`

#### Read-only dotdirs

Mounted as read-only. These are toolchains and SDKs that should be available but not modified:

`.local`, `.vscode`, `.nvm`, `.sdkman`, `.rustup`, `.cargo`, `.pyenv`, `.rbenv`, `.goenv`, `.asdf`, `.mise`, `.volta`, `.fnm`, `.jabba`, `.jenv`, `.openjfx`, `.dotnet`, `.net`, `.redhat`, `.antigravity`, `.m2`, `.azure`

#### Always denied (not in any allowlist)

Directories not in either list are never mounted, including (but not limited to):

`.gnupg`, `.aws`, `.ssh` (except `config` and `known_hosts`), `.mozilla`, `.sparrow`, `.kube`, `.password-store`, `.vault-token`, `.terraform.d`, `.pki`

Agent homes such as `.claude`, `.gemini`, `.codex` are mounted only when the matching recipe is active (see below).

### Agent / provider recipes (`config/agents.conf`)

Extensible without code changes. Overlay: `~/.config/magen/agents.conf`.

Per-command recipes add home dotdirs, env pass-through, macOS Application Support dirs, `SET_ENV`, and optional keychain→JSON exports. Interactive shells (`magen`, `magen bash`) activate **all** recipes; `magen sh -c …` / scripts do not (isolation tests keep `.claude` hidden).

Built-in recipes (docs-verified only): Cursor (`agent`), Claude Code (`claude`), Codex (`codex`), Gemini CLI (`gemini`), GitHub Copilot CLI (`copilot`), xAI Grok Build (`grok`), Kimi Code CLI (`kimi`), OpenCode (`opencode`), OpenClaw (`openclaw`), Hermes Agent (`hermes`), Aider (`aider`), Continue CLI (`cn`).

API keys listed in `GLOBAL_PASS_ENV` / `PASS_ENV` survive env sanitization; other secrets matching sensitive prefixes are still stripped. Add unverified tools via `~/.config/magen/agents.conf`.

### Config deny list

Subdirectories of `~/.config/` that are masked with tmpfs (Linux) or denied (macOS), even though `.config` itself is RW:

`BraveSoftware`, `Bitwarden`, `google-chrome`, `chromium`, `gh`, `gcloud`, `helm`

### Cache deny list

Subdirectories of `~/.cache/` that are masked:

`BraveSoftware`, `chromium`, `google-chrome`

### macOS Library allowlists

Only these subdirectories of `~/Library/` are writable:

- **Library:** `Caches`, `Preferences`, `Logs`, `Fonts`, `Developer`, `LaunchAgents`
- **Application Support:** `Cursor`, `Code` (plus any `APP_SUPPORT` from active agent recipes)

`~/Library/Keychains` is **not** mounted by default (high risk: would expose every keychain secret). On macOS, recipes may export specific keychain items into allowlisted files (Cursor → `~/.cursor/auth.json` + `AGENT_CLI_CREDENTIAL_STORE=file`). Use `--allow-keychain` only when an app truly needs Security.framework inside the sandbox.

### RC files (read-only)

These shell configuration files are mounted read-only if present:

`.profile`, `.bash_logout`, `.bash_aliases`, `.zshrc`, `.gitconfig`

### SSH access

| Path                 | Access     | Notes                                 |
| -------------------- | ---------- | ------------------------------------- |
| `~/.ssh/config`      | Read-only  | Needed for git SSH host configuration |
| `~/.ssh/known_hosts` | Read-only  | Needed for SSH host verification      |
| `~/.ssh/id_*`        | **Denied** | Private keys are never mounted        |
| `SSH_AUTH_SOCK`      | Forwarded  | Socket only — keys stay in the agent  |

### XDG runtime masking (Linux)

When `$XDG_RUNTIME_DIR` is mounted, these subdirectories are masked with tmpfs to limit credential and input surfaces:

`gnupg`, `keyring`, `pulse`, `pipewire`, `systemd`, `at-spi`, `speech-dispatcher`, `dconf`, `doc`, `gvfs`, `gvfsd`

Sockets `bus` and `pipewire-0` are bound to `/dev/null`.

---

## 12. Testing

The test suite validates sandbox isolation end-to-end. It runs commands inside real sandboxes and asserts that protections work correctly.

### Running tests

```bash
# Run all tests
magen --self-test

# Verbose output (shows commands, stdout, stderr, exit codes)
magen --self-test --verbose

# Only normal mode tests
magen --self-test --normal-only

# Only lockdown mode tests
magen --self-test --lockdown-only
```

### Test suites

| Suite                                  | What it validates                                                                                                            |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| **Version**                            | `--version` outputs valid semver                                                                                             |
| **Normal Mode — Project access**       | Read/write to project dir, system tools, git availability                                                                    |
| **Normal Mode — Filesystem isolation** | Ephemeral `$HOME`, `/tmp` isolation, dotdir deny, SSH keys, browser profiles, XDG masking, Docker/Azure credential stripping |
| **Normal Mode — Environment**          | `MAGEN_ACTIVE`, hostname, secret env var stripping, DNS                                                                    |
| **Normal Mode — Sensitive files**      | Pattern-based file masking (18 patterns), normal files still readable                                                        |
| **Normal Mode — Session logging**      | Log file creation, EXIT trap stderr flush, exit code logging                                                                 |
| **Home Directory Isolation**           | Projects under `$HOME` still get tmpfs isolation                                                                             |
| **GUI / Background Mode**              | Chromium `--no-sandbox`, `--die-with-parent` exclusion, macOS IOKit                                                          |
| **Docker Proxy — Basic**               | Safe container/volume/network creates, passthrough requests                                                                  |
| **Docker Proxy — Security**            | Privilege, mounts, namespaces, restart policies, blocked APIs                                                                |
| **Docker Proxy — Advanced**            | Non-privileged exec, registry auth injection                                                                                 |
| **npm Registry Proxy**                 | Auth injection on GET, PUT/POST/DELETE/PATCH blocked, env file                                                               |
| **Azure CLI Proxy**                    | DevOps commands allowed, credentials denied, REST URL filtering, file transfer, error handling                               |
| **Lockdown Mode**                      | Read-only project, minimal PATH, env isolation, network blocking                                                             |

### Test architecture

- Docker, npm, and Azure proxy tests run in a **parallel background subshell** to reduce wall-clock time
- Sandbox tests (filesystem, env, sensitive files) run sequentially in the foreground
- A single "batch" sandbox invocation is used for normal mode tests to minimize expensive `bwrap` launches
- Each test uses `pass()`, `fail()`, or `skip()` with descriptive messages
- Results are aggregated with suite-level pass/fail and timing

---

## 13. Architecture

### Startup flow

```text
1. If MAGEN_ACTIVE=1: clear inherited DEBUG trap (avoids session-log noise)
2. Parse CLI arguments (--lockdown, --map, --dry-run, --verbose, etc.)
3. If MAGEN_ACTIVE=1: Chromium/Snap flags if needed, then exec (no re-sandbox)
4. Source lib/chromium.sh (Chromium binary resolution) + Snap resolve
5. Source lib/config.sh (access control lists, helpers)
6. Source lib/proxies.sh (proxy lifecycle functions)
7. Start ssh-agent if needed
8. Detect git worktree (mount main .git dir if linked worktree)
9. Set up session log (FIFO + external cat reader)
10. Run pre-flight validation (magen --self-test subset)
11. Start proxies (npm, Docker, Azure CLI)
12. Source lib/linux.sh or lib/macos.sh and call magen_linux() / magen_macos()
```

### Linux sandbox assembly (bwrap)

```text
_bwrap_system_mounts()        → OS tree, /dev, /proc, GPU, /dev/shm
_bwrap_env_and_session()      → Strip sensitive env, enable colors, select Landlock
_bwrap_runtime_and_network()  → IDE sockets, D-Bus, Docker/Azure proxy, DNS, X11, XDG, SSH
_bwrap_dotdirs()              → Mount allowed dotdirs (RW/RO from allowlists)
_bwrap_credential_sanitization() → Strip secrets from npmrc, docker, azure, maven, cargo, ssh
_bwrap_ancestors()            → Walk project→root, bind-mount each ancestor
_bwrap_home_and_project()     → tmpfs $HOME, dotdirs, creds, ancestors, project mount, sensitive masks
_bwrap_execute()              → Namespaces, session log, Landlock, cgroup, exec
```

### macOS sandbox assembly (SBPL)

```text
_sbpl_build_profile()  → Deny-default SBPL, system paths, project, dotdirs, Library, deny rules
_macos_prep_env()      → Strip env, inject proxy vars, sanitize docker/npm configs, BASH_ENV logger
_macos_execute()       → Write session header, exec sandbox-exec with profile
```

### Chromium/GUI handling

Chromium-based applications (Cursor, VS Code, Chrome) need special handling:

1. **Binary resolution** — `find_chromium_binary()` skips wrapper scripts and finds the real Electron binary
2. **Snap apps** — `resolve_snap_binary()` bypasses snap-confine by resolving the real binary inside `/snap/`
3. **`--no-sandbox` injection** — Chrome's SUID sandbox can't nest inside bwrap's PID namespace
4. **`--die-with-parent` exclusion** — GUI apps run in the background; `--die-with-parent` would kill them when the launcher exits
5. **Wrapper scripts** — `create_chromium_wrappers()` creates shim scripts for all detected Chromium-based binaries, prepended to PATH
6. **X11 untrusted cookies** — Prevents keystroke capture and screenshots between windows

### Git worktree support

When the project is a git linked worktree, the main `.git` directory (which may be outside the project tree) is detected via `git rev-parse --git-dir --git-common-dir` and mounted read-write to ensure git operations work correctly.

### Parent directory handling

The parent directory of the project is mounted read-write **unless** it is sensitive (is or contains `$HOME`). In that case, it's mounted read-only or skipped to preserve the ephemeral `$HOME` isolation.

---

## 14. File Reference

```text
.
├── magen                    # Hub entrypoint (CLI + OS dispatch)
├── install.sh               # Installer (symlinks to ~/.local/bin)
├── uninstall.sh             # Removes symlinks and PATH blocks
├── VERSION                  # Semver version file
├── config/
│   └── agents.conf          # AI agent / provider recipes (env, homes, keychain)
├── lib/                     # Sourced helpers (not run directly)
│   ├── config.sh            # Access control lists and shared helpers
│   ├── agents.sh            # Loads agents.conf; extends allowlists / auth
│   ├── proxies.sh           # Proxy lifecycle (Docker, npm, Azure CLI)
│   ├── chromium.sh          # Chromium/Electron binary resolution
│   ├── linux.sh             # Linux backend (bubblewrap)
│   ├── macos.sh             # macOS backend (sandbox-exec)
│   ├── landlock.py          # Kernel-level FS restrictions (Linux)
│   └── log.py               # Shared session logging utilities
├── proxies/                 # Sidecar proxies (run outside the sandbox)
│   ├── docker.py            # Docker Engine API filtering proxy
│   ├── npm_registry.py      # npm registry auth-injecting proxy
│   └── azure_cli.py         # Azure CLI command proxy (allowlist)
├── wrappers/                # Shims installed inside the sandbox
│   └── az.py                # `az` → azure_cli proxy
├── mcp/
│   └── chrome.sh            # Chrome DevTools MCP wrapper
└── tests/
    ├── test.sh              # Integration test suite
    └── batch_linux.sh       # Batch assertions for Linux tests
```

### Top-level scripts

| File            | Type | Description                                                                                                                                                                      |
| --------------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `magen`       | bash | Hub entrypoint. Parses CLI, starts proxies, sources `lib/linux.sh` or `lib/macos.sh`, manages session logging.                                                                               |
| `install.sh`    | bash | Creates `magen` and `chrome-mcp` symlinks under `~/.local/bin/`. Checks for required packages, detects AppArmor issues. Supports `--uninstall`.                                |
| `uninstall.sh`  | bash | Removes `magen`/`chrome-mcp` symlinks and PATH blocks.                                                                                                                         |
| `VERSION`       | text | Semver version string. Read by `magen` for banner and `--version`.                                                                                                             |

### Modules

| File                      | Type   | Description                                                                                                                                                                                                                                                                                                |
| ------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib/config.sh`           | bash   | Central configuration: dotdir allowlists (RW/RO), deny lists (config/cache), macOS Library allowlists, sensitive env prefixes, sensitive file patterns (dual glob+regex format), safe env exceptions, helper functions (`is_rw`, `is_allowed_ro`, `_is_env_safe`, `_sanitize_docker_config`).              |
| `lib/agents.sh`           | bash   | Config-driven agent recipes: loads `config/agents.conf` (+ user overlay), extends dotdirs/`PASS_ENV`/`SET_ENV`/App Support, materializes keychain→JSON on macOS.                                                                                                                                              |
| `config/agents.conf`      | text   | Docs-verified recipes for AI CLIs (Cursor, Claude, Codex, Gemini, Copilot, Grok, Kimi, OpenCode, OpenClaw, Hermes, Aider, Continue).                                                                                                                                                                         |
| `lib/proxies.sh`          | bash   | Sidecar proxy lifecycle: start/stop for Docker proxy, npm registry proxy, Azure CLI proxy. SSH agent management. Shared helpers `_wait_sidecar_ready()` and `_cleanup_sidecar()`.                                                                                                                          |
| `lib/chromium.sh`         | bash   | Chromium/Electron binary resolution: `resolve_snap_binary()`, `find_chromium_binary()`, `is_chromium_based()` (detects via `*_crashpad_handler`), `resolve_macos_electron()`, `create_chromium_wrappers()` (creates `--no-sandbox` shims for all detected Chromium binaries).                              |
| `lib/linux.sh`            | bash   | Linux backend: bubblewrap mounts, Landlock, cgroups, X11, session integration. Defines `magen_linux()`.                                                                                                                                                                                                     |
| `lib/macos.sh`            | bash   | macOS backend: Seatbelt/SBPL profile generation and `sandbox-exec`. Defines `magen_macos()`.                                                                                                                                                                                                                |
| `lib/landlock.py`         | python | Linux Landlock LSM enforcement. Makes all top-level dirs read-only, grants full access to specified paths. Supports ABI v1-v4. Falls back gracefully on unsupported kernels/architectures.                                                                                                                 |
| `lib/log.py`              | python | Shared session logging utilities. `session_log(msg)` appends to `$MAGEN_SESSION_LOG`. `make_logger(prefix)` returns a stderr logger function. Used by all Python sidecar processes.                                                                                                                      |
| `proxies/docker.py`       | python | Docker Engine API filtering proxy. Validates container creation against security rules, blocks risky API paths, injects registry auth for pulls, handles HTTP/1.1 upgrade for streams. Threaded with concurrent connection limiting.                                                                       |
| `proxies/npm_registry.py` | python | Read-only npm registry proxy. Parses `.npmrc` (Bearer, Basic, Azure DevOps formats), injects auth headers on GET/HEAD, blocks writes, rewrites tarball URLs to force routing through proxy.                                                                                                                |
| `proxies/azure_cli.py`    | python | Azure CLI command proxy. Allowlist-only security model for DevOps commands. Handles file transfer (`--in-file`) by materializing files on the host side. JSON-over-Unix-socket protocol.                                                                                                                   |
| `wrappers/az.py`          | python | Thin `az` CLI shim installed inside the sandbox. Forwards commands to `proxies/azure_cli.py` via Unix socket. Reads `--in-file` content and sends it alongside the command. Shows help listing allowed commands.                                                                                           |
| `mcp/chrome.sh`           | bash   | Wrapper for `chrome-devtools-mcp` inside bwrap. Starts headless Chrome with `--no-sandbox`, manages port allocation, PID locks, orphan cleanup. Falls through on macOS.                                                                                                                                     |
| `tests/test.sh`           | bash   | Integration suite by category (`sandbox`, `agents`, `isolation`, `proxies`, `lockdown`). Workers run in parallel with isolated TEMP dirs. Flags: `--normal-only`, `--lockdown-only`, `--category LIST`, `--verbose`. Via `magen --self-test`.                                                              |
| `tests/batch_linux.sh`    | bash   | Batch test script that runs inside the sandbox during Linux tests. Outputs `KEY=VALUE` pairs consumed by `tests/test.sh` assertions. Checks filesystem isolation, dotdir visibility, credential stripping, sensitive file masking, environment sanitization, Docker/Azure config sanitization, XDG masking, DNS. |

---

## 15. Troubleshooting

### `Error: bubblewrap (bwrap) is not installed`

Install bubblewrap and uidmap:

```bash
sudo apt install bubblewrap uidmap
```

### `Error: sandbox validation failed`

The pre-flight validation detected an issue. Run with verbose output:

```bash
magen --self-test --verbose
```

Common causes:

- Missing `bubblewrap` or `uidmap` packages
- Kernel update changed namespace restrictions
- AppArmor blocking user namespace creation

### AppArmor blocks user namespaces (Ubuntu 24.04+)

If Cursor's internal sandbox (or bwrap) fails with namespace errors:

```bash
# Check if restriction is active
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns

# If 1, and Cursor's profile has userns commented out:
sudo sed -i 's/^\(\s*\)#userns,/\1userns,/' /etc/apparmor.d/cursor-sandbox
sudo apparmor_parser -r /etc/apparmor.d/cursor-sandbox
```

### Docker not available inside sandbox

The Docker proxy requires:

1. `python3` installed on the host
2. A Docker socket at `/run/docker.sock`, `/var/run/docker.sock`, or `~/.docker/run/docker.sock`
3. Not running in lockdown mode or validation mode

Check proxy status in verbose output:

```bash
magen --verbose bash
# Look for: docker: proxied (/var/run/docker.sock → /tmp/magen/sandbox/docker.XXXXXX.sock)
```

### npm installs fail with 401/403

The npm registry proxy requires:

1. `python3` installed on the host
2. Auth tokens present in `~/.npmrc` or project `.npmrc`

Check if the proxy started:

```bash
magen --verbose bash
# Look for: npm proxy: listening on port XXXXX
```

### Azure CLI not available inside sandbox

The Azure CLI proxy requires:

1. `python3` and `az` installed on the host
2. An active `az` login session (`az account show` must succeed)
3. Not running in lockdown or validation mode

### X11 forwarding not working

Install `xauth` for secure X11 access:

```bash
sudo apt install xauth
```

Without `xauth`, X11 is disabled entirely for security reasons.

### `.NET` MCP servers fail to start

`.NET` single-file apps need a writable directory for extraction. The sandbox sets `DOTNET_BUNDLE_EXTRACT_BASE_DIR=/tmp/.dotnet-bundle-extract` automatically. If issues persist, check that `/tmp` is writable inside the sandbox.

---

## 16. FAQ

### Can I run Docker Compose inside the sandbox?

Yes. Docker Compose uses the Docker Engine API, which is proxied through `proxies/docker.py`. Container creation is validated against the security rules. Note that `--privileged` containers and host namespace access will be blocked.

### Can I use git inside the sandbox?

Yes. Git is available as a read-only system tool. The project directory is writable (in normal mode), so `git commit`, `git push`, etc. work normally. SSH agent is forwarded (socket only, never keys), and `.gitconfig` is mounted read-only.

### Can I run multiple sandbox instances?

Yes. Each instance creates its own tmpfs `$HOME`, proxy sockets, and session log. Port conflicts for Chrome MCP are handled automatically (fallback range of +100 ports).

### Does the sandbox affect performance?

Minimal impact. Bubblewrap uses kernel namespaces (near-zero overhead), not virtualization. The only measurable overhead comes from:

- Proxy latency for Docker/npm/Azure CLI operations (milliseconds per request)
- Landlock syscall filtering (negligible)
- Cgroup monitoring (negligible)

### Can I access cloud services (AWS, GCP, Azure) from the sandbox?

Network is fully open in normal mode, so HTTP/HTTPS requests work. However, cloud CLI credentials are stripped from the environment. For Azure CLI specifically, use the built-in proxy (DevOps commands only). For AWS/GCP, you would need to re-authenticate inside the sandbox or use a custom proxy.

### How do I add a new dotdir to the allowlist?

For a base toolchain/tool used by every command, edit `lib/config.sh`:

- Add to `_DOTDIR_RW_LIST` for read-write access
- Add to `_DOTDIR_RO_LIST` for read-only access

For an AI agent/CLI, prefer `config/agents.conf` (or `~/.config/magen/agents.conf`) with `HOME_RW` / `PASS_ENV` / `KEYCHAIN` so access is scoped to that command.

### What happens if I create files in `$HOME` inside the sandbox?

On Linux, `$HOME` is a tmpfs — files exist only in memory and are lost when the sandbox exits. On macOS, writes to non-allowlisted paths are denied by SBPL policy.

### Can I disable specific security features?

| Feature         | How to disable                                |
| --------------- | --------------------------------------------- |
| Cgroup limits   | `MAGEN_NO_CGROUP=1`                         |
| Pre-flight test | `MAGEN_SKIP_VALIDATION=1`                   |
| All isolation   | Don't use the sandbox (run commands directly) |

Individual proxy features cannot be disabled selectively — they start automatically based on available tools and configuration.

---

## 17. References

- [Bubblewrap](https://github.com/containers/bubblewrap) — Unprivileged sandboxing tool
- [Landlock](https://landlock.io/) — Linux security module for filesystem access control
- [SBPL / Seatbelt](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) — macOS sandbox policy language
- [AkitaOnRails — AI Agents: Garantindo a Protecao do seu Sistema](https://akitaonrails.com/2026/01/10/ai-agents-garantindo-a-protecao-do-seu-sistema/) — Original article
- [AkitaOnRails — AI Jail: Sandbox para Agentes de IA](https://akitaonrails.com/2026/03/01/ai-jail-sandbox-para-agentes-de-ia-de-shell-script-a-ferramenta-real/) — Follow-up article
- [Docker Engine API](https://docs.docker.com/engine/api/) — API reference for the Docker proxy
- [npm registry API](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md) — API reference for the npm proxy
- [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/) — Protocol used by Chrome MCP
