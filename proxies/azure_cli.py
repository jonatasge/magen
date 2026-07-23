#!/usr/bin/env python3
"""azure_cli.py — host-side Azure CLI proxy for magen sandboxes.

Credentials stay on the host. The sandbox sends az subcommands via a Unix
socket; this process runs them with the real MSAL cache and returns only
stdout/stderr/exitcode.

Security model: allowlist-only. Only Azure DevOps developer commands are
permitted. Cloud resource management and token-exposing commands are denied.

``az rest`` is allowed only when ``--uri``/``--url`` targets Azure DevOps
hosts. Optional ``files`` in the JSON request bridge ``--in-file`` across
the sandbox /tmp boundary.

Protocol (newline-delimited JSON over Unix socket)::

    → {"args": ["repos", "pr", "list", "--output", "json"]}
    ← {"exitcode": 0, "stdout": "...", "stderr": "..."}
"""

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from log import make_logger, session_log as _session_log

_log = make_logger("azure-proxy")

MAX_REQUEST = 1024 * 1024  # 1 MB

# Allowlist: only these top-level subcommand prefixes are permitted.
# Designed for developers who work with Azure DevOps — PRs, repos,
# pipelines, boards, artifacts.  Cloud resource commands (vm, group,
# storage, network, keyvault, …) are denied by default.
_ALLOWED_PREFIXES = [
    ["devops"],       # organization/project operations
    ["repos"],        # repositories and pull requests
    ["boards"],       # work items and sprints
    ["pipelines"],    # pipeline runs and definitions
    ["artifacts"],    # package feeds
    ["account", "show"],   # current account info (no credentials)
    ["account", "list"],   # list subscriptions
    ["extension"],    # manage CLI extensions (e.g. install devops)
    ["version"],      # az --version / az version
]


_DEVOPS_URL_RE = re.compile(
    r"^https?://([a-z0-9-]+\.)?"  # optional subdomain
    r"(dev\.azure\.com|visualstudio\.com|vsaex\.dev\.azure\.com|vssps\.dev\.azure\.com)"
    r"(/|$)",
    re.IGNORECASE,
)

_FILE_FLAGS = ("--in-file",)


# --- Allowlist / request handling ---
def _is_allowed(args):
    """Return True if the az argv is in the DevOps allowlist."""
    if not args:
        return False
    for prefix in _ALLOWED_PREFIXES:
        if args[: len(prefix)] == prefix:
            return True
    if args[0] == "rest":
        return _rest_targets_devops(args)
    return False


def _rest_targets_devops(args):
    """Allow ``az rest`` only when --uri/--url points to Azure DevOps."""
    for i, arg in enumerate(args):
        if arg in ("--uri", "--url") and i + 1 < len(args):
            return bool(_DEVOPS_URL_RE.match(args[i + 1]))
        if arg.startswith("--uri=") or arg.startswith("--url="):
            return bool(_DEVOPS_URL_RE.match(arg.split("=", 1)[1]))
    return False


def _materialize_files(args, files, tmp_files):
    """Write file contents from the request to host temp files.

    For each flag in *files* (e.g. ``--in-file``), find the matching
    argument in *args* and replace the sandbox path with the host temp
    file path.  Appends created paths to *tmp_files* for cleanup.
    """
    args = list(args)
    for flag, content in files.items():
        fd, path = tempfile.mkstemp(prefix="az-proxy-", suffix=".json")
        try:
            os.write(fd, content.encode() if isinstance(content, str) else content)
        finally:
            os.close(fd)
        tmp_files.append(path)

        for i, arg in enumerate(args):
            if arg == flag and i + 1 < len(args):
                args[i + 1] = path
                break
            if arg.startswith(f"{flag}="):
                args[i] = f"{flag}={path}"
                break
    return args


def _find_az():
    for p in os.environ.get("PATH", "").split(":"):
        candidate = os.path.join(p, "az")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _handle(client, az_path, verbose, timeout):
    buf = b""
    try:
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_REQUEST:
                client.sendall(
                    json.dumps({"exitcode": 1, "stdout": "", "stderr": "az: request too large\n"}).encode()
                )
                return

        request = json.loads(buf)
        args = request.get("args", [])
        cmd_display = "az " + " ".join(args)

        if not _is_allowed(args):
            _session_log(f"[azure-proxy] DENIED: {cmd_display}")
            _log(f"DENIED: {cmd_display}")
            response = {
                "exitcode": 1,
                "stdout": "",
                "stderr": f"az {' '.join(args[:2])}: not allowed inside sandbox"
                " (only DevOps commands are permitted)\n",
            }
        else:
            _session_log(f"[azure-proxy] exec: {cmd_display}")
            if verbose:
                _log(f"exec: {cmd_display}")

            tmp_files = []
            try:
                files = request.get("files", {})
                if files:
                    args = _materialize_files(args, files, tmp_files)

                result = subprocess.run(
                    [az_path] + args,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                response = {
                    "exitcode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            except subprocess.TimeoutExpired:
                response = {"exitcode": 1, "stdout": "", "stderr": f"az: timed out after {timeout}s\n"}
            except Exception as e:
                response = {"exitcode": 1, "stdout": "", "stderr": f"az: proxy error: {e}\n"}
            finally:
                for f in tmp_files:
                    try:
                        os.unlink(f)
                    except OSError:
                        pass

        client.sendall(json.dumps(response).encode())

    except (json.JSONDecodeError, ValueError):
        try:
            client.sendall(json.dumps({"exitcode": 1, "stdout": "", "stderr": "az: invalid request\n"}).encode())
        except OSError:
            pass
    except (OSError, BrokenPipeError):
        pass
    except Exception as e:
        _log(f"error: {e}")
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description="Azure CLI proxy for sandbox")
    parser.add_argument("--socket", required=True, help="Unix socket path")
    parser.add_argument("--timeout", type=int, default=300, help="Per-command timeout (seconds)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    az_path = _find_az()
    if not az_path:
        print("[azure-proxy] az CLI not found", file=sys.stderr, flush=True)
        sys.exit(1)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(args.socket)
    except OSError:
        pass

    sock.bind(args.socket)
    os.chmod(args.socket, 0o600)
    sock.listen(8)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))

    if args.verbose:
        _log(f"listening on {args.socket} (az={az_path})")

    try:
        while True:
            client, _ = sock.accept()
            _handle(client, az_path, args.verbose, args.timeout)
    except (SystemExit, KeyboardInterrupt):
        pass
    finally:
        sock.close()
        try:
            os.unlink(args.socket)
        except OSError:
            pass


if __name__ == "__main__":
    main()
