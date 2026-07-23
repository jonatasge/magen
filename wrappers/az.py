#!/usr/bin/env python3
"""az.py — in-sandbox shim that forwards ``az`` to the host Azure CLI proxy.

Installed on PATH inside the magen sandbox as ``az``. Credentials never enter
the namespace: arguments (and optional ``--in-file`` contents) are sent over
``AZURE_CLI_PROXY_SOCK`` to ``proxies/azure_cli.py``, which runs the real CLI.

Usage (inside sandbox):
  az repos pr list --output json
  az --help
"""

import json
import os
import socket
import sys

# Unix socket path published by magen when the Azure proxy is running.
_SOCK = os.environ.get("AZURE_CLI_PROXY_SOCK", "")

# Flags whose path arguments must be read inside the sandbox and sent as content.
_FILE_FLAGS = ("--in-file",)

_MAGEN_HELP = """\
Azure CLI (sandbox mode) — only DevOps commands are permitted.

Allowed commands:
  az devops          : Organization and project operations
  az repos           : Repositories and pull requests
  az boards          : Work items and sprints
  az pipelines       : Pipeline runs and definitions
  az artifacts       : Package feeds
  az account show    : Current account info (no credentials)
  az account list    : List subscriptions
  az extension       : Manage CLI extensions
  az version         : Show CLI version
  az rest            : REST calls (only to dev.azure.com)

Use 'az <command> --help' for details on a specific command.
"""


def _is_help(args):
    """True when the user asked for help instead of a real az command."""
    return not args or args == ["--help"] or args == ["-h"] or args == ["help"]


def _collect_files(args):
    """Read local files referenced by --in-file and return their content.

    The sandbox /tmp is isolated from the host, so files created inside
    the sandbox would not be visible to the proxy. This reads them here
    and sends the content over the socket so the proxy can materialise
    them on the host side.
    """
    files = {}
    for i, arg in enumerate(args):
        for flag in _FILE_FLAGS:
            path = None
            if arg == flag and i + 1 < len(args):
                path = args[i + 1]
            elif arg.startswith(f"{flag}="):
                path = arg.split("=", 1)[1]

            if path and os.path.isfile(path):
                try:
                    with open(path, "r") as f:
                        files[flag] = f.read()
                except OSError:
                    pass
    return files


def main():
    args = sys.argv[1:]

    # Help is answered locally so we never need the proxy for discovery.
    if _is_help(args):
        sys.stdout.write(_MAGEN_HELP)
        sys.exit(0)

    if not _SOCK or not os.path.exists(_SOCK):
        print("az: not available inside sandbox (proxy not running)", file=sys.stderr)
        sys.exit(127)

    # Build JSON request: args always; files optional for --in-file bridging.
    files = _collect_files(args)
    request = {"args": args}
    if files:
        request["files"] = files
    payload = json.dumps(request).encode()

    # One-shot request/response over the proxy Unix socket.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(310)
        sock.connect(_SOCK)
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)

        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, OSError) as e:
        print(f"az: proxy error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        sock.close()

    try:
        resp = json.loads(buf)
    except (json.JSONDecodeError, ValueError):
        print("az: invalid proxy response", file=sys.stderr)
        sys.exit(1)

    # Relay stdout/stderr and exit code from the real az process.
    out = resp.get("stdout", "")
    err = resp.get("stderr", "")
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if err:
        sys.stderr.write(err)
        sys.stderr.flush()
    sys.exit(resp.get("exitcode", 1))


if __name__ == "__main__":
    main()
