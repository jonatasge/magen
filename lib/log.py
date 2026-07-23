#!/usr/bin/env python3
"""log.py — shared session logging for magen sidecar processes.

Sidecar proxies and Landlock write audit lines to the path in
MAGEN_SESSION_LOG (FIFO or file). Failures are swallowed so logging never
breaks the caller's control flow.
"""

import os
import sys


def session_log(msg):
    """Append one line to MAGEN_SESSION_LOG when that env var is set."""
    log_path = os.environ.get("MAGEN_SESSION_LOG")
    if not log_path:
        return
    try:
        with open(log_path, "a") as f:
            f.write(f"{msg}\n")
    except OSError:
        pass


def make_logger(prefix):
    """Return a stderr logger that prefixes each line with ``[prefix]``."""

    def _log(msg):
        print(f"[{prefix}] {msg}", file=sys.stderr, flush=True)

    return _log
