#!/usr/bin/env python3
"""landlock.py — Linux Landlock LSM enforcement inside bwrap.

Defense-in-depth filesystem policy applied *after* bubblewrap mounts:
every visible top-level directory becomes read-only; paths passed via
``--rw`` keep full access. Unsupported kernels/architectures no-op.

Usage:
  landlock.py [--verbose] [--rw PATH]... -- COMMAND [ARGS...]
"""

import ctypes
import ctypes.util
import os
import platform
import struct
import sys

# Prefer sibling log.py (host lib/ or /tmp/magen/sandbox when bound).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from log import session_log as _session_log

# --- Landlock syscall ABI (same numbers on x86_64 and aarch64) ---
_NR_LANDLOCK_CREATE_RULESET = 444
_NR_LANDLOCK_ADD_RULE = 445
_NR_LANDLOCK_RESTRICT_SELF = 446

_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38

# ABI v1 access rights (bits 0-12)
_ACCESS_FS_V1 = 0x1FFF
_ACCESS_FS_REFER = 1 << 13  # ABI v2
_ACCESS_FS_TRUNCATE = 1 << 14  # ABI v3
_ACCESS_FS_IOCTL_DEV = 1 << 15  # ABI v4

_ACCESS_FS_READ = (1 << 0) | (1 << 2) | (1 << 3)  # EXECUTE | READ_FILE | READ_DIR


def _load_libc():
    """Load libc with syscall/prctl signatures for Landlock syscalls."""
    path = ctypes.util.find_library("c")
    if not path:
        return None
    lib = ctypes.CDLL(path, use_errno=True)
    lib.syscall.restype = ctypes.c_long
    lib.prctl.restype = ctypes.c_int
    lib.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    return lib


def _syscall(libc, nr, *args):
    """Invoke a raw Linux syscall by number."""
    c_args = [ctypes.c_long(a) if isinstance(a, int) else a for a in args]
    return libc.syscall(ctypes.c_long(nr), *c_args)


def _get_abi(libc):
    """Return the highest Landlock ABI version supported by the running kernel (0 = unsupported)."""
    ret = _syscall(libc, _NR_LANDLOCK_CREATE_RULESET, 0, 0, _LANDLOCK_CREATE_RULESET_VERSION)
    return max(ret, 0)


def _full_access(abi):
    """Build a bitmask with all filesystem access rights available for the given ABI version."""
    access = _ACCESS_FS_V1
    if abi >= 2:
        access |= _ACCESS_FS_REFER
    if abi >= 3:
        access |= _ACCESS_FS_TRUNCATE
    if abi >= 4:
        access |= _ACCESS_FS_IOCTL_DEV
    return access


def _create_ruleset(libc, handled_access):
    """Create a new Landlock ruleset fd that governs the given access rights."""
    # struct landlock_ruleset_attr { __u64 handled_access_fs; }
    attr = struct.pack("=Q", handled_access)
    buf = ctypes.create_string_buffer(attr)
    fd = _syscall(libc, _NR_LANDLOCK_CREATE_RULESET, ctypes.byref(buf), len(attr), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return fd


def _add_path(libc, ruleset_fd, path, access):
    """Add a per-path access rule to an existing ruleset. Returns False if the path can't be opened."""
    try:
        parent_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return False
    # struct landlock_path_beneath_attr { __u64 allowed_access; __s32 parent_fd; } __packed
    buf = ctypes.create_string_buffer(struct.pack("=Qi", access, parent_fd))
    ret = _syscall(
        libc,
        _NR_LANDLOCK_ADD_RULE,
        ruleset_fd,
        _LANDLOCK_RULE_PATH_BENEATH,
        ctypes.byref(buf),
        0,
    )
    os.close(parent_fd)
    if ret < 0:
        raise OSError(ctypes.get_errno(), f"{path}: {os.strerror(ctypes.get_errno())}")
    return True


def _restrict(libc, ruleset_fd):
    """Enforce the ruleset on the current process (irreversible). Requires NO_NEW_PRIVS first."""
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0:
        raise OSError(ctypes.get_errno(), "prctl(NO_NEW_PRIVS)")
    if _syscall(libc, _NR_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0) < 0:
        raise OSError(ctypes.get_errno(), "landlock_restrict_self")


def _log(msg):
    print(f"[landlock] {msg}", file=sys.stderr)


def apply_landlock(rw_paths, verbose=False):
    """Apply Landlock restrictions: all top-level dirs become read-only, except those in rw_paths.

    Skips gracefully on unsupported architectures, missing libc, or kernels without Landlock.
    """
    if platform.machine() not in ("x86_64", "aarch64"):
        _log("landlock: unsupported architecture, skipping")
        _session_log("[landlock] skipped: unsupported architecture")
        return False

    libc = _load_libc()
    if not libc:
        _log("landlock: libc not found, skipping")
        _session_log("[landlock] skipped: libc not found")
        return False

    abi = _get_abi(libc)
    if abi < 1:
        _log("landlock: not supported by kernel, skipping")
        _session_log("[landlock] skipped: not supported by kernel")
        return False

    all_access = _full_access(abi)
    ruleset_fd = _create_ruleset(libc, all_access)

    ro_paths = []
    with os.scandir("/") as entries:
        for entry in entries:
            if _add_path(libc, ruleset_fd, entry.path, _ACCESS_FS_READ):
                ro_paths.append(entry.path)
                if verbose:
                    _log(f"landlock: ro {entry.path}")

    for p in rw_paths:
        if os.path.exists(p):
            _add_path(libc, ruleset_fd, p, all_access)
            if verbose:
                _log(f"landlock: rw {p}")

    _restrict(libc, ruleset_fd)
    os.close(ruleset_fd)

    if verbose:
        _log(f"landlock: active (ABI v{abi})")

    _session_log(f"[landlock] active (ABI v{abi})")
    _session_log(f"[landlock] read-only: {' '.join(sorted(ro_paths))}")
    _session_log(f"[landlock] read-write: {' '.join(sorted(rw_paths))}")
    return True


def main():
    """Parse --rw/--verbose/--, apply Landlock if possible, then exec the command (no return on success)."""
    args = sys.argv[1:]
    verbose = False
    rw_paths = []

    i = 0
    while i < len(args):
        if args[i] == "--verbose":
            verbose = True
            i += 1
        elif args[i] == "--rw" and i + 1 < len(args):
            rw_paths.append(args[i + 1])
            i += 2
        elif args[i] == "--":
            i += 1
            break
        else:
            break

    command = args[i:]
    if not command:
        print("landlock: no command specified", file=sys.stderr)
        sys.exit(1)

    try:
        apply_landlock(rw_paths, verbose)
    except OSError as e:
        print(f"Warning: Landlock failed: {e}. Continuing without.", file=sys.stderr)

    # Replace this process with the target command (never returns on success)
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
