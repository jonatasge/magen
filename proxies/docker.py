#!/usr/bin/env python3
"""docker.py — Docker Engine API filtering proxy for magen.

Intercepts Docker API calls on a Unix socket and blocks container
configurations that would escape the sandbox (privileged mode, host
namespaces, denied bind mounts, etc.). Injects registry auth for pulls
from the host Docker config without exposing credentials inside magen.

Runs outside the bwrap/sandbox-exec namespace. Non-mutating/pass-through
requests are forwarded without inspection.

Usage:
  docker.py --proxy-socket PATH --target-socket PATH [--deny PATH]... [--verbose]
"""

import argparse
import base64
import json
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from log import make_logger, session_log as _session_log

BUFFER_SIZE = 65536
MAX_HEADER_SIZE = 256 * 1024  # 256 KB — reject abnormally large header blocks
MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB — prevents OOM from oversized requests
MAX_CONCURRENT_CONNECTIONS = 64

# Capabilities that grant root-equivalent or sandbox-bypassing access.
BLOCKED_CAPABILITIES = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
    }
)

_log = make_logger("docker-proxy")

# ---------------------------------------------------------------------------
# Docker registry auth resolution (analogous to npm-registry-proxy)
# ---------------------------------------------------------------------------

_DOCKERHUB_KEYS = frozenset({
    "docker.io",
    "index.docker.io",
    "registry-1.docker.io",
    "https://index.docker.io/v1/",
    "https://index.docker.io/v1",
})


def _extract_registry(image_ref):
    """Extract registry hostname from a Docker image reference."""
    if not image_ref:
        return "docker.io"
    first = image_ref.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    return "docker.io"


def _registry_match(config_key, registry):
    """Check if a Docker config auth key matches a registry."""
    k = config_key.rstrip("/")
    r = registry.rstrip("/")
    if k == r:
        return True
    for prefix in ("https://", "http://"):
        if k.startswith(prefix) and k[len(prefix):].rstrip("/") == r:
            return True
    if r in _DOCKERHUB_KEYS or r == "docker.io":
        return k in _DOCKERHUB_KEYS
    return False


def _run_cred_helper(helper, registry):
    """Run docker-credential-<helper> get. Returns (user, secret) or None."""
    try:
        p = subprocess.run(
            [f"docker-credential-{helper}", "get"],
            input=registry,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if p.returncode != 0:
            return None
        data = json.loads(p.stdout)
        return data.get("Username", ""), data.get("Secret", "")
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return None


def _make_auth_header(username, password, registry):
    """Build base64-encoded X-Registry-Auth JSON."""
    obj = {
        "username": username,
        "password": password,
        "serveraddress": f"https://{registry}",
    }
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()


def resolve_registry_auth(registry, config_path):
    """Resolve Docker registry credentials from the host config.

    Checks credHelpers → credsStore → auths (same order as Docker CLI).
    Re-reads config on every call so refreshed tokens (e.g. az acr login)
    are picked up without restarting the proxy.

    Returns base64-encoded X-Registry-Auth value, or None.
    """
    if not config_path or not os.path.isfile(config_path):
        return None
    try:
        with open(config_path) as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    for key, helper in (config.get("credHelpers") or {}).items():
        if _registry_match(key, registry):
            cred = _run_cred_helper(helper, registry)
            if cred and cred[1]:
                return _make_auth_header(cred[0], cred[1], registry)
            break

    creds_store = config.get("credsStore")
    if creds_store:
        cred = _run_cred_helper(creds_store, registry)
        if cred and cred[1]:
            return _make_auth_header(cred[0], cred[1], registry)

    for key, entry in (config.get("auths") or {}).items():
        if not _registry_match(key, registry):
            continue
        auth_b64 = entry.get("auth", "")
        if auth_b64:
            try:
                decoded = base64.b64decode(auth_b64).decode()
                user, passwd = decoded.split(":", 1)
                return _make_auth_header(user, passwd, registry)
            except Exception:
                pass
        if entry.get("identitytoken"):
            obj = {
                "identitytoken": entry["identitytoken"],
                "serveraddress": f"https://{registry}",
            }
            return base64.urlsafe_b64encode(
                json.dumps(obj).encode()
            ).decode()

    return None


def _inject_header(hdr_bytes, name, value):
    """Inject or replace an HTTP header in raw request bytes."""
    end = hdr_bytes.rfind(b"\r\n\r\n")
    if end < 0:
        return hdr_bytes
    lines = hdr_bytes[:end].split(b"\r\n")
    name_lower = name.lower().encode()
    filtered = [
        ln for ln in lines if not ln.lower().startswith(name_lower + b":")
    ]
    filtered.append(f"{name}: {value}".encode())
    return b"\r\n".join(filtered) + b"\r\n\r\n"


# ---------------------------------------------------------------------------
# Bind-mount / capability validation
# ---------------------------------------------------------------------------


def _is_path_denied(host_path, denied_paths, docker_socket_real):
    """Check if a host path would expose any protected directory.

    Catches both direct access (path inside a denied dir) and indirect
    access (path is an ancestor that would expose a denied dir).
    """
    try:
        real = os.path.realpath(os.path.expanduser(host_path))
    except (ValueError, OSError):
        return True, "invalid path"

    if real == docker_socket_real:
        return True, "docker socket (privilege escalation)"

    real_prefix = real if real.endswith("/") else real + "/"
    for denied in denied_paths:
        if real == denied or real.startswith(denied + "/"):
            return True, f"inside protected path {denied}"
        if denied.startswith(real_prefix):
            return True, f"would expose protected path {denied}"

    return False, None


def _parse_json_body(body):
    """Parse JSON body, returning (data, error). Returns ({}, None) on empty body."""
    try:
        return json.loads(body or b"{}"), None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, "invalid JSON body"


def _validate_container_create(body, denied_paths, docker_socket_real):
    """Validate POST /containers/create. Returns (allowed, reason)."""
    data, err = _parse_json_body(body)
    if err:
        return False, err
    if not isinstance(data, dict):
        return False, "container create payload must be a JSON object"

    hc = data.get("HostConfig") or {}
    if not isinstance(hc, dict):
        return False, "HostConfig must be a JSON object"

    if hc.get("Privileged"):
        return False, "--privileged is blocked"

    for key, flag in (
        ("PidMode", "--pid"),
        ("IpcMode", "--ipc"),
        ("NetworkMode", "--network"),
        ("UsernsMode", "--userns"),
    ):
        if hc.get(key) == "host":
            return False, f"{flag}=host is blocked"

    cap_add = hc.get("CapAdd") or []
    if not isinstance(cap_add, list):
        return False, "CapAdd must be an array"
    for cap in cap_add:
        if not isinstance(cap, str):
            return False, "CapAdd must only contain strings"
    cap_add = {c.upper().removeprefix("CAP_") for c in cap_add}
    blocked = cap_add & BLOCKED_CAPABILITIES
    if blocked:
        return False, f"blocked capabilities: {', '.join(sorted(blocked))}"

    if hc.get("Devices"):
        return False, "device mappings are blocked"

    security_opts = hc.get("SecurityOpt") or []
    if not isinstance(security_opts, list):
        return False, "SecurityOpt must be an array"
    for opt in security_opts:
        if not isinstance(opt, str):
            return False, "SecurityOpt must only contain strings"
        opt_lower = opt.lower()
        if "unconfined" in opt_lower or "disabled" in opt_lower:
            return False, f"security option '{opt}' is blocked"

    if hc.get("Sysctls"):
        return False, "sysctls are blocked"

    if hc.get("CgroupParent"):
        return False, "custom CgroupParent is blocked"

    if hc.get("GroupAdd"):
        return False, "GroupAdd is blocked"

    runtime = hc.get("Runtime", "")
    if runtime and runtime not in ("", "runc", "io.containerd.runc.v2"):
        return False, f"custom runtime '{runtime}' is blocked"

    restart = (hc.get("RestartPolicy") or {}).get("Name", "")
    if restart in ("always", "unless-stopped"):
        return False, f"RestartPolicy '{restart}' is blocked (container would persist after sandbox exit)"

    # HostConfig.Binds: "host:container[:opts]"
    binds = hc.get("Binds") or []
    if not isinstance(binds, list):
        return False, "Binds must be an array"
    for bind_str in binds:
        if not isinstance(bind_str, str):
            return False, "Binds must only contain strings"
        parts = bind_str.split(":")
        if len(parts) >= 2 and parts[0].startswith("/"):
            denied, reason = _is_path_denied(parts[0], denied_paths, docker_socket_real)
            if denied:
                return False, f"bind mount {parts[0]}: {reason}"

    mounts = hc.get("Mounts") or []
    if not isinstance(mounts, list):
        return False, "Mounts must be an array"
    for mount in mounts:
        if not isinstance(mount, dict):
            return False, "Mounts must only contain objects"
        if mount.get("Type") == "bind":
            source = mount.get("Source", "")
            if source.startswith("/"):
                denied, reason = _is_path_denied(
                    source, denied_paths, docker_socket_real
                )
                if denied:
                    return False, f"mount {source}: {reason}"

    return True, None


def _validate_exec_create(body):
    """Validate POST /containers/{id}/exec. Returns (allowed, reason)."""
    data, err = _parse_json_body(body)
    if err:
        return False, err
    if not isinstance(data, dict):
        return False, "exec create payload must be a JSON object"

    if data.get("Privileged"):
        return False, "privileged exec is blocked"

    return True, None


def _validate_volume_create(body, denied_paths):
    """Validate POST /volumes/create. Returns (allowed, reason)."""
    data, err = _parse_json_body(body)
    if err:
        return False, err
    if not isinstance(data, dict):
        return False, "volume create payload must be a JSON object"

    opts = data.get("DriverOpts") or {}
    if not isinstance(opts, dict):
        return False, "DriverOpts must be an object"
    device = opts.get("device", "")
    if device and device.startswith("/"):
        denied, reason = _is_path_denied(device, denied_paths, "")
        if denied:
            return False, f"volume device {device}: {reason}"

    return True, None


def _validate_network_create(body):
    """Validate POST /networks/create. Returns (allowed, reason)."""
    data, err = _parse_json_body(body)
    if err:
        return False, err
    if not isinstance(data, dict):
        return False, "network create payload must be a JSON object"

    if data.get("Driver", "").lower() == "host":
        return False, "host network driver is blocked"

    return True, None


# ---------------------------------------------------------------------------
# HTTP helpers — minimal parsing for Docker Engine API over Unix socket
# ---------------------------------------------------------------------------


def _parse_request(raw):
    """Parse raw HTTP bytes → (method, path, headers_dict, header_end_offset)."""
    end = raw.find(b"\r\n\r\n")
    if end < 0:
        return None, None, {}, len(raw)

    text = raw[:end].decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    parts = lines[0].split(" ", 2)
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) >= 2 else ""

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return method, path, headers, end + 4


def _relay(a, b, timeout=120):
    """Bidirectional byte relay between two sockets.

    Handles half-close: when *a* (client) shuts down its write side the
    relay keeps forwarding data from *b* (upstream) until *b* also closes.
    This is required because Docker CLI calls CloseWrite() on the attach
    connection for non-interactive containers (no stdin).
    """
    pair = [a, b]
    try:
        while pair:
            rd, _, err = select.select(pair, [], pair, timeout)
            if err or not rd:
                break
            for s in rd:
                data = s.recv(BUFFER_SIZE)
                if not data:
                    if s is b:
                        return
                    pair = [b]
                    try:
                        b.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                dst = b if s is a else a
                dst.sendall(data)
    except (OSError, BrokenPipeError):
        pass


def _drain(sock):
    """Read from sock until peer closes (discards data)."""
    try:
        while True:
            if not sock.recv(BUFFER_SIZE):
                return
    except OSError:
        pass


def _http_error(status, phrase, message):
    body = json.dumps({"message": f"[sandbox] {message}"}).encode()
    hdr = (
        f"HTTP/1.1 {status} {phrase}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    return hdr + body


def _block_request(client, status, phrase, http_message, *, log_message, session_message):
    """Log to stderr and session file, send JSON error body, then caller returns."""
    _log(log_message)
    _session_log(session_message)
    client.sendall(_http_error(status, phrase, http_message))


def _inject_connection_close(hdr_bytes):
    """Replace Connection header with 'close' (skip upgrade requests)."""
    end = hdr_bytes.rfind(b"\r\n\r\n")
    if end < 0:
        return hdr_bytes
    section = hdr_bytes[:end]
    lines = section.split(b"\r\n")
    for line in lines[1:]:
        if line.lower().startswith(b"connection:") and b"upgrade" in line.lower():
            return hdr_bytes
    filtered = [line for line in lines if not line.lower().startswith(b"connection:")]
    filtered.append(b"Connection: close")
    return b"\r\n".join(filtered) + b"\r\n\r\n"


# API deny rules: (method, path predicate, stderr log, session log, JSON body for client).
# First match wins (order is intentional). Blocks image mutation, post-create container
# changes, archive I/O (exfil), swarm/plugins/secrets (cluster / host-level control).
_MAGEN_API_PATH_DENY_RULES = (
    (
        "POST",
        lambda p: "/images/" in p and p.endswith("/push"),
        "BLOCKED: image push",
        "[docker-proxy] BLOCKED: image push (read-only)",
        "image push blocked in sandbox",
    ),
    (
        "POST",
        lambda p: p.endswith("/build"),
        "BLOCKED: image build",
        "[docker-proxy] BLOCKED: image build (not allowed in sandbox)",
        "image build blocked in sandbox",
    ),
    (
        "POST",
        lambda p: "/containers/" in p and p.endswith("/update"),
        "BLOCKED: container update",
        "[docker-proxy] BLOCKED: container update",
        "container update blocked in sandbox",
    ),
    (
        "POST",
        lambda p: "/swarm/" in p,
        "BLOCKED: swarm operation",
        "[docker-proxy] BLOCKED: swarm operation",
        "swarm operations blocked in sandbox",
    ),
    (
        "POST",
        lambda p: "/plugins/" in p,
        "BLOCKED: plugins operation",
        "[docker-proxy] BLOCKED: plugins operation",
        "plugins operations blocked in sandbox",
    ),
    (
        "POST",
        lambda p: "/secrets/create" in p or "/configs/create" in p,
        "BLOCKED: secrets/configs creation",
        "[docker-proxy] BLOCKED: secrets/configs creation",
        "secrets/configs creation blocked in sandbox",
    ),
    (
        "POST",
        lambda p: p.endswith("/commit"),
        "BLOCKED: container commit",
        "[docker-proxy] BLOCKED: container commit",
        "container commit blocked in sandbox",
    ),
    (
        "PUT",
        lambda p: "/containers/" in p and p.endswith("/archive"),
        "BLOCKED: container archive upload",
        "[docker-proxy] BLOCKED: container archive upload",
        "container archive upload blocked in sandbox",
    ),
    (
        "GET",
        lambda p: "/containers/" in p and p.endswith("/archive"),
        "BLOCKED: container archive download",
        "[docker-proxy] BLOCKED: container archive download (data exfiltration risk)",
        "container archive download blocked in sandbox",
    ),
    (
        "POST",
        lambda p: p.endswith("/images/load"),
        "BLOCKED: image load",
        "[docker-proxy] BLOCKED: image load",
        "image load blocked in sandbox",
    ),
)


def _maybe_block_by_sandbox_path_rules(client, method, path_no_qs):
    """If path matches a sandbox deny rule, send 403 and return True."""
    for meth, pred, log_m, sess_m, http_m in _MAGEN_API_PATH_DENY_RULES:
        if method == meth and pred(path_no_qs):
            _block_request(
                client,
                403,
                "Forbidden",
                http_m,
                log_message=log_m,
                session_message=sess_m,
            )
            return True
    return False


# ---------------------------------------------------------------------------
# Connection handler — one upstream per request (no keep-alive forwarding)
# ---------------------------------------------------------------------------


def _read_full_request(client, buf):
    """Read one complete HTTP request (headers + body) from the client.

    Returns (method, path, headers, hdr_bytes, body, buf) on success,
    or (None, ...) if the connection should close.
    """
    while b"\r\n\r\n" not in buf:
        chunk = client.recv(BUFFER_SIZE)
        if not chunk:
            return None, None, {}, b"", b"", buf
        buf += chunk
        if len(buf) > MAX_HEADER_SIZE:
            _log(f"BLOCKED: header block exceeds {MAX_HEADER_SIZE} bytes")
            client.sendall(
                _http_error(431, "Request Header Fields Too Large", "headers too large")
            )
            return None, None, {}, b"", b"", buf

    method, path, headers, hdr_end = _parse_request(buf)
    if method is None:
        return None, None, {}, b"", b"", buf

    hdr_bytes = buf[:hdr_end]
    buf = buf[hdr_end:]

    _cl_count = sum(
        1 for ln in hdr_bytes[:hdr_bytes.find(b"\r\n\r\n")].split(b"\r\n")[1:]
        if ln.lower().startswith(b"content-length:")
    )
    if _cl_count > 1:
        client.sendall(
            _http_error(400, "Bad Request", "duplicate Content-Length (possible request smuggling)")
        )
        _drain(client)
        return None, None, {}, b"", b"", buf

    cl = int(headers.get("content-length", 0))
    if cl > MAX_BODY_SIZE:
        _log(f"BLOCKED: body too large ({cl} bytes)")
        client.sendall(
            _http_error(413, "Payload Too Large", f"body exceeds {MAX_BODY_SIZE} byte limit")
        )
        _drain(client)
        return None, None, {}, b"", b"", buf

    if cl > 0:
        while len(buf) < cl:
            chunk = client.recv(BUFFER_SIZE)
            if not chunk:
                return None, None, {}, b"", b"", buf
            buf += chunk
        body = buf[:cl]
        buf = buf[cl:]
    else:
        body = b""

    return method, path, headers, hdr_bytes, body, buf


def _validate_and_dispatch(client, method, path, headers, body, denied, docker_real, verbose):
    """Validate create/exec/volume/network requests. Returns True if blocked."""
    inspect_create = method == "POST" and path and "/containers/create" in path
    inspect_exec = (
        method == "POST"
        and path
        and "/containers/" in path
        and path.rstrip("/").endswith("/exec")
    )
    inspect_volume = method == "POST" and path and "/volumes/create" in path
    inspect_network = method == "POST" and path and "/networks/create" in path

    if not (inspect_create or inspect_exec or inspect_volume or inspect_network):
        return False

    if "chunked" in headers.get("transfer-encoding", "").lower():
        _session_log("[docker-proxy] BLOCKED: chunked encoding")
        client.sendall(
            _http_error(400, "Bad Request", "chunked encoding not supported")
        )
        return True

    if inspect_create:
        ok, reason = _validate_container_create(body, denied, docker_real)
    elif inspect_exec:
        ok, reason = _validate_exec_create(body)
    elif inspect_volume:
        ok, reason = _validate_volume_create(body, denied)
    else:
        ok, reason = _validate_network_create(body)

    if not ok:
        _block_request(
            client, 403, "Forbidden", reason,
            log_message=f"BLOCKED: {reason}",
            session_message=f"[docker-proxy] BLOCKED: {reason}",
        )
        return True

    if verbose and inspect_create:
        try:
            _hc = json.loads(body).get("HostConfig") or {}
            for _k in (
                "Binds", "Mounts", "CapAdd", "Privileged",
                "PidMode", "IpcMode", "NetworkMode", "UsernsMode",
            ):
                _v = _hc.get(_k)
                if _v:
                    _session_log(f"[docker-proxy]   {_k}={_v}")
        except Exception:
            pass

    _ops = {True: "container create"} if inspect_create else {}
    _ops.update({True: "exec"} if inspect_exec else {})
    _ops.update({True: "volume create"} if inspect_volume else {})
    _ops.update({True: "network create"} if inspect_network else {})
    _session_log(f"[docker-proxy] ALLOWED {next(iter(_ops.values()))}")
    return False


def _forward_to_upstream(client, target_path, hdr_bytes, body, method, path, docker_config, verbose):
    """Inject headers, connect to upstream Docker daemon, relay response."""
    modified_hdr = _inject_connection_close(hdr_bytes)
    if method == "POST" and path and "/images/create" in path and docker_config:
        _q = urllib.parse.urlparse(path)
        _from = urllib.parse.parse_qs(_q.query).get("fromImage", [""])[0]
        if _from:
            _reg = _extract_registry(_from)
            _auth = resolve_registry_auth(_reg, docker_config)
            if _auth:
                modified_hdr = _inject_header(modified_hdr, "X-Registry-Auth", _auth)
                _session_log(f"[docker-proxy] auth: {_reg}")
                if verbose:
                    _log(f"injected auth for {_reg}")

    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        upstream.connect(target_path)
        upstream.sendall(modified_hdr + body)

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = upstream.recv(BUFFER_SIZE)
            if not chunk:
                client.sendall(resp)
                return
            resp += chunk

        first_line = resp.split(b"\r\n", 1)[0]
        if b" 101 " in first_line:
            client.sendall(resp)
            _relay(client, upstream)
            return

        client.sendall(resp)
        while True:
            chunk = upstream.recv(BUFFER_SIZE)
            if not chunk:
                break
            client.sendall(chunk)
    finally:
        try:
            upstream.close()
        except OSError:
            pass


def _handle(client, target_path, denied, docker_real, verbose, docker_config):
    """Handle one client connection, processing requests in a loop.

    Opens a fresh upstream connection per request with Connection: close
    injected, so Docker closes after each response. This prevents HTTP
    keep-alive from letting requests bypass inspection via _relay.
    Upgrade (101) responses switch to bidirectional relay for streams.
    """
    buf = b""
    try:
        while True:
            method, path, headers, hdr_bytes, body, buf = _read_full_request(client, buf)
            if method is None:
                return

            _session_log(f"[docker-proxy] {method} {path}")
            if verbose:
                _log(f"{method} {path}")

            path_no_qs = path.split("?")[0].rstrip("/") if path else ""
            if _maybe_block_by_sandbox_path_rules(client, method, path_no_qs):
                return

            if _validate_and_dispatch(client, method, path, headers, body, denied, docker_real, verbose):
                return

            _forward_to_upstream(client, target_path, hdr_bytes, body, method, path, docker_config, verbose)

    except (OSError, BrokenPipeError):
        pass
    except Exception as e:
        _log(f"error: {e}")
        _session_log(f"[docker-proxy] ERROR: {e}")
        try:
            client.sendall(_http_error(502, "Bad Gateway", "upstream connection failed"))
        except OSError:
            pass
    finally:
        try:
            client.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


def _guarded_handle(sem, *args):
    if not sem.acquire(timeout=30):
        _log("connection dropped: too many concurrent connections")
        try:
            args[0].sendall(_http_error(503, "Service Unavailable", "too many connections"))
            args[0].close()
        except OSError:
            pass
        return
    try:
        _handle(*args)
    finally:
        sem.release()


def _serve(proxy_path, target_path, denied, verbose, docker_config):
    if os.path.exists(proxy_path):
        os.unlink(proxy_path)

    docker_real = os.path.realpath(target_path)
    denied_resolved = [os.path.realpath(os.path.expanduser(p)) for p in denied]
    _conn_sem = threading.Semaphore(MAX_CONCURRENT_CONNECTIONS)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(proxy_path)
    os.chmod(proxy_path, 0o600)
    srv.listen(16)
    srv.settimeout(1.0)

    def _shutdown(_sig, _frame):
        srv.close()
        try:
            os.unlink(proxy_path)
        except OSError:
            pass
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, _shutdown)

    _log(f"proxying {proxy_path} → {target_path}")
    _session_log(f"[docker-proxy] active: {proxy_path} → {target_path}")
    _session_log(f"[docker-proxy] denied: {' '.join(denied_resolved)}")
    if docker_config:
        _session_log(f"[docker-proxy] registry auth: {docker_config}")

    try:
        while True:
            try:
                client, _ = srv.accept()
                t = threading.Thread(
                    target=_guarded_handle,
                    args=(
                        _conn_sem, client, target_path, denied_resolved,
                        docker_real, verbose, docker_config,
                    ),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
    except OSError:
        pass
    finally:
        srv.close()
        try:
            os.unlink(proxy_path)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(
        description="Docker socket proxy for sandbox isolation"
    )
    ap.add_argument("--proxy-socket", required=True)
    ap.add_argument("--target-socket", required=True)
    ap.add_argument("--deny", action="append", default=[])
    ap.add_argument(
        "--docker-config",
        help="Path to the host ~/.docker/config.json for registry auth injection",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.target_socket):
        _log(f"target socket not found: {args.target_socket}")
        sys.exit(1)

    _serve(
        args.proxy_socket,
        args.target_socket,
        args.deny,
        args.verbose,
        args.docker_config,
    )


if __name__ == "__main__":
    main()
