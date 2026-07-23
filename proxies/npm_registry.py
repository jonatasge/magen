#!/usr/bin/env python3
"""npm_registry.py — read-only npm registry proxy with host-side auth injection.

Runs outside the magen sandbox. Forwards GET/HEAD to upstream registries
while injecting Authorization from host/project ``.npmrc``. Mutating methods
(PUT/POST/DELETE/PATCH) return 403 so ``npm publish`` cannot leak or alter
packages. Tarball URLs in metadata are rewritten to keep downloads on-proxy.

Analogous to ssh-agent: credentials are used but never exposed inside magen.
"""

import argparse
import base64
import http.client
import http.server
import json
import os
import re
import signal
import ssl
import sys
import threading
import urllib.parse

_DEFAULT_UPSTREAM = "https://registry.npmjs.org"
MAX_RESPONSE_SIZE = 50 * 1024 * 1024  # 50 MB


# ---------------------------------------------------------------------------
# .npmrc parsing
# ---------------------------------------------------------------------------

def parse_npmrc(*paths):
    """Extract registry URLs and auth tokens from .npmrc files.

    Returns:
        registries: {scope_or_None: url}
            scope is lowercase (e.g. "@myorg") or None for the default.
        tokens: {url_prefix: (scheme, value)}
            url_prefix has no scheme (e.g. "pkgs.dev.azure.com/org/...").

    Supported auth formats:
        _authToken  → Bearer <token>
        _auth       → Basic <base64>
        _password + username → Basic base64(username:decode(_password))
            (Azure DevOps Artifacts format)
    """
    registries = {}
    tokens = {}
    usernames = {}
    passwords = {}

    for path in paths:
        if not path or not os.path.isfile(path):
            continue
        with open(path) as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line[0] in ("#", ";"):
                    continue
                m = re.match(r"^(@[^:]+):registry\s*=\s*(.+)$", line)
                if m:
                    registries[m.group(1).lower()] = m.group(2).strip().rstrip("/")
                    continue
                m = re.match(r"^registry\s*=\s*(.+)$", line)
                if m:
                    registries.setdefault(None, m.group(1).strip().rstrip("/"))
                    continue
                m = re.match(r"^//(.+):_authToken\s*=\s*(.+)$", line)
                if m:
                    tokens[m.group(1).strip().rstrip("/")] = (
                        "Bearer",
                        m.group(2).strip(),
                    )
                    continue
                m = re.match(r"^//(.+):_auth\s*=\s*(.+)$", line)
                if m:
                    tokens[m.group(1).strip().rstrip("/")] = (
                        "Basic",
                        m.group(2).strip(),
                    )
                    continue
                m = re.match(r"^//(.+):username\s*=\s*(.+)$", line)
                if m:
                    usernames[m.group(1).strip().rstrip("/")] = m.group(2).strip()
                    continue
                m = re.match(r"^//(.+):_password\s*=\s*(.+)$", line)
                if m:
                    passwords[m.group(1).strip().rstrip("/")] = m.group(2).strip()

    for prefix, b64_password in passwords.items():
        if prefix in tokens:
            continue
        user = usernames.get(prefix, "")
        try:
            raw_pass = base64.b64decode(b64_password).decode()
        except Exception:
            continue
        basic = base64.b64encode(f"{user}:{raw_pass}".encode()).decode()
        tokens[prefix] = ("Basic", basic)

    return registries, tokens


def _match_token(url, tokens):
    """Longest-prefix match for a registry URL against token entries."""
    parsed = urllib.parse.urlparse(url)
    key = (parsed.netloc + parsed.path).rstrip("/")
    best, best_len = None, 0
    for prefix, auth in tokens.items():
        p = prefix.rstrip("/")
        if key.startswith(p) and len(p) > best_len:
            best, best_len = auth, len(p)
    return best


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    registries = {}
    tokens = {}
    verbose = False

    def log_message(self, fmt, *args):
        if self.verbose:
            print(f"[npm-proxy] {fmt % args}", file=sys.stderr, flush=True)

    def do_GET(self):     self._forward()      # noqa: E704
    def do_HEAD(self):    self._forward()      # noqa: E704
    def do_PUT(self):     self._block()        # noqa: E704
    def do_POST(self):    self._block()        # noqa: E704
    def do_DELETE(self):  self._block()        # noqa: E704
    def do_PATCH(self):   self._block()        # noqa: E704

    def _block(self):
        body = json.dumps(
            {"error": "Blocked: sandbox npm proxy is read-only"}
        ).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self.log_message("BLOCKED %s %s", self.command, self.path)

    # -- routing ------------------------------------------------------------

    def _resolve(self):
        """Return (upstream_base_url, auth | None) for this request."""
        path = urllib.parse.unquote(self.path)
        m = re.match(r"^/(@[^/]+)(?:/|%2[Ff])", path)
        scope = m.group(1).lower() if m else None
        upstream = (
            self.registries.get(scope)
            or self.registries.get(None)
            or _DEFAULT_UPSTREAM
        )
        return upstream, _match_token(upstream, self.tokens)

    # -- forwarding ---------------------------------------------------------

    def _forward(self):
        upstream, auth = self._resolve()
        up = urllib.parse.urlparse(upstream)
        target = up.path.rstrip("/") + self.path

        self.log_message(
            "%s %s -> %s%s %s",
            self.command, self.path, up.netloc, target,
            "(auth)" if auth else "",
        )

        try:
            conn = (
                http.client.HTTPSConnection(
                    up.netloc,
                    context=ssl.create_default_context(),
                    timeout=60,
                )
                if up.scheme == "https"
                else http.client.HTTPConnection(up.netloc, timeout=60)
            )

            hdrs = {}
            for h in (
                "Accept", "User-Agent",
                "If-None-Match", "If-Modified-Since",
            ):
                v = self.headers.get(h)
                if v:
                    hdrs[h] = v
            if auth:
                hdrs["Authorization"] = f"{auth[0]} {auth[1]}"

            conn.request(self.command, target, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read(MAX_RESPONSE_SIZE + 1)
            if len(body) > MAX_RESPONSE_SIZE:
                self.log_message("BLOCKED: response too large from %s", upstream)
                body = json.dumps({"error": "Response too large"}).encode()
                self.send_response(502)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                conn.close()
                return

            ct = resp.getheader("Content-Type") or ""
            if auth and resp.status == 200 and "json" in ct:
                body = self._rewrite_tarballs(body, upstream)

            self.send_response(resp.status)
            for h, v in resp.getheaders():
                if h.lower() in (
                    "transfer-encoding", "connection",
                    "content-length", "content-encoding",
                ):
                    continue
                self.send_header(h, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            conn.close()

        except Exception as exc:
            self.log_message("ERROR %s: %s", upstream, exc)
            body = json.dumps({"error": "Proxy error: upstream connection failed"}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # -- tarball URL rewriting ----------------------------------------------

    def _rewrite_tarballs(self, raw, upstream):
        """Replace upstream tarball URLs with proxy URLs in metadata JSON."""
        try:
            data = json.loads(raw)
            versions = data.get("versions")
            if not versions:
                return raw

            up = urllib.parse.urlparse(upstream)
            origin = f"{up.scheme}://{up.netloc}"
            up_path = up.path.rstrip("/")
            proxy = f"http://127.0.0.1:{self.server.server_address[1]}"

            changed = False
            for vdata in versions.values():
                dist = vdata.get("dist") or {}
                tb = dist.get("tarball", "")
                if not tb or origin not in tb:
                    continue
                tp = urllib.parse.urlparse(tb)
                rel = tp.path
                if up_path and rel.startswith(up_path):
                    rel = rel[len(up_path):]
                dist["tarball"] = proxy + rel
                changed = True

            if changed:
                return json.dumps(data, separators=(",", ":")).encode()
        except (json.JSONDecodeError, TypeError, KeyError):
            pass
        return raw


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class _ThreadedServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(
        description="npm registry auth proxy for sandbox environments"
    )
    ap.add_argument(
        "--npmrc", action="append", default=[],
        help=".npmrc file(s) to parse (repeatable, merged in order)",
    )
    ap.add_argument(
        "--port-file", required=True,
        help="Write the listening port number to this file",
    )
    ap.add_argument(
        "--env-file", required=True,
        help="Write env var overrides (KEY\\tVALUE per line)",
    )
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    registries, tokens = parse_npmrc(*args.npmrc)
    if not tokens:
        print(
            "[npm-proxy] no auth tokens found in npmrc files, exiting",
            file=sys.stderr,
        )
        sys.exit(1)

    _Handler.registries = registries
    _Handler.tokens = tokens
    _Handler.verbose = args.verbose

    srv = _ThreadedServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]

    with open(args.port_file, "w") as f:
        f.write(str(port))

    with open(args.env_file, "w") as f:
        f.write(f"npm_config_registry\thttp://127.0.0.1:{port}\n")
        for scope in registries:
            if scope is not None:
                f.write(f"npm_config_{scope}:registry\thttp://127.0.0.1:{port}\n")

    if args.verbose:
        print(
            f"[npm-proxy] listening on 127.0.0.1:{port}",
            file=sys.stderr, flush=True,
        )
        for scope, url in registries.items():
            a = _match_token(url, tokens)
            label = scope or "(default)"
            print(
                f"[npm-proxy]   {label} -> {url} {'(auth)' if a else ''}",
                file=sys.stderr, flush=True,
            )

    def _shutdown(*_):
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        srv.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
