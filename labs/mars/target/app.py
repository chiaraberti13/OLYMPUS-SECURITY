"""Mars practice target — a deliberately-vulnerable-by-design web app.

This is a **training range**, the legal target you point the working Olympus
tools at so you can practise real techniques without touching anyone else's
systems. It is intentionally weak in a few controlled, non-harmful ways:

* ``/app/search`` reflects its ``q`` parameter **unescaped** (practise
  ``olympus artemis xss``);
* a few "hidden" paths exist — ``/app/admin``, ``/app/.env``,
  ``/app/backup.zip`` (practise ``olympus artemis content``);
* it advertises a fingerprintable stack and an *affected* Metabase version at
  ``/api/session/properties`` (practise ``olympus artemis fingerprint`` and
  ``olympus artemis metabase``).

Everything it serves is **synthetic** — the "secret" is a placeholder, there
are no real credentials and no state is stored. It binds to localhost only, so
it is not reachable off the machine. Run it with::

    python labs/mars/target/app.py            # http://127.0.0.1:8081

then aim the Olympus tools at it using ``practice-scope.json`` in this folder.
"""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# Defaults to loopback so the range is never reachable off the host. Docker sets
# MARS_BIND_HOST=0.0.0.0 inside the container while the compose port mapping
# still restricts host exposure to 127.0.0.1.
BIND_HOST = os.environ.get("MARS_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.environ.get("MARS_BIND_PORT", "8081"))

# Synthetic, non-harmful "hidden" resources for content-discovery practice.
_HIDDEN: dict[str, tuple[str, bytes]] = {
    "/app/admin": ("text/html", b"<h1>Admin console (synthetic practice target)</h1>"),
    "/app/.env": ("text/plain", b"APP_ENV=demo\nSECRET_KEY=synthetic-demo-not-a-real-secret\n"),
    "/app/backup.zip": ("application/zip", b"PK\x03\x04 synthetic placeholder, not a real archive"),
}

_ROBOTS = b"User-agent: *\nDisallow: /app/admin\nDisallow: /app/backup.zip\n"

# An intentionally *affected* Metabase version tag (CVE-2026-72898 practice).
_METABASE_PROPERTIES = b'{"version": {"tag": "v0.60.10"}, "engine": "demo"}'

_LANDING = (
    b"<!doctype html><title>Olympus Demo Corp</title>"
    b"<h1>Olympus Demo Corp - practice target</h1>"
    b"<p>Synthetic, vulnerable-by-design range. Try <code>/app/search?q=hello</code>.</p>"
)


def build_response(path: str, query_string: str) -> tuple[int, str, bytes]:
    """Route one GET request to a (status, content_type, body) triple.

    Pure and side-effect free so the routing logic is easy to reason about and
    the deliberate weaknesses are all visible in one place.
    """
    if path == "/":
        return 200, "text/html", _LANDING
    if path == "/robots.txt":
        return 200, "text/plain", _ROBOTS
    if path == "/api/session/properties":
        return 200, "application/json", _METABASE_PROPERTIES
    if path == "/app/search":
        query = parse_qs(query_string)
        term = query.get("q", [""])[0]
        # DELIBERATE: reflects the parameter unescaped so a reflected-XSS check
        # has something real to find. Never do this in production code.
        page = f"<html><body>Results for: {term}</body></html>"
        return 200, "text/html", page.encode("utf-8")
    if path in _HIDDEN:
        content_type, body = _HIDDEN[path]
        return 200, content_type, body
    return 404, "text/plain", b"not found"


class PracticeHandler(BaseHTTPRequestHandler):
    """Serve the practice routes, advertising a fingerprintable stack."""

    server_version = "nginx/1.18.0"
    sys_version = ""

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        status, content_type, body = build_response(parts.path, parts.query)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Powered-By", "PHP/8.1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Log one line to stdout so practice sessions are observable."""
        print(f"[mars-target] {self.address_string()} {format % args}")


def main() -> None:
    """Run the practice target until interrupted."""
    server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), PracticeHandler)
    print(f"[mars-target] listening on http://{BIND_HOST}:{BIND_PORT} (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[mars-target] shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
