"""Vercel serverless entry point for the BFF (DEPLOY-3).

Thin adapter between Vercel's Python runtime and the named-route forwarder in
:mod:`_bff`. It owns no logic beyond translating the HTTP request/response — all
policy (the route allowlist, https-only backend, timeout, no redirects) lives in
``_bff.forward`` and is unit-tested there. No ``olympus`` import, no subprocess:
nothing executes here, it only relays a read request to the backend.

Routing: ``vercel.json`` rewrites ``/bff/<route>`` to ``/api/bff?p=<route>``, so the
client-facing route name arrives in the ``p`` query parameter and is looked up in
``_bff.ROUTES`` (a constant backend path). The client never supplies a URL or path.
"""

from __future__ import annotations

import os
import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

# The helper module sits next to this file; make it importable in the serverless
# runtime regardless of the current working directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bff import Response, forward


class handler(BaseHTTPRequestHandler):
    def _relay(self, method: str) -> None:
        route = (parse_qs(urlsplit(self.path).query).get("p") or [""])[0]
        if not route:
            response = Response(
                400,
                (("Content-Type", "application/json"), ("X-Content-Type-Options", "nosniff")),
                b'{"error":"missing route"}',
            )
        else:
            response = forward(method, route, dict(self.headers.items()), b"", env=os.environ)
        self.send_response(response.status)
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(response.body)

    def do_GET(self) -> None:
        self._relay("GET")

    def do_HEAD(self) -> None:
        self._relay("HEAD")
