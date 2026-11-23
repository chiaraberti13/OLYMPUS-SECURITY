"""Vercel serverless entry point for the BFF (DEPLOY-3).

Thin adapter between Vercel's Python runtime and the pure forwarder in
:mod:`_bff`. It owns no logic beyond translating the HTTP request/response — all
policy (allowlist, https-only backend, size/timeout limits, no redirects) lives in
``_bff.forward`` and is unit-tested there. No ``olympus`` import, no subprocess:
nothing executes here, it only relays to the backend.

Routing: ``vercel.json`` rewrites ``/bff/<path>`` to ``/api/bff?p=/<path>``, so the
target backend path arrives in the ``p`` query parameter.
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

from _bff import forward


class handler(BaseHTTPRequestHandler):
    def _relay(self, method: str) -> None:
        query = parse_qs(urlsplit(self.path).query)
        target = (query.get("p") or [""])[0]
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        if not target:
            response = _bad_request()
        else:
            response = forward(
                method,
                target,
                dict(self.headers.items()),
                body,
                env=os.environ,
            )
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

    def do_POST(self) -> None:
        self._relay("POST")


def _bad_request() -> object:
    from _bff import Response

    return Response(
        400,
        (("Content-Type", "application/json"), ("X-Content-Type-Options", "nosniff")),
        b'{"error":"missing target path"}',
    )
