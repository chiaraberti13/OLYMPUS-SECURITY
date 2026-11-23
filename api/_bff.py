"""Backend-for-frontend (BFF) core for the split deployment (DEPLOY-3).

The production control plane runs on a container **Execution backend** (DEPLOY-2);
the Vercel deployment is static (``public/``) plus thin serverless functions. This
module is that thin layer: a **pure forwarder** to the one configured backend. It
deliberately imports nothing from :mod:`olympus` and never spawns a process — **no
scanner ever runs on Vercel**; execution, authorization, scope and isolation all
stay on the backend. The function only relays HTTP.

Safety properties (all enforced here, verified offline in ``tests/unit/test_bff.py``):

* **One fixed backend, no SSRF.** The target host comes only from the
  ``OLYMPUS_BACKEND_URL`` environment variable and must be ``https://``; the
  request path is appended but may never introduce a scheme/host or escape with
  ``..``. The client cannot choose where the proxy connects.
* **Fail-closed allowlist.** Only method+path combinations on the allowlist are
  forwarded; everything else is refused *without* contacting the backend. POST is
  empty by default (extended when a real frontend needs it).
* **Bounded and non-amplifying.** Request bodies are size-capped, a timeout is
  always set, and redirects are never followed (a 3xx is passed through, not
  chased).

This file is a helper (underscore-prefixed) — not a Vercel route. ``api/bff.py``
is the handler that wires it to the serverless runtime.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

#: Read-only surface the BFF may forward by default. Keep this tight: the backend
#: still enforces its own authorization, but the proxy must not be an open relay.
ALLOWED_GET_PREFIXES: tuple[str, ...] = ("/api/", "/healthz", "/openapi.json")
#: POST is fail-closed: no write/trigger route is proxied until a real frontend
#: needs one and it is added here explicitly.
ALLOWED_POST_PATHS: tuple[str, ...] = ()

MAX_BODY_BYTES = 1_000_000
TIMEOUT_SECONDS = 15.0

#: Hop-by-hop headers never forwarded in either direction (RFC 7230 §6.1).
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)
#: Request headers the BFF relays (everything else is dropped — no ambient cookies).
_FORWARD_REQUEST_HEADERS = frozenset({"accept", "content-type", "authorization"})


class BackendError(RuntimeError):
    """The backend URL is missing or not a valid https base."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""

    def with_default_security_headers(self) -> Response:
        names = {k.lower() for k, _ in self.headers}
        extra = []
        if "content-type" not in names:
            extra.append(("Content-Type", "application/json"))
        extra.append(("X-Content-Type-Options", "nosniff"))
        return Response(self.status, tuple(self.headers) + tuple(extra), self.body)


@dataclass(frozen=True)
class _Request:
    method: str
    path: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""


# An opener takes a urllib Request + timeout and returns an object exposing
# ``status``/``getcode()``, ``headers`` (iterable of pairs) and ``read()``. urllib's
# HTTPResponse and HTTPError both satisfy it, which lets 3xx/4xx/5xx pass through.
Opener = Callable[[urllib.request.Request, float], object]


def backend_base(env: Mapping[str, str]) -> str:
    """Return the validated ``https://host[:port]`` base, or raise BackendError."""
    raw = (env.get("OLYMPUS_BACKEND_URL") or "").strip()
    if not raw:
        raise BackendError("OLYMPUS_BACKEND_URL is not set")
    parts = urlsplit(raw)
    if parts.scheme != "https":
        raise BackendError("OLYMPUS_BACKEND_URL must be https")
    if not parts.hostname:
        raise BackendError("OLYMPUS_BACKEND_URL has no host")
    if parts.query or parts.fragment:
        raise BackendError("OLYMPUS_BACKEND_URL must not carry a query or fragment")
    # Keep scheme://host[:port] and an optional base path (no trailing slash).
    base = f"{parts.scheme}://{parts.netloc}{parts.path}"
    return base.rstrip("/")


def _is_allowed(method: str, path: str) -> bool:
    if method in ("GET", "HEAD"):
        return any(path == p or path.startswith(p) for p in ALLOWED_GET_PREFIXES)
    if method == "POST":
        return path in ALLOWED_POST_PATHS
    return False


def _safe_path(path: str) -> bool:
    # A relayed path must be server-absolute and must not smuggle a scheme/host or
    # climb out with "..". Query strings are allowed.
    if not path.startswith("/") or path.startswith("//"):
        return False
    if "://" in path or "\\" in path:
        return False
    return (
        "/../" not in path
        and not path.endswith("/..")
        and ".." not in path.split("?", 1)[0].split("/")
    )


def _default_opener(req: urllib.request.Request, timeout: float) -> object:
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: object, **kwargs: object) -> None:
            return None  # never follow a redirect; pass the 3xx through

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        return opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:  # 3xx (no-redirect) / 4xx / 5xx are responses
        return exc


def _relay_response_headers(raw: Iterable[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    return tuple((k, v) for k, v in raw if k.lower() not in _HOP_BY_HOP)


def forward(
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: bytes,
    *,
    env: Mapping[str, str],
    opener: Opener | None = None,
) -> Response:
    """Forward one request to the configured backend and return the response.

    Refusals never touch the network: an unknown method is 405, a path outside the
    allowlist (or an unsafe path) is 403, an oversized body is 413, and a missing or
    invalid backend URL is 503. Transport failures are 502.
    """
    method = method.upper()
    if method not in ("GET", "HEAD", "POST"):
        return _error(405, "method not allowed")
    if not _safe_path(path) or not _is_allowed(method, path):
        return _error(403, "not allowed")
    if len(body) > MAX_BODY_BYTES:
        return _error(413, "request body too large")
    try:
        base = backend_base(env)
    except BackendError as exc:
        return _error(503, f"backend unavailable: {exc}")

    # Scheme is pinned to https by backend_base() and the path is validated by
    # _safe_path() (no scheme/host, no traversal), so the target is always an https
    # URL on the configured backend host.
    req = urllib.request.Request(base + path, method=method)  # noqa: S310
    for name, value in headers.items():
        if name.lower() in _FORWARD_REQUEST_HEADERS:
            req.add_header(name, value)
    if method == "POST":
        req.data = body

    call = opener or _default_opener
    try:
        resp = call(req, TIMEOUT_SECONDS)
    except (urllib.error.URLError, TimeoutError, OSError):
        return _error(502, "backend request failed")

    status = int(getattr(resp, "status", None) or resp.getcode())  # type: ignore[attr-defined]
    raw_headers = list(getattr(resp, "headers", []).items())  # type: ignore[attr-defined]
    payload = b"" if method == "HEAD" else resp.read()  # type: ignore[attr-defined]
    return Response(
        status, _relay_response_headers(raw_headers), payload
    ).with_default_security_headers()


def _error(status: int, message: str) -> Response:
    import json

    body = json.dumps({"error": message}, separators=(",", ":")).encode("utf-8")
    return Response(
        status,
        (("Content-Type", "application/json"), ("X-Content-Type-Options", "nosniff")),
        body,
    )
