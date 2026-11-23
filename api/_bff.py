"""Backend-for-frontend (BFF) core for the split deployment (DEPLOY-3).

The production control plane runs on a container **Execution backend** (DEPLOY-2);
the Vercel deployment is static (``public/``) plus thin serverless functions. This
module is that thin layer: a **named-route forwarder** to the one configured
backend. It imports nothing from :mod:`olympus` and never spawns a process — **no
scanner ever runs on Vercel**; execution, authorization, scope and isolation all
stay on the backend. The function only relays HTTP.

Safety properties (enforced here, verified offline in ``tests/unit/test_bff.py``):

* **One fixed backend, no SSRF.** The target host comes only from the
  ``OLYMPUS_BACKEND_URL`` environment variable and must be ``https://``. The client
  never supplies a URL or a path: it names a **route**, and the outbound path is a
  constant looked up in :data:`ROUTES`. No request data is ever concatenated into
  the request URL.
* **Fail-closed allowlist.** Only the read-only routes in :data:`ROUTES` are
  forwarded (GET/HEAD); an unknown route or a write method is refused *without*
  contacting the backend. Add a route here explicitly when a real frontend needs
  one (and review query/body forwarding then).
* **Bounded and non-amplifying.** A timeout is always set and redirects are never
  followed (a 3xx is passed through, not chased); response hop-by-hop headers are
  stripped and request cookies are not relayed.

This file is a helper (underscore-prefixed) — not a Vercel route. ``api/bff.py``
is the handler that wires it to the serverless runtime.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

#: Read-only routes the BFF may forward: a stable client-facing name -> the exact,
#: constant backend path. The client never sends a path, only one of these names,
#: so no request data can steer the outbound URL (no SSRF, full or partial). Extend
#: this map deliberately when a real frontend needs a route.
ROUTES: dict[str, str] = {
    "health": "/healthz",
    "openapi": "/openapi.json",
    "engines-preflight": "/api/v1/engines/preflight",
    "capabilities": "/api/v1/capabilities",
}

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
_FORWARD_REQUEST_HEADERS = frozenset({"accept", "authorization"})


class BackendError(RuntimeError):
    """The backend URL is missing or not a valid https base."""


@dataclass(frozen=True)
class Response:
    status: int
    headers: tuple[tuple[str, str], ...] = ()
    body: bytes = b""

    def with_default_security_headers(self) -> Response:
        names = {k.lower() for k, _ in self.headers}
        extra: list[tuple[str, str]] = []
        if "content-type" not in names:
            extra.append(("Content-Type", "application/json"))
        extra.append(("X-Content-Type-Options", "nosniff"))
        return Response(self.status, tuple(self.headers) + tuple(extra), self.body)


# An opener takes a urllib Request + timeout and returns an object exposing
# ``status``/``getcode()``, ``headers`` (iterable of pairs) and ``read()``. urllib's
# HTTPResponse and HTTPError both satisfy it, which lets 3xx/4xx/5xx pass through.
Opener = Callable[[urllib.request.Request, float], object]


def backend_base(env: Mapping[str, str]) -> str:
    """Return the validated ``https://host[:port][/base]`` URL, or raise BackendError."""
    from urllib.parse import urlsplit

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
    return f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/")


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
    route: str,
    headers: Mapping[str, str],
    body: bytes,
    *,
    env: Mapping[str, str],
    opener: Opener | None = None,
) -> Response:
    """Forward one read request, named by ``route``, to the configured backend.

    Refusals never touch the network: a write/unknown method is 405, an unknown
    route is 403, and a missing or invalid backend URL is 503. Transport failures
    are 502. The outbound path is the constant ``ROUTES[route]`` — no part of the
    request reaches the URL.
    """
    method = method.upper()
    if method not in ("GET", "HEAD"):
        return _error(405, "method not allowed")
    backend_path = ROUTES.get(route)
    if backend_path is None:
        return _error(403, "unknown route")
    try:
        base = backend_base(env)
    except BackendError as exc:
        return _error(503, f"backend unavailable: {exc}")

    # base is https (validated) and backend_path is a constant from ROUTES, so the
    # URL is fully determined by server-side config — no request data flows into it.
    req = urllib.request.Request(base + backend_path, method=method)  # noqa: S310
    for name, value in headers.items():
        if name.lower() in _FORWARD_REQUEST_HEADERS:
            req.add_header(name, value)

    call = opener or _default_opener
    try:
        resp = call(req, TIMEOUT_SECONDS)
    except (urllib.error.URLError, TimeoutError, OSError):
        return _error(502, "backend request failed")

    status = int(getattr(resp, "status", None) or resp.getcode())  # type: ignore[attr-defined]
    raw_headers = list(getattr(resp, "headers", []).items())  # type: ignore[attr-defined]
    payload = b"" if method == "HEAD" else resp.read()  # type: ignore[attr-defined]
    relayed = Response(status, _relay_response_headers(raw_headers), payload)
    return relayed.with_default_security_headers()


def _error(status: int, message: str) -> Response:
    import json

    body = json.dumps({"error": message}, separators=(",", ":")).encode("utf-8")
    return Response(
        status,
        (("Content-Type", "application/json"), ("X-Content-Type-Options", "nosniff")),
        body,
    )
