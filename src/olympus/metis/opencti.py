"""Live OpenCTI indicator pulling for Metis CTI (BLUE-3).

OpenCTI is a widely deployed threat-intelligence platform with a GraphQL API.
Its ``indicators`` already carry a STIX 2.1 ``pattern`` (e.g.
``[domain-name:value = 'evil.tld']``) and a ``pattern_type``, so this client is
the third sibling of the TAXII and MISP pullers: it fetches indicator nodes over
GraphQL, maps each one back into a STIX ``indicator`` object, wraps them into a
bundle, and hands that to the existing, offline, well-tested STIX parser
(:func:`~olympus.metis.stix.bundle_to_indicators`). A live pull and an
``metis case stix-import`` of the written bundle therefore yield the identical
IOCs — the network edge is new, the parsing is the proven core.

The three safety properties match the other live surfaces:

* **Egress is pinned and guarded.** The real transport dials through
  :func:`olympus.core.pinning.pinned_handlers` with the global address policy,
  so the TCP address is resolved once, inside the socket call, and refused if it
  is private/loopback — closing the SSRF and DNS-rebinding windows. A private
  OpenCTI instance (a local lab) is reachable only when the operator has declared
  its range in the active lab policy.
* **Every read is bounded.** Response size, page count and indicator count all
  have hard caps, so a hostile or runaway instance cannot exhaust memory.
* **No secret lives in the repo.** OpenCTI always authenticates; the API token is
  read from an environment variable named by the caller, sent as an
  ``Authorization: Bearer`` header, and is never a committed value and never
  logged.

A **revoked** indicator is deliberately excluded from the bundle: a revoked IOC
is no longer valid intelligence and must not be imported as active.

The transport is an :class:`OpenCtiTransport` ``Protocol`` so tests drive the
whole pull — Relay pagination, the incremental ``since`` cursor, bounds, the
auth header and GraphQL errors — against a canned in-memory server with no
sockets.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

from olympus.core.pinning import PinnedConnectionError, global_address_policy, pinned_handlers
from olympus.metis.extraction import (
    MAX_EXTRACTION_ITEMS,
    ExtractedIndicator,
    ExtractionResult,
    SkippedItem,
)
from olympus.metis.stix import StixError, bundle_to_indicators

#: Hard cap on a single HTTP response body, in bytes.
MAX_OPENCTI_RESPONSE_BYTES = 32_000_000

#: Hard cap on pages followed in one pull (Relay pagination).
MAX_OPENCTI_PAGES = 100

#: Hard cap on indicators collected in one pull, across all pages.
MAX_OPENCTI_INDICATORS = MAX_EXTRACTION_ITEMS

#: Default indicators requested per page (the instance's own maximum may differ).
DEFAULT_PAGE_SIZE = 100

#: Bounded default timeout for one HTTP request, in seconds.
DEFAULT_TIMEOUT = 30.0

#: The GraphQL query: a page of indicators ordered by update time, so the last
#: node on the last page carries the newest ``updated_at`` for the next cursor.
_INDICATORS_QUERY = """
query OlympusIndicators($first: Int!, $after: ID, $filters: FilterGroup) {
  indicators(first: $first, after: $after, filters: $filters,
             orderBy: updated_at, orderMode: asc) {
    edges { node { pattern pattern_type revoked updated_at } }
    pageInfo { hasNextPage endCursor }
  }
}
"""


class OpenCtiError(RuntimeError):
    """Raised when an OpenCTI pull cannot complete (transport, auth, protocol)."""


class OpenCtiConfigError(ValueError):
    """Raised when a server is misconfigured (bad URL or token env)."""


@dataclass(frozen=True)
class OpenCtiResponse:
    """One HTTP response from an OpenCTI server: status, body and headers."""

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class OpenCtiTransport(Protocol):
    """A single bounded HTTP POST against an OpenCTI GraphQL endpoint.

    Implementations perform I/O only; all protocol logic lives in
    :func:`pull_indicators`, so a test can supply canned responses.
    """

    def post(
        self, url: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> OpenCtiResponse:  # pragma: no cover - Protocol signature
        """POST ``body`` to ``url`` with ``headers``, returning the response."""


@dataclass(frozen=True)
class OpenCtiServer:
    """Where to pull and how to authenticate, with no secret value inlined.

    ``base_url`` is the OpenCTI instance root (e.g. ``https://opencti.example``);
    ``token_env`` is the *name* of the environment variable holding the API token
    — never the token itself. OpenCTI always requires a token, so ``token_env``
    is mandatory and the pull fails closed when the variable is unset.
    """

    base_url: str
    token_env: str

    def __post_init__(self) -> None:
        split = urlsplit(self.base_url)
        if split.scheme != "https":
            raise OpenCtiConfigError("OpenCTI base_url must be https://")
        if not split.hostname:
            raise OpenCtiConfigError("OpenCTI base_url has no host")
        if split.query or split.fragment:
            raise OpenCtiConfigError("OpenCTI base_url must not carry a query or fragment")
        if not self.token_env.strip():
            raise OpenCtiConfigError("token_env must name an environment variable")

    @property
    def graphql_url(self) -> str:
        """The GraphQL endpoint."""
        return f"{self.base_url.rstrip('/')}/graphql"

    @property
    def source_label(self) -> str:
        """A stable provenance string: host only, no secret."""
        return f"opencti://{urlsplit(self.base_url).hostname or 'opencti'}"

    def auth_headers(self, environ: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return the request headers, including the bearer token from the env var.

        Fail-closed: the configured variable must be set, or the pull raises
        rather than contacting the instance unauthenticated.
        """
        env = os.environ if environ is None else environ
        token = env.get(self.token_env, "")
        if not token.strip():
            raise OpenCtiConfigError(
                f"environment variable {self.token_env} is not set; "
                "export the OpenCTI API token there"
            )
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


@dataclass(frozen=True)
class OpenCtiPullResult:
    """The outcome of one pull: normalized IOCs, provenance and the next cursor."""

    source: str
    result: ExtractionResult
    bundle: dict[str, Any]
    indicators_fetched: int
    pages_fetched: int
    next_since: str | None
    more_available: bool

    @property
    def indicator_count(self) -> int:
        """Number of faithfully normalized IOCs."""
        return len(self.result.indicators)


class PinnedOpenCtiTransport:
    """HTTPS POST pinned to a once-resolved, policy-authorized address.

    Reuses the vetted :mod:`olympus.core.pinning` stack: the hostname is used for
    TLS/SNI and the HTTP ``Host`` header, while the TCP connection goes only to
    an address the global policy authorizes — public by default, or a declared
    lab range when the active policy allows one. No HTTP proxy is permitted.
    """

    def __init__(self, *, ca_file: str | None = None) -> None:
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = urllib.request.build_opener(
            *pinned_handlers(global_address_policy(), context=context)
        )

    def post(
        self, url: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> OpenCtiResponse:
        """POST ``body`` over pinned HTTPS, reading at most the bounded limit."""
        if urlsplit(url).scheme != "https":
            raise OpenCtiError("OpenCTI transport only speaks https://")
        # scheme is pinned to https above; the opener's address policy refuses
        # any non-public/lab destination, so file:/custom schemes cannot apply.
        request = urllib.request.Request(  # noqa: S310
            url, data=body, headers=dict(headers), method="POST"
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                payload = response.read(MAX_OPENCTI_RESPONSE_BYTES + 1)
                status = int(response.status)
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            data = exc.read(MAX_OPENCTI_RESPONSE_BYTES) if exc.fp is not None else b""
            return OpenCtiResponse(int(exc.code), data, dict(exc.headers.items()))
        except PinnedConnectionError as exc:
            raise OpenCtiError(f"OpenCTI egress refused: {exc}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise OpenCtiError(f"OpenCTI request to {url} failed: {exc}") from exc
        if len(payload) > MAX_OPENCTI_RESPONSE_BYTES:
            raise OpenCtiError("OpenCTI response exceeds the bounded size limit")
        return OpenCtiResponse(status, payload, response_headers)


def _parse_page(
    response: OpenCtiResponse, url: str
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Validate one GraphQL response and return ``(nodes, hasNextPage, endCursor)``."""
    if response.status in (401, 403):
        raise OpenCtiError(f"OpenCTI server refused authorization ({response.status}) for {url}")
    if response.status != 200:
        raise OpenCtiError(f"OpenCTI server returned HTTP {response.status} for {url}")
    try:
        document: Any = json.loads(response.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise OpenCtiError(f"OpenCTI response is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise OpenCtiError("OpenCTI response is not a JSON object")
    errors = document.get("errors")
    if errors:
        message = "unknown error"
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            message = str(errors[0].get("message", message))
        raise OpenCtiError(f"OpenCTI GraphQL error: {message}")
    data = document.get("data")
    indicators = data.get("indicators") if isinstance(data, dict) else None
    if not isinstance(indicators, dict):
        raise OpenCtiError("OpenCTI response has no 'indicators' connection")
    edges = indicators.get("edges", [])
    if not isinstance(edges, list):
        raise OpenCtiError("OpenCTI 'edges' is not an array")
    nodes: list[dict[str, Any]] = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        node = edge.get("node")
        if isinstance(node, dict):
            nodes.append(node)
    page_info = indicators.get("pageInfo", {})
    has_next = bool(page_info.get("hasNextPage", False)) if isinstance(page_info, dict) else False
    cursor = page_info.get("endCursor") if isinstance(page_info, dict) else None
    end_cursor = str(cursor) if isinstance(cursor, str) and cursor else None
    return nodes, has_next, end_cursor


def _stix_objects(nodes: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str | None]:
    """Map indicator nodes to STIX objects, skipping revoked ones.

    Returns the STIX objects and the newest ``updated_at`` seen (the incremental
    cursor for the next pull).
    """
    objects: list[dict[str, Any]] = []
    latest: str | None = None
    for node in nodes:
        updated = node.get("updated_at")
        if isinstance(updated, str) and (latest is None or updated > latest):
            latest = updated
        if node.get("revoked") is True:
            continue  # a revoked IOC is no longer valid; never import it as active
        pattern = node.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            continue
        pattern_type = node.get("pattern_type")
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "pattern": pattern,
                "pattern_type": pattern_type if isinstance(pattern_type, str) else "stix",
            }
        )
    return objects, latest


def _normalize(bundle: dict[str, Any]) -> ExtractionResult:
    """Parse a collected bundle into the shared ExtractionResult shape.

    Uses the offline STIX parser directly (not the web ``extract_from_source``
    boundary): the live pull is already bounded by indicator and byte caps, so
    the 1 MB pasted-body limit that guards the API surface does not apply. The
    faithful IOCs are sorted by ``(type, value)`` for a stable, pull-order-
    independent result.
    """
    try:
        parsed = bundle_to_indicators(json.dumps(bundle))
    except StixError as exc:  # pragma: no cover - we construct the bundle ourselves
        raise OpenCtiError(
            f"collected OpenCTI indicators did not form a valid bundle: {exc}"
        ) from exc
    indicators = tuple(
        sorted(
            (ExtractedIndicator(item.indicator_type, item.value) for item in parsed.indicators),
            key=lambda item: (item.indicator_type.value, item.value),
        )
    )
    skipped = tuple(SkippedItem(item.pattern, item.reason) for item in parsed.skipped)
    return ExtractionResult(source_format="stix", indicators=indicators, skipped=skipped)


def _filters(since: str | None) -> dict[str, Any] | None:
    """Build an OpenCTI FilterGroup selecting indicators updated since ``since``."""
    if not since:
        return None
    return {
        "mode": "and",
        "filters": [{"key": "updated_at", "values": [since], "operator": "gte", "mode": "or"}],
        "filterGroups": [],
    }


def pull_indicators(
    transport: OpenCtiTransport,
    server: OpenCtiServer,
    *,
    since: str | None = None,
    page_size: int = DEFAULT_PAGE_SIZE,
    max_indicators: int = MAX_OPENCTI_INDICATORS,
    max_pages: int = MAX_OPENCTI_PAGES,
    timeout: float = DEFAULT_TIMEOUT,
    environ: Mapping[str, str] | None = None,
) -> OpenCtiPullResult:
    """Pull OpenCTI indicators over GraphQL and normalize them to IOCs.

    Pages through the ``indicators`` connection (Relay ``hasNextPage``/``endCursor``),
    collecting at most ``max_indicators`` indicator nodes over at most ``max_pages``
    requests. Each non-revoked node's STIX pattern is wrapped into a STIX indicator
    object and the resulting bundle is parsed by the offline STIX normalizer, so the
    IOCs match a later ``stix-import`` of the written bundle exactly. ``since`` filters
    on ``updated_at`` for an incremental pull; the returned ``next_since`` is the
    cursor to pass next time.

    Raises :class:`OpenCtiError` on a transport/protocol failure and
    :class:`OpenCtiConfigError` on a bad bound or missing credential.
    """
    if not 1 <= page_size <= MAX_OPENCTI_INDICATORS:
        raise OpenCtiConfigError(f"page_size must be between 1 and {MAX_OPENCTI_INDICATORS}")
    if not 1 <= max_indicators <= MAX_OPENCTI_INDICATORS:
        raise OpenCtiConfigError(f"max_indicators must be between 1 and {MAX_OPENCTI_INDICATORS}")
    if not 1 <= max_pages <= MAX_OPENCTI_PAGES:
        raise OpenCtiConfigError(f"max_pages must be between 1 and {MAX_OPENCTI_PAGES}")
    if timeout <= 0:
        raise OpenCtiConfigError("timeout must be positive")

    headers = server.auth_headers(environ)
    url = server.graphql_url
    filters = _filters(since)

    nodes: list[dict[str, Any]] = []
    cursor: str | None = None
    more_available = False
    pages = 0

    while pages < max_pages:
        variables: dict[str, Any] = {"first": page_size, "after": cursor, "filters": filters}
        body = json.dumps({"query": _INDICATORS_QUERY, "variables": variables}).encode("utf-8")

        response = transport.post(url, body, headers, timeout=timeout)
        pages += 1
        page_nodes, has_next, end_cursor = _parse_page(response, url)

        hit_bound = False
        for node in page_nodes:
            if len(nodes) >= max_indicators:
                hit_bound = True
                break
            nodes.append(node)

        # Reflect the last page the server gave us; the page-cap exit keeps this.
        more_available = bool(has_next)
        if hit_bound:
            more_available = True
            break
        if has_next and end_cursor and len(nodes) < max_indicators:
            cursor = end_cursor
            continue
        break

    objects, latest = _stix_objects(nodes)
    bundle = {"type": "bundle", "id": "bundle--olympus-opencti-pull", "objects": objects}
    result = _normalize(bundle)

    return OpenCtiPullResult(
        source=server.source_label,
        result=result,
        bundle=bundle,
        indicators_fetched=len(nodes),
        pages_fetched=pages,
        next_since=latest or since,
        more_available=more_available,
    )


__all__ = [
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_TIMEOUT",
    "MAX_OPENCTI_INDICATORS",
    "MAX_OPENCTI_PAGES",
    "MAX_OPENCTI_RESPONSE_BYTES",
    "OpenCtiConfigError",
    "OpenCtiError",
    "OpenCtiPullResult",
    "OpenCtiResponse",
    "OpenCtiServer",
    "OpenCtiTransport",
    "PinnedOpenCtiTransport",
    "pull_indicators",
]
