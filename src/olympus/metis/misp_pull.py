"""Live MISP event pulling for Metis CTI (BLUE-3).

MISP is the other widely deployed threat-intelligence exchange, and its REST API
is plain JSON over HTTPS: a client ``POST``s a search to ``/events/restSearch``
with filters (a ``timestamp`` floor for "only what is new", a tag set, published
only) and pages through the matching events.

This module adds exactly that — the *live pull* — and nothing else. Once the
MISP events are in hand, their attributes are merged into a single event and
handed to the existing, offline, well-tested parser
(:func:`~olympus.metis.misp.event_to_indicators`), so a live pull and an
``metis case misp-import`` of the written event yield the identical IOCs. The
network edge is new; the parsing is the proven core — the same split as the
TAXII client in :mod:`olympus.metis.taxii`.

The three safety properties match the TAXII client:

* **Egress is pinned and guarded.** The real transport dials through
  :func:`olympus.core.pinning.pinned_handlers` with the global address policy,
  so the TCP address is resolved once, inside the socket call, and refused if it
  is private/loopback — closing the SSRF and DNS-rebinding windows. A private
  MISP instance (a local lab) is reachable only when the operator has declared
  its range in the active lab policy.
* **Every read is bounded.** Response size, page count and event count all have
  hard caps, so a hostile or runaway instance cannot exhaust memory.
* **No secret lives in the repo.** MISP always authenticates; the API key is
  read from an environment variable named by the caller, sent in the
  ``Authorization`` header (MISP uses the raw key, no ``Bearer`` prefix), and is
  never a committed value and never logged.

The transport is a :class:`MispTransport` ``Protocol`` so tests drive the whole
pull — pagination, the incremental ``timestamp`` cursor, bounds and the auth
header — against a canned in-memory server with no sockets.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
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
from olympus.metis.misp import MispError as MispParseError
from olympus.metis.misp import event_to_indicators

#: Hard cap on a single HTTP response body, in bytes.
MAX_MISP_RESPONSE_BYTES = 32_000_000

#: Hard cap on pages followed in one pull.
MAX_MISP_PAGES = 100

#: Hard cap on events collected in one pull, across all pages.
MAX_MISP_EVENTS = 10_000

#: Hard cap on attributes normalized from one pull (matches the parser ceiling).
MAX_MISP_ATTRIBUTES = MAX_EXTRACTION_ITEMS

#: Default events requested per page (the instance's own maximum may be smaller).
DEFAULT_PAGE_LIMIT = 100

#: Bounded default timeout for one HTTP request, in seconds.
DEFAULT_TIMEOUT = 30.0


class MispPullError(RuntimeError):
    """Raised when a MISP pull cannot complete (transport, auth, or protocol)."""


class MispConfigError(ValueError):
    """Raised when a server is misconfigured (bad URL or token env)."""


@dataclass(frozen=True)
class MispResponse:
    """One HTTP response from a MISP server: status, body and headers."""

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


class MispTransport(Protocol):
    """A single bounded HTTP POST against a MISP endpoint.

    Implementations perform I/O only; all protocol logic lives in
    :func:`pull_events`, so a test can supply canned responses.
    """

    def post(
        self, url: str, body: bytes, headers: Mapping[str, str], *, timeout: float
    ) -> MispResponse:  # pragma: no cover - Protocol signature
        """POST ``body`` to ``url`` with ``headers``, returning the response."""


@dataclass(frozen=True)
class MispServer:
    """Where to pull and how to authenticate, with no secret value inlined.

    ``base_url`` is the MISP instance root (e.g. ``https://misp.example``);
    ``token_env`` is the *name* of the environment variable holding the API key
    — never the key itself. MISP always requires a key, so ``token_env`` is
    mandatory and the pull fails closed when the variable is unset.
    """

    base_url: str
    token_env: str

    def __post_init__(self) -> None:
        split = urlsplit(self.base_url)
        if split.scheme != "https":
            raise MispConfigError("MISP base_url must be https://")
        if not split.hostname:
            raise MispConfigError("MISP base_url has no host")
        if split.query or split.fragment:
            raise MispConfigError("MISP base_url must not carry a query or fragment")
        if not self.token_env.strip():
            raise MispConfigError("token_env must name an environment variable")

    @property
    def search_url(self) -> str:
        """The events restSearch endpoint."""
        return f"{self.base_url.rstrip('/')}/events/restSearch"

    @property
    def source_label(self) -> str:
        """A stable provenance string: host only, no secret."""
        return f"misp://{urlsplit(self.base_url).hostname or 'misp'}"

    def auth_headers(self, environ: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return the MISP request headers, including the key from the env var.

        Fail-closed: the configured variable must be set, or the pull raises
        rather than contacting the instance unauthenticated.
        """
        env = os.environ if environ is None else environ
        key = env.get(self.token_env, "")
        if not key.strip():
            raise MispConfigError(
                f"environment variable {self.token_env} is not set; export the MISP API key there"
            )
        return {
            "Authorization": key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


@dataclass(frozen=True)
class MispPullResult:
    """The outcome of one pull: normalized IOCs, provenance and the next cursor."""

    source: str
    result: ExtractionResult
    event: dict[str, Any]
    events_fetched: int
    pages_fetched: int
    next_since: str | None
    more_available: bool

    @property
    def indicator_count(self) -> int:
        """Number of faithfully normalized IOCs."""
        return len(self.result.indicators)


class PinnedMispTransport:
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
    ) -> MispResponse:
        """POST ``body`` over pinned HTTPS, reading at most the bounded limit."""
        if urlsplit(url).scheme != "https":
            raise MispPullError("MISP transport only speaks https://")
        # scheme is pinned to https above; the opener's address policy refuses
        # any non-public/lab destination, so file:/custom schemes cannot apply.
        request = urllib.request.Request(  # noqa: S310
            url, data=body, headers=dict(headers), method="POST"
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                payload = response.read(MAX_MISP_RESPONSE_BYTES + 1)
                status = int(response.status)
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            data = exc.read(MAX_MISP_RESPONSE_BYTES) if exc.fp is not None else b""
            return MispResponse(int(exc.code), data, dict(exc.headers.items()))
        except PinnedConnectionError as exc:
            raise MispPullError(f"MISP egress refused: {exc}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise MispPullError(f"MISP request to {url} failed: {exc}") from exc
        if len(payload) > MAX_MISP_RESPONSE_BYTES:
            raise MispPullError("MISP response exceeds the bounded size limit")
        return MispResponse(status, payload, response_headers)


def _parse_events(response: MispResponse, url: str) -> list[dict[str, Any]]:
    """Validate one response and return its list of ``{"Event": ...}`` wrappers."""
    if response.status in (401, 403):
        raise MispPullError(f"MISP server refused authorization ({response.status}) for {url}")
    if response.status != 200:
        raise MispPullError(f"MISP server returned HTTP {response.status} for {url}")
    try:
        document: Any = json.loads(response.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise MispPullError(f"MISP response is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise MispPullError("MISP response is not a JSON object")
    events = document.get("response", [])
    if not isinstance(events, list):
        raise MispPullError("MISP response 'response' is not an array")
    if not all(isinstance(item, dict) for item in events):
        raise MispPullError("MISP response contains a non-object event")
    return events


def _event_timestamp(event: dict[str, Any]) -> int | None:
    """Return an event's MISP ``timestamp`` (unix seconds) if present and valid."""
    body = event.get("Event", event)
    if not isinstance(body, dict):
        return None
    raw = body.get("timestamp")
    try:
        return int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _attributes(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Return an event's top-level MISP attributes (never nested objects)."""
    body = event.get("Event", event)
    if not isinstance(body, dict):
        return []
    attributes = body.get("Attribute", [])
    if not isinstance(attributes, list):
        return []
    return [item for item in attributes if isinstance(item, dict)]


def _normalize(event: dict[str, Any], source: str) -> ExtractionResult:
    """Parse a combined MISP event into the shared ExtractionResult shape.

    Uses the offline MISP parser directly (not the web ``extract_from_source``
    boundary): the live pull is already bounded by event and byte caps, so the
    1 MB pasted-body limit that guards the API surface does not apply. The
    faithful IOCs are sorted by ``(type, value)`` for a stable, pull-order-
    independent result, exactly as the other extraction surfaces return them.
    """
    try:
        parsed = event_to_indicators(json.dumps(event))
    except MispParseError as exc:  # pragma: no cover - we construct the event ourselves
        raise MispPullError(f"collected MISP attributes did not form a valid event: {exc}") from exc
    indicators = tuple(
        sorted(
            (ExtractedIndicator(item.indicator_type, item.value) for item in parsed.indicators),
            key=lambda item: (item.indicator_type.value, item.value),
        )
    )
    skipped = tuple(
        SkippedItem(f"{item.misp_type}: {item.value}", item.reason) for item in parsed.skipped
    )
    return ExtractionResult(source_format="misp", indicators=indicators, skipped=skipped)


def pull_events(
    transport: MispTransport,
    server: MispServer,
    *,
    since: str | None = None,
    tags: Sequence[str] | None = None,
    published_only: bool = True,
    page_limit: int = DEFAULT_PAGE_LIMIT,
    max_events: int = MAX_MISP_EVENTS,
    max_pages: int = MAX_MISP_PAGES,
    timeout: float = DEFAULT_TIMEOUT,
    environ: Mapping[str, str] | None = None,
) -> MispPullResult:
    """Pull MISP events via ``/events/restSearch`` and normalize them to IOCs.

    Pages through the search (MISP has no "more" flag: a short page ends it),
    collecting at most ``max_events`` events over at most ``max_pages`` requests.
    The events' top-level attributes are merged into one event and parsed by the
    offline MISP normalizer, so the IOCs match a later ``misp-import`` of the
    written event exactly. ``since`` sets the ``timestamp`` floor (a unix second
    or a MISP relative value like ``"1d"``) for an incremental pull; the returned
    ``next_since`` is the cursor to pass next time. ``tags`` and ``published_only``
    narrow the search.

    Raises :class:`MispPullError` on a transport/protocol failure and
    :class:`MispConfigError` on a bad bound or missing credential.
    """
    if not 1 <= page_limit <= MAX_MISP_EVENTS:
        raise MispConfigError(f"page_limit must be between 1 and {MAX_MISP_EVENTS}")
    if not 1 <= max_events <= MAX_MISP_EVENTS:
        raise MispConfigError(f"max_events must be between 1 and {MAX_MISP_EVENTS}")
    if not 1 <= max_pages <= MAX_MISP_PAGES:
        raise MispConfigError(f"max_pages must be between 1 and {MAX_MISP_PAGES}")
    if timeout <= 0:
        raise MispConfigError("timeout must be positive")

    headers = server.auth_headers(environ)
    url = server.search_url

    collected: list[dict[str, Any]] = []
    latest_ts: int | None = None
    more_available = False
    pages = 0

    for page in range(1, max_pages + 1):
        query: dict[str, Any] = {
            "returnFormat": "json",
            "limit": page_limit,
            "page": page,
            "published": published_only,
        }
        if since:
            query["timestamp"] = since
        if tags:
            query["tags"] = list(tags)
        body = json.dumps(query).encode("utf-8")

        response = transport.post(url, body, headers, timeout=timeout)
        pages += 1
        events = _parse_events(response, url)

        hit_bound = False
        for event in events:
            if len(collected) >= max_events:
                hit_bound = True
                break
            collected.append(event)
            ts = _event_timestamp(event)
            if ts is not None and (latest_ts is None or ts > latest_ts):
                latest_ts = ts

        if hit_bound:
            more_available = True
            break
        # MISP ends a search with a short (or empty) page; a full page may have more.
        if len(events) < page_limit:
            more_available = False
            break
        more_available = True
    else:
        # Loop exhausted max_pages while every page was full: more may remain.
        more_available = True

    merged_attributes: list[dict[str, Any]] = []
    for event in collected:
        merged_attributes.extend(_attributes(event))
    combined = {
        "Event": {
            "info": f"Olympus MISP pull {server.source_label}",
            "Attribute": merged_attributes,
        }
    }
    result = _normalize(combined, server.source_label)

    return MispPullResult(
        source=server.source_label,
        result=result,
        event=combined,
        events_fetched=len(collected),
        pages_fetched=pages,
        next_since=str(latest_ts + 1) if latest_ts is not None else since,
        more_available=more_available,
    )


__all__ = [
    "DEFAULT_PAGE_LIMIT",
    "DEFAULT_TIMEOUT",
    "MAX_MISP_EVENTS",
    "MAX_MISP_PAGES",
    "MAX_MISP_RESPONSE_BYTES",
    "MispConfigError",
    "MispPullError",
    "MispPullResult",
    "MispResponse",
    "MispServer",
    "MispTransport",
    "PinnedMispTransport",
    "pull_events",
]
