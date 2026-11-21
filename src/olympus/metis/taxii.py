"""Live TAXII 2.1 collection polling for Metis CTI (BLUE-3).

TAXII 2.1 is the HTTP transport that goes with STIX 2.1: a server exposes
*collections* of STIX objects, and a client polls a collection's ``objects``
endpoint, paging through an *envelope* (``{"objects": [...], "more": ..., "next":
...}``) and asking only for what is new since last time (``added_after``).

This module adds exactly that — the *live fetch* — and nothing else. Once the
STIX objects are in hand they are wrapped into a bundle and handed to the
existing, offline, well-tested STIX parser
(:func:`~olympus.metis.stix.bundle_to_indicators`), so a live poll and an
``metis case stix-import`` of the same bundle yield the identical IOCs. BLUE-3
is the network edge; the parsing is the proven core.

Three properties make the fetch safe to point at the public internet:

* **Egress is pinned and guarded.** The real transport dials through
  :func:`olympus.core.pinning.pinned_handlers` with the global address policy,
  so the TCP address is resolved once, inside the socket call, and refused if it
  is private/loopback — closing the SSRF and DNS-rebinding windows. A private
  TAXII server (a local lab) is reachable *only* when the operator has declared
  its range in the active lab policy, exactly like the live-scan gate.
* **Every read is bounded.** Response size, page count and object count all have
  hard caps, so a hostile or runaway feed cannot exhaust memory.
* **No secret lives in the repo.** The bearer token, when a feed needs one, is
  read from an environment variable named by the caller; it is never a field in
  a committed config and never logged.

The transport is a :class:`TaxiiTransport` ``Protocol`` so tests drive the whole
poll — pagination, incremental cursor, bounds, auth header — against a canned
in-memory server with no sockets.
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
from urllib.parse import quote, urlencode, urlsplit

from olympus.core.pinning import PinnedConnectionError, global_address_policy, pinned_handlers
from olympus.metis.extraction import (
    MAX_EXTRACTION_ITEMS,
    ExtractedIndicator,
    ExtractionResult,
    SkippedItem,
)
from olympus.metis.stix import StixError, bundle_to_indicators

#: TAXII 2.1 content negotiation: both the request ``Accept`` and the response
#: ``Content-Type`` carry this media type (OASIS TAXII 2.1 §1.6.8).
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

#: Hard cap on a single HTTP response body, in bytes. A page that exceeds it is
#: refused rather than read, so one oversized reply cannot exhaust memory.
MAX_TAXII_RESPONSE_BYTES = 16_000_000

#: Hard cap on pages followed in one poll. Pagination that never reports
#: ``more: false`` is stopped here rather than looping forever.
MAX_TAXII_PAGES = 100

#: Hard cap on STIX objects collected in one poll, across all pages. Matches the
#: ceiling the normalizer enforces on parsed items.
MAX_TAXII_OBJECTS = MAX_EXTRACTION_ITEMS

#: Default page size requested from the server (its own maximum may be smaller).
DEFAULT_PAGE_LIMIT = 1_000

#: Bounded default timeout for one HTTP request, in seconds.
DEFAULT_TIMEOUT = 30.0

#: Collection ids are path segments; keep them to an unambiguous, injection-free
#: charset (TAXII ids are UUIDs, but servers vary, so allow a safe superset).
_SAFE_ID = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


class TaxiiError(RuntimeError):
    """Raised when a TAXII poll cannot complete (transport, auth, or protocol)."""


class TaxiiConfigError(ValueError):
    """Raised when a collection is misconfigured (bad URL, id, or token env)."""


@dataclass(frozen=True)
class TaxiiResponse:
    """One HTTP response from a TAXII server: status, body and headers."""

    status: int
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        """Case-insensitive lookup of a response header."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


class TaxiiTransport(Protocol):
    """A single bounded HTTP GET against a TAXII endpoint.

    Implementations perform I/O only; all protocol logic lives in
    :func:`poll_collection`, so a test can supply canned envelopes.
    """

    def get(
        self, url: str, headers: Mapping[str, str], *, timeout: float
    ) -> TaxiiResponse:  # pragma: no cover - Protocol signature
        """Fetch ``url`` with ``headers``, returning the bounded response."""


@dataclass(frozen=True)
class TaxiiCollection:
    """Where to poll and how to authenticate, with no secret value inlined.

    ``api_root_url`` is the TAXII API Root (e.g.
    ``https://feed.example/taxii2/api1``); ``collection_id`` names the collection
    under it. ``token_env``, when set, is the *name* of the environment variable
    holding the bearer token — never the token itself.
    """

    api_root_url: str
    collection_id: str
    token_env: str | None = None

    def __post_init__(self) -> None:
        split = urlsplit(self.api_root_url)
        if split.scheme != "https":
            raise TaxiiConfigError("TAXII api_root_url must be https://")
        if not split.hostname:
            raise TaxiiConfigError("TAXII api_root_url has no host")
        if split.query or split.fragment:
            raise TaxiiConfigError("TAXII api_root_url must not carry a query or fragment")
        if not self.collection_id or any(ch not in _SAFE_ID for ch in self.collection_id):
            raise TaxiiConfigError("TAXII collection_id has an unexpected character")
        if len(self.collection_id) > 200:
            raise TaxiiConfigError("TAXII collection_id is too long")
        if self.token_env is not None and not self.token_env.strip():
            raise TaxiiConfigError("token_env, when set, must name an environment variable")

    @property
    def objects_url(self) -> str:
        """The collection's ``objects`` endpoint, with a single trailing slash."""
        root = self.api_root_url.rstrip("/")
        return f"{root}/collections/{quote(self.collection_id, safe='')}/objects/"

    @property
    def source_label(self) -> str:
        """A stable provenance string: host + collection, no secret."""
        host = urlsplit(self.api_root_url).hostname or "taxii"
        return f"taxii://{host}/{self.collection_id}"

    def auth_headers(self, environ: Mapping[str, str] | None = None) -> dict[str, str]:
        """Return the Authorization header from the token env var, if configured.

        Fail-closed: a collection that declares ``token_env`` but whose variable
        is unset or blank raises, rather than polling an authenticated feed with
        no credential and leaking the request.
        """
        if self.token_env is None:
            return {}
        env = os.environ if environ is None else environ
        token = env.get(self.token_env, "")
        if not token.strip():
            raise TaxiiConfigError(
                f"environment variable {self.token_env} is not set; "
                "export the TAXII token there or clear token_env for an anonymous feed"
            )
        return {"Authorization": f"Bearer {token}"}


@dataclass(frozen=True)
class TaxiiPollResult:
    """The outcome of one poll: normalized IOCs, provenance and the next cursor."""

    source: str
    result: ExtractionResult
    bundle: dict[str, Any]
    objects_fetched: int
    pages_fetched: int
    next_added_after: str | None
    more_available: bool

    @property
    def indicator_count(self) -> int:
        """Number of faithfully normalized IOCs."""
        return len(self.result.indicators)


class PinnedTaxiiTransport:
    """HTTPS GET pinned to a once-resolved, policy-authorized address.

    Reuses the vetted :mod:`olympus.core.pinning` stack: the hostname is used for
    TLS/SNI and the HTTP ``Host`` header, while the TCP connection goes only to
    an address the global policy authorizes — public by default, or a declared
    lab range when the active policy allows one. No HTTP proxy is permitted
    (pinning forbids the second resolution a proxy would do).
    """

    def __init__(self, *, ca_file: str | None = None) -> None:
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = urllib.request.build_opener(
            *pinned_handlers(global_address_policy(), context=context)
        )

    def get(self, url: str, headers: Mapping[str, str], *, timeout: float) -> TaxiiResponse:
        """Fetch ``url`` over pinned HTTPS, reading at most the bounded limit."""
        if urlsplit(url).scheme != "https":
            raise TaxiiError("TAXII transport only speaks https://")
        # scheme is pinned to https above; the opener's address policy refuses
        # any non-public/lab destination, so file:/custom schemes cannot apply.
        request = urllib.request.Request(url, headers=dict(headers), method="GET")  # noqa: S310
        try:
            with self._opener.open(request, timeout=timeout) as response:
                payload = response.read(MAX_TAXII_RESPONSE_BYTES + 1)
                status = int(response.status)
                response_headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            # An HTTP error still carries a status and a (bounded) body worth reporting.
            body = exc.read(MAX_TAXII_RESPONSE_BYTES) if exc.fp is not None else b""
            return TaxiiResponse(int(exc.code), body, dict(exc.headers.items()))
        except PinnedConnectionError as exc:
            raise TaxiiError(f"TAXII egress refused: {exc}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise TaxiiError(f"TAXII request to {url} failed: {exc}") from exc
        if len(payload) > MAX_TAXII_RESPONSE_BYTES:
            raise TaxiiError("TAXII response exceeds the bounded size limit")
        return TaxiiResponse(status, payload, response_headers)


def _parse_envelope(
    response: TaxiiResponse, url: str
) -> tuple[list[dict[str, Any]], bool, str | None]:
    """Validate one response and return ``(objects, more, next-cursor)``."""
    if response.status in (401, 403):
        raise TaxiiError(f"TAXII server refused authorization ({response.status}) for {url}")
    if response.status == 416:
        # Requested range not satisfiable: no more objects. Treat as an empty page.
        return [], False, None
    if response.status != 200:
        raise TaxiiError(f"TAXII server returned HTTP {response.status} for {url}")
    try:
        document: Any = json.loads(response.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TaxiiError(f"TAXII envelope is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise TaxiiError("TAXII envelope is not a JSON object")
    objects = document.get("objects", [])
    if not isinstance(objects, list):
        raise TaxiiError("TAXII envelope 'objects' is not an array")
    if not all(isinstance(item, dict) for item in objects):
        raise TaxiiError("TAXII envelope 'objects' contains a non-object entry")
    more = bool(document.get("more", False))
    cursor = document.get("next")
    next_cursor = str(cursor) if isinstance(cursor, (str, int)) and str(cursor) else None
    return objects, more, next_cursor


def _normalize(bundle: dict[str, Any], source: str) -> ExtractionResult:
    """Parse a collected bundle into the shared ExtractionResult shape.

    Uses the offline STIX parser directly (not the web ``extract_from_source``
    boundary): the live poll is already bounded by object and byte caps, so the
    1 MB pasted-body limit that guards the API surface does not apply here. The
    faithful IOCs are sorted by ``(type, value)`` for a stable, poll-order-
    independent result, exactly as the other extraction surfaces return them.
    """
    try:
        parsed = bundle_to_indicators(json.dumps(bundle))
    except StixError as exc:  # pragma: no cover - we construct the bundle ourselves
        raise TaxiiError(
            f"collected TAXII objects did not form a valid STIX bundle: {exc}"
        ) from exc
    indicators = tuple(
        sorted(
            (ExtractedIndicator(item.indicator_type, item.value) for item in parsed.indicators),
            key=lambda item: (item.indicator_type.value, item.value),
        )
    )
    skipped = tuple(SkippedItem(item.pattern, item.reason) for item in parsed.skipped)
    return ExtractionResult(source_format="stix", indicators=indicators, skipped=skipped)


def poll_collection(
    transport: TaxiiTransport,
    collection: TaxiiCollection,
    *,
    added_after: str | None = None,
    page_limit: int = DEFAULT_PAGE_LIMIT,
    max_objects: int = MAX_TAXII_OBJECTS,
    max_pages: int = MAX_TAXII_PAGES,
    timeout: float = DEFAULT_TIMEOUT,
    environ: Mapping[str, str] | None = None,
) -> TaxiiPollResult:
    """Poll a TAXII 2.1 collection and normalize its STIX objects to IOCs.

    Pages through the collection's ``objects`` endpoint (following the envelope's
    ``more``/``next``), collecting at most ``max_objects`` STIX objects over at
    most ``max_pages`` requests. The objects are wrapped into a STIX 2.1 bundle
    and parsed by the offline STIX normalizer, so the IOCs match a later
    ``stix-import`` of the same bundle exactly. ``added_after`` asks the server
    for only what is new since a prior poll; the returned ``next_added_after`` is
    the cursor to pass next time.

    Raises :class:`TaxiiError` on a transport/protocol failure and
    :class:`TaxiiConfigError` on a bad bound or missing credential.
    """
    if not 1 <= page_limit <= MAX_TAXII_OBJECTS:
        raise TaxiiConfigError(f"page_limit must be between 1 and {MAX_TAXII_OBJECTS}")
    if not 1 <= max_objects <= MAX_TAXII_OBJECTS:
        raise TaxiiConfigError(f"max_objects must be between 1 and {MAX_TAXII_OBJECTS}")
    if not 1 <= max_pages <= MAX_TAXII_PAGES:
        raise TaxiiConfigError(f"max_pages must be between 1 and {MAX_TAXII_PAGES}")
    if timeout <= 0:
        raise TaxiiConfigError("timeout must be positive")

    headers = {"Accept": TAXII_MEDIA_TYPE, **collection.auth_headers(environ)}
    base_url = collection.objects_url

    collected: list[dict[str, Any]] = []
    cursor: str | None = None
    latest_added: str | None = None
    more_available = False
    pages = 0

    while pages < max_pages:
        query: dict[str, str] = {"limit": str(page_limit)}
        if added_after:
            query["added_after"] = added_after
        if cursor:
            query["next"] = cursor
        url = f"{base_url}?{urlencode(query)}"

        response = transport.get(url, headers, timeout=timeout)
        pages += 1
        objects, more, next_cursor = _parse_envelope(response, url)

        header_added = response.header("X-TAXII-Date-Added-Last")
        if header_added:
            latest_added = header_added

        hit_bound = False
        for obj in objects:
            if len(collected) >= max_objects:
                hit_bound = True
                break
            collected.append(obj)

        # Reflect the last page the server gave us; the page-cap exit keeps this.
        more_available = bool(more)
        if hit_bound:
            more_available = True
            break
        if more and next_cursor and len(collected) < max_objects:
            cursor = next_cursor
            continue
        break

    bundle = {"type": "bundle", "id": "bundle--olympus-taxii-poll", "objects": collected}
    result = _normalize(bundle, collection.source_label)

    return TaxiiPollResult(
        source=collection.source_label,
        result=result,
        bundle=bundle,
        objects_fetched=len(collected),
        pages_fetched=pages,
        next_added_after=latest_added or added_after,
        more_available=more_available,
    )


__all__ = [
    "DEFAULT_PAGE_LIMIT",
    "DEFAULT_TIMEOUT",
    "MAX_TAXII_OBJECTS",
    "MAX_TAXII_PAGES",
    "MAX_TAXII_RESPONSE_BYTES",
    "TAXII_MEDIA_TYPE",
    "PinnedTaxiiTransport",
    "TaxiiCollection",
    "TaxiiConfigError",
    "TaxiiError",
    "TaxiiPollResult",
    "TaxiiResponse",
    "TaxiiTransport",
    "poll_collection",
]
