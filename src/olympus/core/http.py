"""Minimal, honest HTTP client shared by Argus OSINT lookups.

Consumers talk to the :class:`HttpClient` protocol, never to ``urllib``
directly, so a real client (production) and a fake in-memory client (tests)
are interchangeable. Every request identifies itself with a fixed, honest
``User-Agent``: Olympus performs *authorized*, transparent security testing
and never impersonates a browser or rotates TLS fingerprints to evade
detection.

This is intentionally separate from Artemis's pinned, scope-safe transport:
it serves passive OSINT enrichment (phone/account lookups) rather than
authorized fetches against a target's own web perimeter.
"""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from olympus.core.decompression import (
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    DEFAULT_MAX_EXPANSION_RATIO,
    DecompressionError,
    decode_body,
)
from olympus.core.execution import (
    Cancellation,
    CancellationRequested,
    ExecutionPolicy,
    NeverCancelled,
)
from olympus.core.pinning import AddressPolicy, PinnedConnectionError, pinned_handlers

#: Honest, fixed identifier sent on every Olympus OSINT HTTP request.
USER_AGENT = "Olympus/1.0 (+authorized-security-testing)"

#: Compression buys nothing for passive recon and only adds an amplification
#: surface, so compliant servers are asked not to use it. A server that
#: compresses anyway is still handled, under the bounds below.
DEFAULT_ACCEPT_ENCODING = "identity"

#: HTTP statuses worth retrying (rate-limited / transient server errors).
_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})

#: Conservative default cap for passive HTTP response bodies (2 MiB).
DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024

#: Explicit application-level response-header bounds. ``http.client`` also
#: has parser guards, but these limits keep the normalized copy predictable.
DEFAULT_MAX_RESPONSE_HEADERS = 100
DEFAULT_MAX_RESPONSE_HEADER_BYTES = 64 * 1024

#: ``urllib`` defaults to ten redirects; expose the bound so callers can
#: tighten it and tests can assert the policy instead of relying on internals.
DEFAULT_MAX_REDIRECTS = 10

#: Small enough to observe cancellation promptly without excessive read calls.
_RESPONSE_CHUNK_BYTES = 64 * 1024

#: Maximum interval between cancellation checks while waiting.
_CANCELLATION_POLL_SECONDS = 0.1


@dataclass(frozen=True)
class HttpResponse:
    """A normalized HTTP response: status, headers, and body text."""

    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


class HttpClient(Protocol):
    """Anything able to perform a passive HTTP GET request."""

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Return the response for a GET request to ``url``, with optional extra headers."""
        ...


class _ReadableBody(Protocol):
    def read(self, amount: int = -1) -> bytes:
        """Read up to ``amount`` bytes from a response body."""
        ...


class _HeaderLookup(Protocol):
    def get(self, name: str, default: str | None = None) -> str | None:
        """Return one HTTP header value."""
        ...


class HttpRequestError(RuntimeError):
    """Raised when the HTTP request fails (network error, timeout...)."""


class HttpResponseTooLarge(HttpRequestError):
    """Raised when a response exceeds the configured in-memory body limit."""


class HttpResponseHeadersTooLarge(HttpRequestError):
    """Raised when response header count or aggregate size exceeds policy."""


class HttpResponseUndecodable(HttpRequestError):
    """Raised when a compressed body is malformed, unsupported, or a bomb."""


class HttpAddressPolicyError(HttpRequestError):
    """Raised when the connect-time address policy refused a destination."""


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Validate every redirect destination before urllib follows it."""

    def __init__(
        self,
        validator: Callable[[str], None],
        *,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
    ) -> None:
        self._validator = validator
        self.max_redirections = max_redirects

    def redirect_request(  # type: ignore[no-untyped-def]
        self, req, fp, code, msg, headers, newurl
    ):
        self._validator(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class UrllibHttpClient:
    """Production :class:`HttpClient` backed by ``urllib``.

    Robust for real-network use: bounded ``timeout``, automatic retries with
    exponential backoff on transient failures (network errors and 429/5xx),
    and an optional client-side rate limit (a minimum interval between
    requests) so bulk lookups stay polite.

    ``jitter`` (0-1, off by default) spreads each backoff wait over that
    fraction of its computed value. Without it every client that hits the same
    struggling endpoint retries on the same tick and keeps it struggling; with
    it the retries spread out. Backoff is always capped at
    ``MAX_BACKOFF_SECONDS`` on top of the overall deadline.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        *,
        retries: int = 2,
        backoff: float = 0.5,
        jitter: float = 0.0,
        min_interval: float = 0.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_response_headers: int = DEFAULT_MAX_RESPONSE_HEADERS,
        max_response_header_bytes: int = DEFAULT_MAX_RESPONSE_HEADER_BYTES,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
        max_expansion_ratio: float = DEFAULT_MAX_EXPANSION_RATIO,
        deadline_seconds: float | None = None,
        redirect_validator: Callable[[str], None] | None = None,
        address_policy: AddressPolicy | None = None,
        cancellation: Cancellation | None = None,
    ) -> None:
        effective_deadline = (
            deadline_seconds if deadline_seconds is not None else max(timeout, 600.0)
        )
        self._policy = ExecutionPolicy(
            authorized=True,
            timeout_seconds=timeout,
            deadline_seconds=effective_deadline,
            retries=retries,
            backoff_seconds=backoff,
            min_interval_seconds=min_interval,
            jitter_ratio=jitter,
        )
        self._timeout = self._policy.timeout_seconds
        self._retries = self._policy.retries
        self._min_interval = self._policy.min_interval_seconds
        if not isinstance(max_response_bytes, int) or isinstance(max_response_bytes, bool):
            raise ValueError("max_response_bytes must be an integer")
        if not 1 <= max_response_bytes <= 100 * 1024 * 1024:
            raise ValueError("max_response_bytes must be between 1 and 104857600")
        self._max_response_bytes = max_response_bytes
        if not isinstance(max_response_headers, int) or isinstance(max_response_headers, bool):
            raise ValueError("max_response_headers must be an integer")
        if not 1 <= max_response_headers <= 1_000:
            raise ValueError("max_response_headers must be between 1 and 1000")
        if not isinstance(max_response_header_bytes, int) or isinstance(
            max_response_header_bytes, bool
        ):
            raise ValueError("max_response_header_bytes must be an integer")
        if not 1 <= max_response_header_bytes <= 1024 * 1024:
            raise ValueError("max_response_header_bytes must be between 1 and 1048576")
        if not isinstance(max_redirects, int) or isinstance(max_redirects, bool):
            raise ValueError("max_redirects must be an integer")
        if not 0 <= max_redirects <= DEFAULT_MAX_REDIRECTS:
            raise ValueError(f"max_redirects must be between 0 and {DEFAULT_MAX_REDIRECTS}")
        if not isinstance(max_decompressed_bytes, int) or isinstance(max_decompressed_bytes, bool):
            raise ValueError("max_decompressed_bytes must be an integer")
        if not 1 <= max_decompressed_bytes <= 100 * 1024 * 1024:
            raise ValueError("max_decompressed_bytes must be between 1 and 104857600")
        if isinstance(max_expansion_ratio, bool) or not isinstance(
            max_expansion_ratio, (int, float)
        ):
            raise ValueError("max_expansion_ratio must be a number")
        if not 1.0 <= float(max_expansion_ratio) <= 10_000.0:
            raise ValueError("max_expansion_ratio must be between 1.0 and 10000.0")
        self._max_response_headers = max_response_headers
        self._max_response_header_bytes = max_response_header_bytes
        self._max_redirects = max_redirects
        self._max_decompressed_bytes = max_decompressed_bytes
        self._max_expansion_ratio = float(max_expansion_ratio)
        self._deadline_seconds = self._policy.deadline_seconds
        self._cancellation = cancellation or NeverCancelled()
        self._last_request_at = 0.0
        self._throttle_lock = threading.Lock()
        validator = redirect_validator or (lambda _url: None)
        needs_opener = (
            redirect_validator is not None
            or address_policy is not None
            or max_redirects != DEFAULT_MAX_REDIRECTS
        )
        handlers: list[urllib.request.BaseHandler] = [
            _ValidatingRedirectHandler(validator, max_redirects=max_redirects)
        ]
        if address_policy is not None:
            # Pinning must survive redirects too: the same policy authorizes
            # every hop's address at the moment the socket is opened.
            handlers.extend(pinned_handlers(address_policy))
            # A pinned opener must NEVER proxy, for any scheme: a proxy resolves
            # the destination itself, defeating the pin. An explicit empty
            # ProxyHandler stops build_opener from adding the env-reading default
            # (which would silently proxy a plain-HTTP pinned request even though
            # the HTTPS CONNECT tunnel is already refused).
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers) if needs_opener else None

    @classmethod
    def from_policy(
        cls,
        policy: ExecutionPolicy,
        *,
        redirect_validator: Callable[[str], None] | None = None,
        address_policy: AddressPolicy | None = None,
        cancellation: Cancellation | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_response_headers: int = DEFAULT_MAX_RESPONSE_HEADERS,
        max_response_header_bytes: int = DEFAULT_MAX_RESPONSE_HEADER_BYTES,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES,
        max_expansion_ratio: float = DEFAULT_MAX_EXPANSION_RATIO,
    ) -> UrllibHttpClient:
        """Build a client from the shared validated execution policy."""
        return cls(
            policy.timeout_seconds,
            retries=policy.retries,
            backoff=policy.backoff_seconds,
            jitter=policy.jitter_ratio,
            min_interval=policy.min_interval_seconds,
            max_response_bytes=max_response_bytes,
            max_response_headers=max_response_headers,
            max_response_header_bytes=max_response_header_bytes,
            max_redirects=max_redirects,
            max_decompressed_bytes=max_decompressed_bytes,
            max_expansion_ratio=max_expansion_ratio,
            deadline_seconds=policy.deadline_seconds,
            redirect_validator=redirect_validator,
            address_policy=address_policy,
            cancellation=cancellation,
        )

    @classmethod
    def from_config(
        cls,
        *,
        min_interval: float | None = None,
        redirect_validator: Callable[[str], None] | None = None,
        address_policy: AddressPolicy | None = None,
    ) -> UrllibHttpClient:
        """Build a client using ``[http]`` config defaults (CLI overrides win).

        ``min_interval`` from the caller (e.g. a ``--rate`` flag) takes
        precedence over the config file; everything else comes from ``[http]``.
        """
        from olympus.core import config

        data = config.load_config()
        rate = min_interval if min_interval is not None else config.get("http", "rate", 0.0, data)
        timeout = config.get("http", "timeout", 10.0, data)
        return cls(
            timeout,
            retries=config.get("http", "retries", 2, data),
            backoff=config.get("http", "backoff", 0.5, data),
            jitter=config.get("http", "jitter", 0.0, data),
            min_interval=rate,
            max_response_bytes=config.get(
                "http", "max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES, data
            ),
            max_response_headers=config.get(
                "http", "max_response_headers", DEFAULT_MAX_RESPONSE_HEADERS, data
            ),
            max_response_header_bytes=config.get(
                "http", "max_response_header_bytes", DEFAULT_MAX_RESPONSE_HEADER_BYTES, data
            ),
            max_redirects=config.get("http", "max_redirects", DEFAULT_MAX_REDIRECTS, data),
            max_decompressed_bytes=config.get(
                "http", "max_decompressed_bytes", DEFAULT_MAX_DECOMPRESSED_BYTES, data
            ),
            max_expansion_ratio=config.get(
                "http", "max_expansion_ratio", DEFAULT_MAX_EXPANSION_RATIO, data
            ),
            deadline_seconds=config.get("http", "deadline", max(timeout, 600.0), data),
            redirect_validator=redirect_validator,
            address_policy=address_policy,
        )

    def _check_cancelled(self) -> None:
        try:
            self._policy.check_cancellation(self._cancellation)
        except CancellationRequested as exc:
            raise HttpRequestError("HTTP request cancelled") from exc

    def _throttle(self, *, deadline_at: float | None = None) -> None:
        """Sleep just enough to honor the configured minimum request interval."""
        if self._min_interval <= 0.0:
            return
        # Account enumeration shares one client across a thread pool. Serialize
        # dispatch timing so concurrent workers cannot bypass the configured rate.
        with self._throttle_lock:
            elapsed = time.monotonic() - self._last_request_at
            if 0.0 <= elapsed < self._min_interval:
                self._sleep_interruptibly(
                    self._min_interval - elapsed, deadline_at=deadline_at
                )
            self._last_request_at = time.monotonic()

    @staticmethod
    def _check_deadline(deadline_at: float) -> float:
        remaining = deadline_at - time.monotonic()
        if remaining <= 0.0:
            raise HttpRequestError("HTTP operation deadline exceeded")
        return remaining

    def _sleep_interruptibly(self, seconds: float, *, deadline_at: float | None = None) -> None:
        """Sleep in bounded slices so cancellation interrupts waits promptly."""
        remaining = max(0.0, seconds)
        while remaining > 0.0:
            self._check_cancelled()
            interval = min(_CANCELLATION_POLL_SECONDS, remaining)
            if deadline_at is not None:
                interval = min(interval, self._check_deadline(deadline_at))
            time.sleep(interval)
            remaining -= interval
        self._check_cancelled()
        if deadline_at is not None:
            self._check_deadline(deadline_at)

    def _copy_bounded_headers(self, headers: object, url: str) -> dict[str, str]:
        """Copy headers only after enforcing count and aggregate encoded size."""
        try:
            items = list(headers.items())  # type: ignore[union-attr]
        except AttributeError:
            items = []
        if len(items) > self._max_response_headers:
            raise HttpResponseHeadersTooLarge(
                f"HTTP response for {url} exceeds the {self._max_response_headers} header limit"
            )
        total = 0
        normalized: dict[str, str] = {}
        for raw_name, raw_value in items:
            name = str(raw_name)
            value = str(raw_value)
            total += len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
            if total > self._max_response_header_bytes:
                raise HttpResponseHeadersTooLarge(
                    f"HTTP response headers for {url} exceed the "
                    f"{self._max_response_header_bytes} byte limit"
                )
            normalized[name] = value
        return normalized

    def _read_bounded(self, stream: _ReadableBody, url: str) -> bytes:
        """Read a body incrementally with a hard in-memory and transfer cap."""
        body = bytearray()
        while len(body) <= self._max_response_bytes:
            self._check_cancelled()
            remaining = self._max_response_bytes + 1 - len(body)
            chunk = stream.read(min(_RESPONSE_CHUNK_BYTES, remaining))
            if not chunk:
                break
            body.extend(chunk)
        if len(body) > self._max_response_bytes:
            raise HttpResponseTooLarge(
                f"HTTP response for {url} exceeds the {self._max_response_bytes} byte limit"
            )
        return bytes(body)

    def _reject_oversized_content_length(
        self, headers: _HeaderLookup | None, url: str
    ) -> None:
        """Fail early when a trustworthy numeric Content-Length is already too large."""
        if headers is None:
            return
        try:
            raw_value = headers.get("Content-Length")
            content_length = int(raw_value) if raw_value is not None else None
        except (TypeError, ValueError):
            return
        if content_length is not None and content_length > self._max_response_bytes:
            raise HttpResponseTooLarge(
                f"HTTP response for {url} declares {content_length} bytes, exceeding the "
                f"{self._max_response_bytes} byte limit"
            )

    def _decode_bounded(self, payload: bytes, headers: object, url: str) -> bytes:
        """Decode a content-coded body under absolute and ratio bounds."""
        encoding: str | None = None
        getter = getattr(headers, "get", None)
        if callable(getter):
            raw = getter("Content-Encoding")
            encoding = str(raw) if raw is not None else None
        try:
            return decode_body(
                payload,
                encoding,
                max_output_bytes=self._max_decompressed_bytes,
                max_expansion_ratio=self._max_expansion_ratio,
            )
        except DecompressionError as exc:
            raise HttpResponseUndecodable(
                f"HTTP response body for {url} could not be safely decoded: {exc}"
            ) from exc

    def _perform(
        self, request: urllib.request.Request, url: str, *, timeout: float
    ) -> HttpResponse:
        try:
            open_request = self._opener.open if self._opener is not None else urllib.request.urlopen
            with open_request(request, timeout=timeout) as response:
                response_headers = self._copy_bounded_headers(response.headers, url)
                self._reject_oversized_content_length(response.headers, url)
                body_bytes = self._decode_bounded(
                    self._read_bounded(response, url), response.headers, url
                )
                status_code = response.status
        except urllib.error.HTTPError as exc:
            response_headers = self._copy_bounded_headers(exc.headers or {}, url)
            self._reject_oversized_content_length(exc.headers, url)
            body_bytes = self._decode_bounded(
                self._read_bounded(exc, url), exc.headers, url
            )
            status_code = exc.code
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, PinnedConnectionError):
                raise HttpAddressPolicyError(
                    f"HTTP GET for {url} was refused by the address policy: {exc.reason}"
                ) from exc
            raise HttpRequestError(f"HTTP GET failed for {url}: {exc}") from exc
        except TimeoutError as exc:
            raise HttpRequestError(f"HTTP GET failed for {url}: {exc}") from exc
        return HttpResponse(
            status_code=status_code,
            headers=response_headers,
            body=body_bytes.decode("utf-8", errors="replace"),
        )

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Perform an HTTP GET with retry/backoff/rate-limit, returning a response."""
        if not url.startswith(("http://", "https://")):
            raise HttpRequestError(f"refusing to fetch a non-HTTP(S) URL: {url}")

        request_headers = {
            "User-Agent": USER_AGENT,
            "Accept-Encoding": DEFAULT_ACCEPT_ENCODING,
            **(headers or {}),
        }
        request = urllib.request.Request(  # noqa: S310 (scheme already checked above)
            url, headers=request_headers
        )
        deadline_at = time.monotonic() + self._deadline_seconds

        last_error: HttpRequestError | None = None
        for attempt in range(self._retries + 1):
            self._check_cancelled()
            self._check_deadline(deadline_at)
            self._throttle(deadline_at=deadline_at)
            remaining = self._check_deadline(deadline_at)
            try:
                response = self._perform(request, url, timeout=min(self._timeout, remaining))
            except (
                HttpResponseTooLarge,
                HttpResponseHeadersTooLarge,
                HttpResponseUndecodable,
                HttpAddressPolicyError,
            ):
                # Retrying a deterministic policy violation (size, encoding, or a
                # refused destination) only wastes bandwidth.
                raise
            except HttpRequestError as exc:
                last_error = exc
            else:
                if response.status_code not in _RETRYABLE_STATUSES:
                    return response
                last_error = HttpRequestError(
                    f"HTTP GET for {url} returned retryable status {response.status_code}"
                )
                if attempt == self._retries:
                    return response  # out of retries: hand back the last response
            if attempt < self._retries:
                self._sleep_interruptibly(
                    self._policy.next_backoff(attempt + 1), deadline_at=deadline_at
                )

        raise last_error or HttpRequestError(f"HTTP GET failed for {url}")
