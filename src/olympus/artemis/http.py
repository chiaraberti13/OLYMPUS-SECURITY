"""DNS-pinned, bounded GET-only client with scope validation on every hop."""

from __future__ import annotations

import http.client
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from olympus.artemis.scope import enforce_address_scope, enforce_scope
from olympus.core.decompression import (
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    DEFAULT_MAX_EXPANSION_RATIO,
    DecompressionError,
    decode_body,
)
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled

USER_AGENT = "Olympus-Security-Artemis/0.1 (authorized-recon)"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}

#: Compression only adds an amplification surface to a recon fetch; ask
#: compliant servers to skip it and bound whatever a non-compliant one sends.
ACCEPT_ENCODING = "identity"


class HttpClientError(RuntimeError):
    """Raised for DNS, transport, redirect or response limit failures."""


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class FetchResult:
    response: HttpResponse
    redirects: list[str]


class Resolver(Protocol):
    def resolve(self, hostname: str, port: int) -> list[str]:
        """Resolve a hostname once to candidate connection addresses."""
        ...


class Transport(Protocol):
    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        """GET through one of the already authorized, pinned addresses."""
        ...


class SocketResolver:
    """Production resolver returning unique stream addresses without connecting."""

    def resolve(self, hostname: str, port: int) -> list[str]:
        try:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise HttpClientError(f"DNS resolution failed: {exc}") from exc
        return list(dict.fromkeys(str(record[4][0]) for record in records))


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, address: str, port: int, timeout: float) -> None:
        super().__init__(hostname, port, timeout=timeout)
        self._pinned_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, port: int, timeout: float) -> None:
        self._ssl_context = ssl.create_default_context()
        super().__init__(hostname, port, timeout=timeout, context=self._ssl_context)
        self._pinned_address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._pinned_address, self.port), self.timeout)
        self.sock = self._ssl_context.wrap_socket(raw_socket, server_hostname=self.host)


def _decode_bounded(payload: bytes, encoding: str | None, max_bytes: int) -> bytes:
    """Decode a content-coded body under an absolute cap and an expansion ratio."""
    try:
        return decode_body(
            payload,
            encoding,
            max_output_bytes=min(DEFAULT_MAX_DECOMPRESSED_BYTES, max(max_bytes, 1)),
            max_expansion_ratio=DEFAULT_MAX_EXPANSION_RATIO,
            min_expansion_allowance=min(max_bytes, DEFAULT_MAX_DECOMPRESSED_BYTES),
        )
    except DecompressionError as exc:
        raise HttpClientError(f"response body could not be safely decoded: {exc}") from exc


class PinnedTransport:
    """Production transport that connects to an authorized IP without re-resolving DNS."""

    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise HttpClientError("transport accepts absolute HTTP(S) URLs only")
        if not addresses:
            raise HttpClientError("transport requires a pinned address")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connection_type = (
            _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
        )
        connection = connection_type(parsed.hostname, addresses[0], port, timeout)
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        host_header = parsed.netloc
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": host_header,
                    "User-Agent": USER_AGENT,
                    "Accept-Encoding": ACCEPT_ENCODING,
                },
            )
            response = connection.getresponse()
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise HttpClientError(f"response exceeds {max_bytes} byte limit")
            headers = {key.lower(): value for key, value in response.getheaders()}
            body = _decode_bounded(body, headers.get("content-encoding"), max_bytes)
            return HttpResponse(url, response.status, headers, body)
        except OSError as exc:
            raise HttpClientError(f"HTTP GET failed: {exc}") from exc
        finally:
            connection.close()


def fetch_scoped(
    target: str,
    scope_path: Path,
    log_path: Path,
    resolver: Resolver,
    transport: Transport,
    *,
    policy: ExecutionPolicy,
    max_bytes: int = 1_000_000,
    max_redirects: int = 5,
    cancellation: Cancellation | None = None,
) -> FetchResult:
    """Resolve once per hop, authorize all answers, then connect only to an approved IP."""
    if not 0.1 <= policy.timeout_seconds <= 30.0:
        raise ValueError("timeout must be between 0.1 and 30 seconds")
    if not 1 <= max_bytes <= 10_000_000:
        raise ValueError("max_bytes must be between 1 and 10000000")
    if not 0 <= max_redirects <= 10:
        raise ValueError("max_redirects must be between 0 and 10")
    policy.require_authorization("Artemis scoped HTTP fetch")
    current = enforce_scope(target, scope_path, log_path)
    token = cancellation or NeverCancelled()
    deadline = time.monotonic() + policy.deadline_seconds
    redirects: list[str] = []
    for redirect_count in range(max_redirects + 1):
        policy.check_cancellation(token)
        if time.monotonic() >= deadline:
            raise HttpClientError("overall HTTP deadline exceeded")
        parsed = urlsplit(current.url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        resolved = resolver.resolve(parsed.hostname or "", port)
        approved = enforce_address_scope(current, resolved, scope_path, log_path)
        last_error: HttpClientError | None = None
        response: HttpResponse | None = None
        for attempt in range(policy.retries + 1):
            policy.check_cancellation(token)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HttpClientError("overall HTTP deadline exceeded")
            try:
                response = transport.get(
                    current.url,
                    approved,
                    min(policy.timeout_seconds, remaining),
                    max_bytes,
                )
            except HttpClientError as exc:
                last_error = exc
                if attempt < policy.retries:
                    policy.check_cancellation(token)
                    delay = policy.backoff_seconds * (2**attempt)
                    if delay >= deadline - time.monotonic():
                        raise HttpClientError("overall HTTP deadline exceeded") from exc
                    time.sleep(delay)
            else:
                break
        if response is None:
            raise last_error or HttpClientError("HTTP transport failed")
        if response.status not in REDIRECT_STATUSES:
            return FetchResult(response, redirects)
        location = response.headers.get("location")
        if location is None:
            raise HttpClientError("redirect response is missing Location header")
        if redirect_count == max_redirects:
            raise HttpClientError("redirect limit exceeded")
        current = enforce_scope(urljoin(current.url, location), scope_path, log_path)
        redirects.append(current.url)
    raise HttpClientError("redirect limit exceeded")
