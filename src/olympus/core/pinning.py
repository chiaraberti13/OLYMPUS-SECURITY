"""urllib handlers that connect only to a pre-authorized IP address.

Validating a hostname and then handing the URL to ``urllib`` leaves a
time-of-check/time-of-use window: the guard resolves the name, approves the
answer, and the HTTP stack resolves it *again* at connect time. A DNS server
that returns a public address to the first query and ``127.0.0.1`` to the
second (DNS rebinding) walks straight through the guard.

These handlers close that window. An ``AddressPolicy`` is consulted at connect
time — inside the socket call, with no second resolution afterwards — and the
connection is made to exactly the address the policy returned. TLS is
unaffected: certificate verification still uses the real hostname, so pinning
adds a restriction rather than removing one.

One consequence is deliberate: a pinned request cannot go through an HTTP
proxy. A proxy resolves the destination itself, which is exactly the second
resolution pinning exists to prevent, so a request that would be tunnelled
(``HTTPS_PROXY``/``HTTP_PROXY`` set in the environment) is refused with a clear
error rather than silently losing the guarantee.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import urllib.request
from collections.abc import Callable

from olympus.core.addresses import AddressResolver, resolve_authorized_addresses

#: Maps a hostname to the addresses a caller's policy has authorized for it.
#: Raising from the policy aborts the connection.
AddressPolicy = Callable[[str], tuple[str, ...]]


class PinnedConnectionError(OSError):
    """Raised when no authorized address is available for a host."""


def _connect_pinned(
    policy: AddressPolicy,
    host: str,
    port: int,
    timeout: float | None,
    source_address: tuple[str, int] | None,
) -> socket.socket:
    """Dial the authorized addresses in order, never re-resolving ``host``."""
    try:
        addresses = policy(host)
    except OSError:
        raise
    except Exception as exc:
        # urllib only understands OSError from a handler; keep the policy's
        # reason in the message so callers can still report *why* it refused.
        raise PinnedConnectionError(f"address policy refused {host}: {exc}") from exc
    if not addresses:
        raise PinnedConnectionError(f"no authorized address for {host}")
    last_error: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout, source_address)
        except OSError as exc:  # try the next authorized address (e.g. no IPv6 route)
            last_error = exc
    raise last_error or PinnedConnectionError(f"could not connect to {host}")


def _reject_proxying(connection: http.client.HTTPConnection) -> None:
    """Refuse a CONNECT tunnel: a proxy would resolve the host itself again."""
    if getattr(connection, "_tunnel_host", None):
        raise PinnedConnectionError(
            "pinned connections do not support HTTP proxying: a proxy resolves the "
            "destination itself, which defeats address pinning"
        )


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Plain-HTTP connection that dials the policy's address, not a fresh lookup."""

    address_policy: AddressPolicy

    def connect(self) -> None:
        _reject_proxying(self)
        self.sock = _connect_pinned(
            self.address_policy,
            self.host,
            self.port,
            self.timeout,
            getattr(self, "source_address", None),
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS connection that dials the policy's address but verifies the hostname."""

    address_policy: AddressPolicy

    def connect(self) -> None:
        _reject_proxying(self)
        raw_socket = _connect_pinned(
            self.address_policy,
            self.host,
            self.port,
            self.timeout,
            getattr(self, "source_address", None),
        )
        context = getattr(self, "_context", None) or ssl.create_default_context()
        # ``server_hostname`` stays the real host, so certificate verification
        # is unchanged by pinning.
        self.sock = context.wrap_socket(raw_socket, server_hostname=self.host)


def _connection_classes(
    policy: AddressPolicy,
) -> tuple[type[http.client.HTTPConnection], type[http.client.HTTPSConnection]]:
    """Bind ``policy`` to fresh connection classes (one pair per client)."""
    return (
        type(
            "PinnedHTTPConnection",
            (_PinnedHTTPConnection,),
            {"address_policy": staticmethod(policy)},
        ),
        type(
            "PinnedHTTPSConnection",
            (_PinnedHTTPSConnection,),
            {"address_policy": staticmethod(policy)},
        ),
    )


class PinnedHTTPHandler(urllib.request.HTTPHandler):
    """``http://`` handler wired to a pinned connection class."""

    def __init__(self, policy: AddressPolicy) -> None:
        super().__init__()
        self._connection_class, _ = _connection_classes(policy)

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        """Open ``req`` through the pinned connection class."""
        return self.do_open(self._connection_class, req)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """``https://`` handler wired to a pinned connection class."""

    def __init__(self, policy: AddressPolicy, *, context: ssl.SSLContext | None = None) -> None:
        self._ssl_context = context or ssl.create_default_context()
        super().__init__(context=self._ssl_context)
        _, self._connection_class = _connection_classes(policy)

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        """Open ``req`` through the pinned connection class, verifying the host."""
        return self.do_open(self._connection_class, req, context=self._ssl_context)


def pinned_handlers(
    policy: AddressPolicy, *, context: ssl.SSLContext | None = None
) -> tuple[PinnedHTTPHandler, PinnedHTTPSHandler]:
    """Return the handler pair that pins every hop to ``policy``'s addresses."""
    return PinnedHTTPHandler(policy), PinnedHTTPSHandler(policy, context=context)


def global_address_policy(resolver: AddressResolver = socket.getaddrinfo) -> AddressPolicy:
    """Authorize any host that resolves exclusively to public addresses.

    The policy for fetches whose scope is "the public internet" — public
    registry lookups and OSINT enrichment — where there is no engagement
    allowlist to check but a private destination is still never legitimate.
    """

    def policy(host: str) -> tuple[str, ...]:
        return resolve_authorized_addresses(host.strip().lower().rstrip("."), resolver)

    return policy
