"""Tests that a validated address is the address actually connected to.

These are the DNS-rebinding regression tests: a resolver that answers
truthfully once and maliciously afterwards must not be able to move the
connection, because the socket is opened against the address the policy
returned rather than against a fresh lookup.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from olympus.core.addresses import NonGlobalAddressError
from olympus.core.http import HttpAddressPolicyError, UrllibHttpClient
from olympus.core.pinning import (
    PinnedConnectionError,
    _connect_pinned,
    global_address_policy,
    pinned_handlers,
)


class _FakeSocket:
    def __init__(self, address: tuple[str, int]) -> None:
        self.address = address

    def close(self) -> None:
        return None


def _record_connections(
    monkeypatch: pytest.MonkeyPatch, *, failing: tuple[str, ...] = ()
) -> list[tuple[str, int]]:
    attempted: list[tuple[str, int]] = []

    def fake_create_connection(
        address: tuple[str, int], timeout: object = None, source_address: object = None
    ) -> _FakeSocket:
        attempted.append(address)
        if address[0] in failing:
            raise OSError(f"no route to {address[0]}")
        return _FakeSocket(address)

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    return attempted


def test_connects_to_the_address_the_policy_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    attempted = _record_connections(monkeypatch)

    _connect_pinned(lambda host: ("93.184.216.34",), "example.test", 443, 5.0, None)

    assert attempted == [("93.184.216.34", 443)]


def test_falls_through_to_the_next_authorized_address(monkeypatch: pytest.MonkeyPatch) -> None:
    attempted = _record_connections(monkeypatch, failing=("2001:db8::2",))

    _connect_pinned(lambda host: ("2001:db8::2", "93.184.216.34"), "example.test", 80, 5.0, None)

    assert attempted == [("2001:db8::2", 80), ("93.184.216.34", 80)]


def test_an_empty_policy_answer_refuses_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _record_connections(monkeypatch)

    with pytest.raises(PinnedConnectionError, match="no authorized address"):
        _connect_pinned(lambda host: (), "example.test", 443, 5.0, None)


def test_a_policy_refusal_becomes_an_oserror_urllib_can_carry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _record_connections(monkeypatch)

    def refuse(host: str) -> tuple[str, ...]:
        raise NonGlobalAddressError(f"host {host} resolves to non-global address 127.0.0.1")

    with pytest.raises(PinnedConnectionError, match="non-global"):
        _connect_pinned(refuse, "rebind.test", 443, 5.0, None)


def test_dns_rebinding_cannot_move_the_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    """The first lookup answers publicly; every later one would return loopback."""
    lookups = 0

    def rebinding_resolver(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        nonlocal lookups
        lookups += 1
        if lookups == 1:
            return [(2, 1, 6, "", ("93.184.216.34", 0))]
        return [(2, 1, 6, "", ("127.0.0.1", 0))]

    attempted = _record_connections(monkeypatch)

    _connect_pinned(global_address_policy(rebinding_resolver), "rebind.test", 443, 5.0, None)

    # One lookup, and the socket goes to exactly what that lookup authorized.
    assert lookups == 1
    assert attempted == [("93.184.216.34", 443)]


def test_rebinding_before_the_socket_is_still_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the rebind lands *before* connect, the policy itself refuses it."""
    _record_connections(monkeypatch)

    def loopback_resolver(host: str, port: object, **kwargs: object) -> list[tuple[Any, ...]]:
        return [(2, 1, 6, "", ("127.0.0.1", 0))]

    with pytest.raises(PinnedConnectionError, match="non-global"):
        _connect_pinned(global_address_policy(loopback_resolver), "rebind.test", 443, 5.0, None)


def test_handlers_bind_distinct_policies_per_client() -> None:
    http_one, https_one = pinned_handlers(lambda host: ("198.51.100.1",))
    http_two, https_two = pinned_handlers(lambda host: ("203.0.113.1",))

    assert http_one._connection_class is not http_two._connection_class
    assert https_one._connection_class is not https_two._connection_class
    assert http_one._connection_class.address_policy("any") == ("198.51.100.1",)
    assert https_two._connection_class.address_policy("any") == ("203.0.113.1",)


def test_client_reports_a_policy_refusal_without_retrying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _record_connections(monkeypatch)
    calls = 0

    def refuse(host: str) -> tuple[str, ...]:
        nonlocal calls
        calls += 1
        raise NonGlobalAddressError(f"host {host} resolves to non-global address 127.0.0.1")

    client = UrllibHttpClient(retries=3, address_policy=refuse)

    with pytest.raises(HttpAddressPolicyError, match="refused by the address policy"):
        client.get("http://rebind.test/")
    assert calls == 1


def test_a_proxied_request_is_refused_rather_than_silently_unpinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CONNECT tunnel would let the proxy resolve the host — pinning's whole point."""
    attempted = _record_connections(monkeypatch)
    _, https_handler = pinned_handlers(lambda host: ("93.184.216.34",))
    connection = https_handler._connection_class("example.test", timeout=5.0)
    connection.set_tunnel("internal.example.test", 443)

    with pytest.raises(PinnedConnectionError, match="proxying"):
        connection.connect()
    assert attempted == []
