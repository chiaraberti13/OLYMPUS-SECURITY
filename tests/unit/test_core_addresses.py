"""Address-policy tests: what Olympus may and may not connect to."""

from __future__ import annotations

import pytest

from olympus.core.addresses import (
    AddressResolutionError,
    NonGlobalAddressError,
    embedded_ipv4,
    ensure_globally_routable,
    is_globally_routable,
    parse_address,
    resolve_authorized_addresses,
)

PUBLIC = (
    "8.8.8.8",
    "93.184.216.34",
    "2001:4860:4860::8888",
    "::ffff:8.8.8.8",  # IPv4-mapped wrapper around a public address
)

BLOCKED = (
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",  # cloud metadata service
    "100.64.0.1",  # carrier-grade NAT
    "0.0.0.0",  # noqa: S104 - unspecified address, asserted to be refused
    "224.0.0.1",  # IPv4 multicast
    "192.0.2.1",  # documentation range
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "2001:db8::1",
    "ff02::1",  # IPv6 multicast: ipaddress.is_global alone calls this global
    "::ffff:127.0.0.1",  # IPv4-mapped loopback
    "::ffff:169.254.169.254",  # IPv4-mapped metadata service
    "::127.0.0.1",  # deprecated IPv4-compatible form
    "64:ff9b::7f00:1",  # NAT64-wrapped loopback
    "64:ff9b::a00:1",  # NAT64-wrapped RFC1918
    "2002:7f00:1::",  # 6to4-wrapped loopback
)


@pytest.mark.parametrize("literal", PUBLIC)
def test_public_addresses_are_reachable(literal: str) -> None:
    assert is_globally_routable(parse_address(literal)) is True
    assert ensure_globally_routable(literal) == parse_address(literal)


@pytest.mark.parametrize("literal", BLOCKED)
def test_private_and_wrapped_addresses_are_refused(literal: str) -> None:
    assert is_globally_routable(parse_address(literal)) is False
    with pytest.raises(NonGlobalAddressError):
        ensure_globally_routable(literal)


def test_embedded_ipv4_is_extracted_from_every_wrapper_form() -> None:
    assert str(embedded_ipv4(parse_address("::ffff:8.8.8.8"))) == "8.8.8.8"
    assert str(embedded_ipv4(parse_address("64:ff9b::7f00:1"))) == "127.0.0.1"
    assert str(embedded_ipv4(parse_address("2002:7f00:1::"))) == "127.0.0.1"
    assert str(embedded_ipv4(parse_address("::127.0.0.1"))) == "127.0.0.1"
    assert embedded_ipv4(parse_address("2001:4860:4860::8888")) is None
    assert embedded_ipv4(parse_address("8.8.8.8")) is None


def test_scope_identifiers_and_brackets_are_stripped_before_parsing() -> None:
    assert str(parse_address("[2001:4860:4860::8888]")) == "2001:4860:4860::8888"
    assert str(parse_address("fe80::1%eth0")) == "fe80::1"
    with pytest.raises(NonGlobalAddressError):
        parse_address("not-an-address")


def test_resolution_rejects_a_mixed_answer_set_outright() -> None:
    def mixed(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ]

    with pytest.raises(NonGlobalAddressError, match=r"127\.0\.0\.1"):
        resolve_authorized_addresses("mixed.example", mixed)


def test_resolution_rejects_an_ipv4_mapped_answer() -> None:
    def mapped(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [(10, 1, 6, "", ("::ffff:127.0.0.1", 0, 0, 0))]

    with pytest.raises(NonGlobalAddressError):
        resolve_authorized_addresses("mapped.example", mapped)


def test_resolution_fails_closed_on_empty_and_broken_answers() -> None:
    with pytest.raises(AddressResolutionError, match="no addresses"):
        resolve_authorized_addresses("empty.example", lambda *a, **k: [])

    def broken(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [(2, 1, 6, "", ("not-an-address", 0))]

    with pytest.raises(AddressResolutionError, match="invalid address"):
        resolve_authorized_addresses("broken.example", broken)

    def failing(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        raise OSError("dns down")

    with pytest.raises(AddressResolutionError, match="could not be resolved"):
        resolve_authorized_addresses("down.example", failing)


def test_resolution_returns_sorted_unique_public_addresses() -> None:
    def answers(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (2, 1, 6, "", ("8.8.8.8", 0)),
        ]

    assert resolve_authorized_addresses("dual.example", answers) == ("8.8.8.8", "93.184.216.34")
