"""One shared answer to "may Olympus connect to this IP address?".

``ipaddress.ip_address(...).is_global`` is close, but not close enough for an
SSRF guard. Several IPv6 forms embed an IPv4 address that the host stack will
happily route to a private destination, yet the wrapper itself is classified
as global:

* ``::ffff:127.0.0.1`` — IPv4-mapped (``is_global`` already says ``False``);
* ``::127.0.0.1`` — deprecated IPv4-compatible, ``is_global`` says **True**;
* ``64:ff9b::7f00:1`` — the well-known NAT64 prefix, ``is_global`` says **True**;
* ``2002:7f00:1::`` / Teredo — 6to4 and Teredo, which also carry an IPv4.

IPv6 multicast (``ff00::/8``) is likewise reported as global.

Everything that reaches the network therefore goes through
:func:`ensure_globally_routable`, which unwraps embedded IPv4 before judging.

The single, explicit exception is the **lab allowlist**: an operator who owns a
private range may declare it in ``[lab].allowed_networks`` of the policy file
(see :mod:`olympus.core.policy`). :func:`is_authorized_destination` is the only
entry point that honours it; :func:`is_globally_routable` stays a pure statement
about the address itself and is never widened by configuration.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
from typing import Any

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Well-known NAT64 prefix (RFC 6052). ``64:ff9b:1::/48`` is already non-global.
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")

#: Deprecated IPv4-compatible IPv6 addresses (RFC 4291 §2.5.5.1).
_IPV4_COMPATIBLE = ipaddress.IPv6Network("::/96")

#: How deep an embedded-address chain may be unwrapped before giving up.
_MAX_UNWRAP_DEPTH = 4


class NonGlobalAddressError(ValueError):
    """Raised when an address is not a legitimate public destination."""


class AddressResolutionError(RuntimeError):
    """Raised when a hostname cannot be resolved to usable addresses."""


#: ``socket.getaddrinfo``-shaped callable, so tests can inject answer sets.
AddressResolver = Callable[..., Iterable[tuple[Any, ...]]]


def parse_address(raw: str) -> IPAddress:
    """Parse ``raw`` into an IP address, dropping any IPv6 zone identifier."""
    candidate = raw.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    candidate = candidate.split("%", 1)[0]
    try:
        return ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise NonGlobalAddressError(f"{raw!r} is not an IP address") from exc


def embedded_ipv4(address: IPAddress) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address an IPv6 wrapper carries, if it carries one."""
    if not isinstance(address, ipaddress.IPv6Address):
        return None
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address.teredo is not None:
        # (server, client): the client address is the one a request reaches.
        return address.teredo[1]
    if address in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if address in _IPV4_COMPATIBLE and int(address) > 1:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def is_globally_routable(address: IPAddress) -> bool:
    """Return whether ``address`` is a public destination Olympus may contact.

    Loopback, private, link-local, multicast, reserved, unspecified and
    carrier-grade-NAT space are all refused, for the address itself and for any
    IPv4 address embedded in an IPv6 wrapper.
    """
    current = address
    for _ in range(_MAX_UNWRAP_DEPTH):
        # Judge what the packet actually reaches: several wrappers (NAT64,
        # 6to4) sit in prefixes Python calls "reserved", so unwrap first and
        # classify the embedded IPv4 instead of the envelope.
        nested = embedded_ipv4(current)
        if nested is not None:
            current = nested
            continue
        if (
            current.is_multicast
            or current.is_loopback
            or current.is_link_local
            or current.is_private
            or current.is_reserved
            or current.is_unspecified
        ):
            return False
        return current.is_global
    return False


def ensure_globally_routable(raw: str) -> IPAddress:
    """Parse and authorize one address, or raise :class:`NonGlobalAddressError`."""
    address = parse_address(raw)
    if not is_globally_routable(address):
        raise NonGlobalAddressError(f"{address} is not a globally routable address")
    return address


def active_lab_networks() -> tuple[IPNetwork, ...]:
    """Return the private ranges the active policy declares as operator-owned.

    Imported lazily so this module — the lowest layer of the SSRF guard — keeps
    no import-time dependency on the policy loader. With no policy file the
    result is empty and every check below behaves exactly as it always has.
    """
    from olympus.core.policy import active_policy

    return active_policy().lab_networks()


def _unwrapped(address: IPAddress) -> IPAddress:
    """Return the address a packet actually reaches, unwrapping embedded IPv4."""
    current = address
    for _ in range(_MAX_UNWRAP_DEPTH):
        nested = embedded_ipv4(current)
        if nested is None:
            return current
        current = nested
    return current


def is_authorized_destination(
    address: IPAddress,
    lab_networks: Iterable[IPNetwork] | None = None,
) -> bool:
    """Return whether Olympus may contact ``address`` under the active policy.

    A public address is authorized as usual. A private one is authorized only
    when it falls inside a range the operator explicitly declared in the lab
    profile — the wrapper forms are unwrapped first, so ``::ffff:10.10.0.1`` is
    judged as ``10.10.0.1`` rather than slipping past the allowlist.
    """
    if is_globally_routable(address):
        return True
    networks = active_lab_networks() if lab_networks is None else tuple(lab_networks)
    if not networks:
        return False
    candidate = _unwrapped(address)
    return any(candidate in network for network in networks)


def ensure_authorized_destination(
    raw: str,
    lab_networks: Iterable[IPNetwork] | None = None,
) -> IPAddress:
    """Parse and authorize one address, honouring the declared lab ranges."""
    address = parse_address(raw)
    if not is_authorized_destination(address, lab_networks):
        raise NonGlobalAddressError(f"{address} is not an authorized destination")
    return address


def resolve_authorized_addresses(
    host: str,
    resolver: AddressResolver = socket.getaddrinfo,
    lab_networks: Iterable[IPNetwork] | None = None,
) -> tuple[str, ...]:
    """Resolve ``host``, refusing the whole answer set if any address is unsafe.

    Rejecting the entire set — rather than filtering it — is deliberate: a name
    that mixes a public address with a loopback one must not be reachable at
    all, because the connecting stack, not Olympus, would pick the address.
    """
    try:
        answers = resolver(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise AddressResolutionError(f"host {host} could not be resolved") from exc

    addresses: set[str] = set()
    for answer in answers:
        try:
            address = parse_address(str(answer[4][0]))
        except (IndexError, TypeError, NonGlobalAddressError) as exc:
            raise AddressResolutionError(
                f"resolver returned an invalid address for {host}"
            ) from exc
        if not is_authorized_destination(address, lab_networks):
            raise NonGlobalAddressError(f"host {host} resolves to non-global address {address}")
        addresses.add(str(address))
    if not addresses:
        raise AddressResolutionError(f"host {host} resolved to no addresses")
    return tuple(sorted(addresses))
