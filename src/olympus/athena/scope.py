"""Target validation and SSRF protection for Athena adapters.

Every adapter re-validates its target here immediately before doing any
network work, independently of the plan-time check. Two guarantees:

* the target host is inside the plan's authorized scope; and
* active web targets cannot resolve to a private, loopback, link-local, or
  otherwise non-global address (a classic SSRF pivot).
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from olympus.core.addresses import (
    AddressResolutionError,
    AddressResolver,
    NonGlobalAddressError,
    is_authorized_destination,
    parse_address,
    resolve_authorized_addresses,
)
from olympus.core.pinning import AddressPolicy


class TargetValidationError(ValueError):
    """Raised when a target is malformed."""


class TargetOutOfScopeError(RuntimeError):
    """Raised when a target host is outside the authorized scope."""


class SsrfBlockedError(RuntimeError):
    """Raised when a target host resolves to a non-global IP address."""


class TargetResolutionError(RuntimeError):
    """Raised when an active web target cannot be resolved safely."""


def host_of(target_kind: str, target_value: str) -> str:
    """Return the bare host for a ``domain`` or ``url`` target."""
    if target_kind == "domain":
        host = target_value.strip().lower().rstrip(".")
        if "/" in host or " " in host or "." not in host:
            raise TargetValidationError(f"invalid domain target: {target_value!r}")
        return host
    if target_kind == "url":
        value = target_value.strip()
        if "://" not in value:
            value = "https://" + value
        parsed = urlparse(value)
        if not parsed.hostname:
            raise TargetValidationError(f"invalid url target: {target_value!r}")
        return parsed.hostname
    raise TargetValidationError(f"unsupported target kind: {target_kind!r}")


def _reject_non_global_ip(host: str) -> None:
    try:
        address = parse_address(host)
    except NonGlobalAddressError:
        return  # not an IP literal; a hostname is resolved by the network layer
    # The policy-aware predicate, so an IP literal inside a declared lab range is
    # treated exactly like the hostname form already is by resolve_global_addresses.
    if not is_authorized_destination(address):
        raise SsrfBlockedError(
            f"target host {host} is a non-global IP address and is blocked (SSRF guard)"
        )


def _reject_out_of_scope(host: str, allowed_domains: tuple[str, ...]) -> None:
    """Raise unless ``host`` is covered by the engagement's allowed domains."""
    normalized = host.strip().lower().rstrip(".")
    covered = any(
        normalized == allowed.strip().lower().rstrip(".")
        or normalized.endswith(f".{allowed.strip().lower().rstrip('.')}")
        for allowed in allowed_domains
    )
    if not covered:
        raise TargetOutOfScopeError(f"target host {host} is out of scope")


def resolve_global_addresses(
    host: str,
    resolver: AddressResolver = socket.getaddrinfo,
) -> tuple[str, ...]:
    """Resolve ``host`` and reject the whole answer set if any address is non-global.

    Thin Athena-flavoured wrapper over the shared address policy, so callers keep
    seeing Athena's error vocabulary.
    """
    try:
        return resolve_authorized_addresses(host, resolver)
    except NonGlobalAddressError as exc:
        raise SsrfBlockedError(f"{exc} and is blocked (SSRF guard)") from exc
    except AddressResolutionError as exc:
        raise TargetResolutionError(f"target {exc}") from exc


def ensure_target_allowed(
    target_kind: str,
    target_value: str,
    allowed_domains: tuple[str, ...],
) -> str:
    """Validate a target and confirm it is in scope and not an SSRF pivot.

    Returns the validated host on success; raises the appropriate error
    otherwise.
    """
    host = host_of(target_kind, target_value)
    _reject_non_global_ip(host)
    _reject_out_of_scope(host, allowed_domains)
    return host


def ensure_web_target_allowed(
    target_kind: str,
    target_value: str,
    allowed_domains: tuple[str, ...],
    *,
    resolver: AddressResolver = socket.getaddrinfo,
) -> str:
    """Apply scope validation and DNS-aware SSRF checks to an active web target."""
    host = ensure_target_allowed(target_kind, target_value, allowed_domains)
    resolve_global_addresses(host, resolver)
    return host


def scoped_address_policy(
    allowed_domains: tuple[str, ...],
    *,
    resolver: AddressResolver = socket.getaddrinfo,
) -> AddressPolicy:
    """Return the connect-time policy that authorizes a host's addresses.

    The HTTP stack calls this immediately before opening the socket and then
    connects to exactly what it returns, so a DNS answer cannot change between
    the scope/SSRF check and the connection (DNS rebinding). Every hop of a
    redirect chain goes through it again.
    """

    def policy(host: str) -> tuple[str, ...]:
        normalized = host.strip().lower().rstrip(".")
        _reject_non_global_ip(normalized)
        _reject_out_of_scope(normalized, allowed_domains)
        return resolve_global_addresses(normalized, resolver)

    return policy
