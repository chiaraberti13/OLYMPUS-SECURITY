"""Strict target normalization, engagement scope and DNS/SSRF validation."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Protocol
from urllib.parse import urlsplit


class TargetValidationError(ValueError):
    """Raised when a target or scope entry is malformed."""


class TargetResolutionError(RuntimeError):
    """Raised when an authorized hostname cannot be resolved safely."""


class OutOfScopeError(RuntimeError):
    """Raised when a target host is outside the authorized scope."""


class SsrfBlockedError(RuntimeError):
    """Raised when current target addresses are not explicitly safe/in scope."""


class Resolver(Protocol):
    def __call__(self, host: str) -> tuple[str, ...]:
        """Resolve one host to normalized IP literals."""
        ...


def host_of(target_kind: str, target_value: str) -> str:
    """Return a normalized bare host for a host/domain/HTTP(S) URL target."""
    if target_kind not in {"host", "domain", "url"}:
        raise TargetValidationError("target kind must be host, domain, or url")
    value = target_value.strip()
    if not value or any(character in value for character in "\r\n\x00"):
        raise TargetValidationError("target must be non-empty and contain no CR/LF/NUL")
    if target_kind == "url":
        candidate = value if "://" in value else f"https://{value}"
        try:
            parsed = urlsplit(candidate)
            _ = parsed.port
        except ValueError as exc:
            raise TargetValidationError("URL target has an invalid port or address") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise TargetValidationError("URL target must use http or https and include a host")
        if parsed.username is not None or parsed.password is not None:
            raise TargetValidationError("URL target must not contain userinfo credentials")
        return _normalize_host(parsed.hostname)
    if any(character in value for character in "/?#@") or " " in value:
        raise TargetValidationError("host/domain target contains URL or whitespace characters")
    return _normalize_host(value.rstrip("."))


def ensure_allowed(
    target_kind: str,
    target_value: str,
    allowed: tuple[str, ...],
    allowed_domains: tuple[str, ...] = (),
    allowed_cidrs: tuple[str, ...] = (),
    *,
    legacy_suffixes: bool = True,
) -> str:
    """Validate exact host/domain/CIDR authorization without network activity."""
    host = host_of(target_kind, target_value)
    exact_hosts = {_normalize_host(entry) for entry in allowed}
    domains = {_normalize_domain(entry) for entry in allowed_domains}
    networks = _networks(allowed_cidrs)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        in_scope = host in exact_hosts or any(address in network for network in networks)
        if not in_scope:
            if not address.is_global:
                raise SsrfBlockedError(
                    f"target {host} is non-global and not explicitly authorized by IP/CIDR"
                )
            raise OutOfScopeError(f"target {host} is out of scope")
        return host
    if (
        host not in exact_hosts
        and not any(host == domain or host.endswith(f".{domain}") for domain in domains)
        and (
            not legacy_suffixes
            or not any(host == entry or host.endswith(f".{entry}") for entry in exact_hosts)
        )
    ):
        raise OutOfScopeError(f"target {host} is out of scope")
    return host


def resolve_and_validate(
    host: str,
    *,
    allowed: tuple[str, ...],
    allowed_cidrs: tuple[str, ...] = (),
    resolver: Resolver | None = None,
    progress_check: Callable[[], None] | None = None,
) -> tuple[str, ...]:
    """Resolve immediately before execution and block unsafe current addresses."""
    if progress_check is not None:
        progress_check()
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    addresses: tuple[str, ...]
    if literal is not None:
        addresses = (str(literal),)
    else:
        try:
            addresses = (resolver or socket_resolver)(host)
        except OSError as exc:
            raise TargetResolutionError(f"could not resolve authorized target {host}") from exc
    normalized = tuple(dict.fromkeys(str(ipaddress.ip_address(value)) for value in addresses))
    if not normalized:
        raise TargetResolutionError(f"authorized target {host} resolved to no addresses")
    if len(normalized) > 256:
        raise TargetResolutionError(f"authorized target {host} resolved to more than 256 addresses")
    exact_hosts = {_normalize_host(entry) for entry in allowed}
    networks = _networks(allowed_cidrs)
    for value in normalized:
        if progress_check is not None:
            progress_check()
        address = ipaddress.ip_address(value)
        if (
            not address.is_global
            and value not in exact_hosts
            and not any(address in network for network in networks)
        ):
            raise SsrfBlockedError(
                f"authorized hostname {host} resolves to non-global {value} outside IP/CIDR scope"
            )
    return normalized


def socket_resolver(host: str) -> tuple[str, ...]:
    """Resolve one target using the system resolver without returning aliases."""
    records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return tuple(str(record[4][0]) for record in records)


def _normalize_host(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if not candidate or len(candidate) > 253:
        raise TargetValidationError("scope/target host must contain 1-253 characters")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        try:
            ascii_host = candidate.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetValidationError(f"invalid internationalized host {value!r}") from exc
        labels = ascii_host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or any(not (character.isalnum() or character == "-") for character in label)
            for label in labels
        ):
            raise TargetValidationError(f"invalid host {value!r}") from None
        return ascii_host


def _normalize_domain(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("*."):
        candidate = candidate[2:]
    return _normalize_host(candidate)


def _networks(values: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value.strip(), strict=False))
        except ValueError as exc:
            raise TargetValidationError(f"invalid scope CIDR {value!r}") from exc
    return tuple(networks)
