"""URL scope enforcement for authorized Artemis web reconnaissance."""

from __future__ import annotations

import ipaddress
import json
import posixpath
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit
from uuid import uuid4

from olympus.core.execution import StructuredAuditRecord, append_structured_audit


class ScopeError(ValueError):
    """Raised when a target or scope document is invalid."""


class OutOfScopeError(PermissionError):
    """Raised after a target has been blocked and safely audited."""


@dataclass(frozen=True)
class ScopedUrl:
    """A canonical URL approved for a later network operation."""

    url: str
    origin: str
    path: str


def _audit_block(target: str, log_path: Path, reason: str) -> None:
    """Append a query-free, structured scope denial record."""
    append_structured_audit(
        log_path,
        StructuredAuditRecord(
            timestamp=datetime.now(UTC).isoformat(),
            execution_id=str(uuid4()),
            action="artemis.scope",
            outcome="blocked",
            target=target,
            metadata={"reason": reason},
        ),
    )


def _canonicalize(raw_url: str) -> ScopedUrl:
    """Validate and canonicalize an HTTP URL without resolving or requesting it."""
    if any(character in raw_url for character in "\r\n\t"):
        raise ScopeError("URL contains control characters")
    try:
        parsed = urlsplit(raw_url)
        port = parsed.port
    except ValueError as exc:
        raise ScopeError(f"invalid URL: {exc}") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or parsed.hostname is None:
        raise ScopeError("URL must use http or https and include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ScopeError("credentials are not allowed in target URLs")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ScopeError("invalid internationalized hostname") from exc
    if ":" in hostname:
        hostname = f"[{hostname}]"
    default_port = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    authority = hostname if default_port else f"{hostname}:{port}"
    decoded_path = unquote(parsed.path or "/")
    if "\\" in decoded_path or any(character in decoded_path for character in "\r\n\t"):
        raise ScopeError("URL path contains unsafe characters")
    normalized_path = posixpath.normpath(decoded_path)
    if not normalized_path.startswith("/"):
        normalized_path = f"/{normalized_path}"
    origin = f"{scheme}://{authority}"
    canonical = urlunsplit((scheme, authority, normalized_path, parsed.query, ""))
    return ScopedUrl(canonical, origin, normalized_path)


def _path_allowed(path: str, prefixes: list[str]) -> bool:
    return any(
        prefix == "/" or path == prefix or path.startswith(f"{prefix}/") for prefix in prefixes
    )


def enforce_scope(target: str, scope_path: Path, log_path: Path) -> ScopedUrl:
    """Authorize a URL or block and append a query-free JSON audit record."""
    scoped_target = _canonicalize(target)
    try:
        payload: Any = json.loads(scope_path.read_text(encoding="utf-8"))
        origins = {_canonicalize(origin).origin for origin in payload["allowed_origins"]}
        raw_prefixes = payload.get("allowed_path_prefixes", ["/"])
        if not isinstance(raw_prefixes, list) or not all(
            isinstance(prefix, str) and prefix.startswith("/") for prefix in raw_prefixes
        ):
            raise ScopeError("allowed_path_prefixes must be absolute paths")
        prefixes = [posixpath.normpath(unquote(prefix)) for prefix in raw_prefixes]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ScopeError(f"invalid scope file: {exc}") from exc
    if scoped_target.origin in origins and _path_allowed(scoped_target.path, prefixes):
        return scoped_target
    safe_target = f"{scoped_target.origin}{scoped_target.path}"
    _audit_block(safe_target, log_path, "url_not_allowed")
    raise OutOfScopeError(safe_target)


def enforce_address_scope(
    scoped_url: ScopedUrl,
    addresses: list[str],
    scope_path: Path,
    log_path: Path,
) -> tuple[str, ...]:
    """Require every resolved address to be explicitly covered by a scope CIDR."""
    if not addresses:
        raise ScopeError("DNS resolution returned no addresses")
    try:
        payload: Any = json.loads(scope_path.read_text(encoding="utf-8"))
        networks = [
            ipaddress.ip_network(value, strict=False) for value in payload["allowed_ip_networks"]
        ]
        parsed_addresses = [ipaddress.ip_address(value) for value in addresses]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ScopeError(f"invalid address scope: {exc}") from exc
    denied = [
        address
        for address in parsed_addresses
        if not any(address in network for network in networks)
    ]
    if denied:
        safe_target = f"{scoped_url.origin}{scoped_url.path}"
        _audit_block(safe_target, log_path, "resolved_address_not_allowed")
        raise OutOfScopeError(safe_target)
    return tuple(str(address) for address in parsed_addresses)
