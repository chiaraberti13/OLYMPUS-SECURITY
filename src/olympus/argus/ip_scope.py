"""Scope enforcement for Argus IP OSINT.

IP intelligence only ever runs against explicitly authorized addresses. A
target IP is checked against a JSON allowlist of CIDR networks before any
lookup runs; anything outside the perimeter is blocked and the attempt is
appended to an audit log. Matching is CIDR containment, distinct from the
domain-suffix / E.164-prefix / handle matching of the other Argus scopes.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class IpScopeError(Exception):
    """Raised when the scope file is missing, unreadable or malformed."""


class IpOutOfScopeError(Exception):
    """Raised when a target IP is not covered by the loaded scope."""

    def __init__(self, ip: str, scope_path: Path) -> None:
        super().__init__(f"{ip!r} is out of scope ({scope_path})")
        self.ip = ip
        self.scope_path = scope_path


@dataclass(frozen=True)
class IpScope:
    """Authorized perimeter: which CIDR networks Argus may look up."""

    engagement: str
    allowed_networks: tuple[_IpNetwork, ...]
    excluded_networks: tuple[_IpNetwork, ...] = ()

    def covers(self, ip: str) -> bool:
        """Return ``True`` if ``ip`` is inside an allowed and no excluded network."""
        try:
            address = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        if any(address in network for network in self.excluded_networks):
            return False
        return any(address in network for network in self.allowed_networks)


def _parse_networks(values: object, field: str, path: Path) -> tuple[_IpNetwork, ...]:
    if not isinstance(values, list):
        raise IpScopeError(f"scope file {path}: '{field}' must be a list of CIDR strings")
    try:
        return tuple(ipaddress.ip_network(str(value), strict=False) for value in values)
    except ValueError as exc:
        raise IpScopeError(f"scope file {path}: invalid CIDR in '{field}' ({exc})") from exc


def load_ip_scope(path: Path) -> IpScope:
    """Load and validate a JSON IP scope file (engagement + CIDR allowlist)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IpScopeError(f"IP scope file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise IpScopeError(f"IP scope file could not be read: {path} ({exc})") from exc

    if not isinstance(raw, dict):
        raise IpScopeError(f"IP scope file {path} must contain a JSON object")
    if "engagement" not in raw or "allowed_networks" not in raw:
        raise IpScopeError(f"IP scope file {path} must define 'engagement' and 'allowed_networks'")

    allowed = _parse_networks(raw["allowed_networks"], "allowed_networks", path)
    if not allowed:
        raise IpScopeError(f"IP scope file {path} defines no allowed_networks")
    excluded = _parse_networks(raw.get("excluded_networks", []), "excluded_networks", path)
    return IpScope(
        engagement=str(raw["engagement"]), allowed_networks=allowed, excluded_networks=excluded
    )


def log_blocked_ip(ip: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked, out-of-scope IP lookup."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": ip,
        "scope_file": str(scope_path),
        "action": "blocked_out_of_scope",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def enforce_ip_scope(ip: str, scope_path: Path, log_path: Path) -> IpScope:
    """Load ``scope_path`` and ensure ``ip`` is covered, blocking+logging otherwise."""
    scope = load_ip_scope(scope_path)
    if not scope.covers(ip):
        log_blocked_ip(ip, scope_path, log_path)
        raise IpOutOfScopeError(ip, scope_path)
    return scope
