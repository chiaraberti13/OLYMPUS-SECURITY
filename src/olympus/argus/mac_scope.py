"""Scope enforcement for Argus MAC vendor lookups.

The optional vendor lookup sends the target's 24-bit OUI to a third-party
registry.  A dedicated OUI allowlist keeps this authorization boundary
separate from domain, IP, phone, and account scopes.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_NON_HEX = re.compile(r"[^0-9A-Fa-f]")


class MacScopeError(Exception):
    """Raised when a MAC scope file is missing, unreadable, or malformed."""


class MacOutOfScopeError(Exception):
    """Raised when a MAC address is not covered by the authorized OUIs."""

    def __init__(self, mac: str, scope_path: Path) -> None:
        super().__init__(f"{mac!r} is out of scope ({scope_path})")
        self.mac = mac
        self.scope_path = scope_path


def _normalize_oui(value: str) -> str:
    normalized = _NON_HEX.sub("", value).upper()
    if len(normalized) != 6:
        raise ValueError(f"not a 24-bit OUI: {value!r}")
    return normalized


def _mac_oui(value: str) -> str:
    normalized = _NON_HEX.sub("", value).upper()
    if len(normalized) != 12:
        raise ValueError(f"not a 48-bit MAC address: {value!r}")
    return normalized[:6]


@dataclass(frozen=True)
class MacScope:
    """Authorized perimeter for OUI registry lookups."""

    engagement: str
    allowed_ouis: tuple[str, ...]
    excluded_ouis: tuple[str, ...] = ()

    def covers(self, mac: str) -> bool:
        """Return whether the address OUI is allowed and not excluded."""
        try:
            oui = _mac_oui(mac)
        except ValueError:
            return False
        return oui in self.allowed_ouis and oui not in self.excluded_ouis


def _parse_ouis(values: object, field: str, path: Path) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise MacScopeError(f"MAC scope file {path}: '{field}' must be a list of OUIs")
    try:
        return tuple(_normalize_oui(str(value)) for value in values)
    except ValueError as exc:
        raise MacScopeError(f"MAC scope file {path}: invalid OUI in '{field}' ({exc})") from exc


def load_mac_scope(path: Path) -> MacScope:
    """Load and validate an engagement/OUI allowlist JSON file."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise MacScopeError(f"MAC scope file not found: {path}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise MacScopeError(f"MAC scope file could not be read: {path} ({exc})") from exc

    if not isinstance(raw, dict):
        raise MacScopeError(f"MAC scope file {path} must contain a JSON object")
    if "engagement" not in raw or "allowed_ouis" not in raw:
        raise MacScopeError(f"MAC scope file {path} must define 'engagement' and 'allowed_ouis'")
    allowed = _parse_ouis(raw["allowed_ouis"], "allowed_ouis", path)
    if not allowed:
        raise MacScopeError(f"MAC scope file {path} defines no allowed_ouis")
    excluded = _parse_ouis(raw.get("excluded_ouis", []), "excluded_ouis", path)
    return MacScope(
        engagement=str(raw["engagement"]),
        allowed_ouis=allowed,
        excluded_ouis=excluded,
    )


def log_blocked_mac(mac: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked OUI registry lookup."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": mac,
        "scope_file": str(scope_path),
        "action": "blocked_out_of_scope",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def enforce_mac_scope(mac: str, scope_path: Path, log_path: Path) -> MacScope:
    """Require the MAC's OUI in scope, auditing a refusal before network use."""
    scope = load_mac_scope(scope_path)
    if not scope.covers(mac):
        log_blocked_mac(mac, scope_path, log_path)
        raise MacOutOfScopeError(mac, scope_path)
    return scope
