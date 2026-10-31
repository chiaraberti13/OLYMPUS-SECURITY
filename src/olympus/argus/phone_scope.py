"""Scope enforcement for Argus phone-number OSINT.

Phone OSINT only ever runs against explicitly authorized numbers. A target
number (in E.164 form, e.g. ``+14155550123``) is checked against a JSON
scope file before any lookup runs; anything outside the perimeter is blocked
and the attempt is appended to an audit log (never silently dropped).

The matching semantics here are prefix-based on E.164 (country/area
prefixes) and therefore intentionally distinct from the domain-suffix
matching in :mod:`olympus.argus.scope` — the two are not merged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class PhoneScopeError(Exception):
    """Raised when the scope file is missing, unreadable or malformed."""


class PhoneOutOfScopeError(Exception):
    """Raised when a target number is not covered by the loaded scope."""

    def __init__(self, number: str, scope_path: Path) -> None:
        super().__init__(f"{number!r} is out of scope ({scope_path})")
        self.number = number
        self.scope_path = scope_path


@dataclass(frozen=True)
class PhoneScope:
    """Authorized perimeter: which E.164 prefixes Argus may look up."""

    engagement: str
    allowed_prefixes: tuple[str, ...]
    excluded_prefixes: tuple[str, ...] = ()

    def covers(self, e164: str) -> bool:
        """Return ``True`` if ``e164`` starts with an allowed and no excluded prefix."""
        target = e164.strip()
        if any(target.startswith(prefix) for prefix in self.excluded_prefixes):
            return False
        return any(target.startswith(prefix) for prefix in self.allowed_prefixes)


def load_phone_scope(path: Path) -> PhoneScope:
    """Load and validate a JSON phone scope file.

    Expected shape::

        {
          "engagement": "olympus-demo-corp-2026",
          "allowed_prefixes": ["+1650555", "+39"],
          "excluded_prefixes": []
        }
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PhoneScopeError(f"phone scope file not found: {path}") from exc
    except OSError as exc:
        raise PhoneScopeError(f"phone scope file could not be read: {path} ({exc})") from exc

    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise PhoneScopeError(f"phone scope file is not valid JSON: {path} ({exc})") from exc

    if not isinstance(raw, dict):
        raise PhoneScopeError(f"phone scope file {path} must contain a JSON object")

    try:
        engagement = str(raw["engagement"])
        allowed = tuple(str(item) for item in raw["allowed_prefixes"])
    except (KeyError, TypeError) as exc:
        raise PhoneScopeError(
            f"phone scope file {path} must define 'engagement' and 'allowed_prefixes'"
        ) from exc
    if not allowed:
        raise PhoneScopeError(f"phone scope file {path} defines no allowed_prefixes")

    excluded = tuple(str(item) for item in raw.get("excluded_prefixes", []))
    return PhoneScope(engagement=engagement, allowed_prefixes=allowed, excluded_prefixes=excluded)


def log_blocked_phone(number: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked, out-of-scope phone lookup."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": number,
        "scope_file": str(scope_path),
        "action": "blocked_out_of_scope",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def enforce_phone_scope(number: str, scope_path: Path, log_path: Path) -> PhoneScope:
    """Load ``scope_path`` and ensure ``number`` is covered, blocking+logging otherwise."""
    scope = load_phone_scope(scope_path)
    if not scope.covers(number):
        log_blocked_phone(number, scope_path, log_path)
        raise PhoneOutOfScopeError(number, scope_path)
    return scope
