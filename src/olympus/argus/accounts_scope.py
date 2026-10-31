"""Scope enforcement for Argus account (username/email) enumeration.

Account enumeration only ever runs against explicitly authorized handles.
The target handle is checked against a JSON allowlist before any site is
queried; anything outside the perimeter is blocked and the attempt is
appended to an audit log.

Matching here is exact (case-insensitive) on the handle, intentionally
distinct from the domain-suffix matching in :mod:`olympus.argus.scope` and
the E.164-prefix matching in :mod:`olympus.argus.phone_scope`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class AccountScopeError(Exception):
    """Raised when the scope file is missing, unreadable or malformed."""


class AccountOutOfScopeError(Exception):
    """Raised when a target handle is not covered by the loaded scope."""

    def __init__(self, handle: str, scope_path: Path) -> None:
        super().__init__(f"{handle!r} is out of scope ({scope_path})")
        self.handle = handle
        self.scope_path = scope_path


@dataclass(frozen=True)
class AccountScope:
    """Authorized perimeter: which handles Argus may enumerate."""

    engagement: str
    allowed_handles: tuple[str, ...]

    def covers(self, handle: str) -> bool:
        """Return ``True`` if ``handle`` is in the allowlist (case-insensitive)."""
        target = handle.strip().lower()
        return any(target == allowed.strip().lower() for allowed in self.allowed_handles)


def load_account_scope(path: Path) -> AccountScope:
    """Load and validate a JSON account scope file.

    Expected shape::

        {
          "engagement": "olympus-demo-corp-2026",
          "allowed_handles": ["olympus_demo", "jdoe@olympusdemocorp.example"]
        }
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AccountScopeError(f"account scope file not found: {path}") from exc
    except OSError as exc:
        raise AccountScopeError(f"account scope file could not be read: {path} ({exc})") from exc

    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise AccountScopeError(f"account scope file is not valid JSON: {path} ({exc})") from exc

    if not isinstance(raw, dict):
        raise AccountScopeError(f"account scope file {path} must contain a JSON object")

    try:
        engagement = str(raw["engagement"])
        allowed = tuple(str(item) for item in raw["allowed_handles"])
    except (KeyError, TypeError) as exc:
        raise AccountScopeError(
            f"account scope file {path} must define 'engagement' and 'allowed_handles'"
        ) from exc
    if not allowed:
        raise AccountScopeError(f"account scope file {path} defines no allowed_handles")

    return AccountScope(engagement=engagement, allowed_handles=allowed)


def log_blocked_account(handle: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked, out-of-scope enumeration attempt."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "target": handle,
        "scope_file": str(scope_path),
        "action": "blocked_out_of_scope",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle_file:
        handle_file.write(json.dumps(entry, sort_keys=True) + "\n")


def enforce_account_scope(handle: str, scope_path: Path, log_path: Path) -> AccountScope:
    """Load ``scope_path`` and ensure ``handle`` is covered, blocking+logging otherwise."""
    scope = load_account_scope(scope_path)
    if not scope.covers(handle):
        log_blocked_account(handle, scope_path, log_path)
        raise AccountOutOfScopeError(handle, scope_path)
    return scope
