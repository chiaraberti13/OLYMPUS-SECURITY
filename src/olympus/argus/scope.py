"""Scope enforcement for Argus.

Every offensive module in Olympus only ever touches explicitly authorized
targets. A scan target is checked against a JSON scope file before any
lookup runs; anything outside the perimeter is blocked and the attempt is
appended to an audit log (never silently dropped).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class ScopeError(Exception):
    """Raised when the scope file is missing, unreadable or malformed."""


class OutOfScopeError(Exception):
    """Raised when a target domain is not covered by the loaded scope."""

    def __init__(self, domain: str, scope_path: Path) -> None:
        super().__init__(f"{domain!r} is out of scope ({scope_path})")
        self.domain = domain
        self.scope_path = scope_path


@dataclass(frozen=True)
class Scope:
    """Authorized engagement perimeter: which domains Argus may query."""

    engagement: str
    allowed_domains: tuple[str, ...]
    excluded_domains: tuple[str, ...] = ()

    def covers(self, domain: str) -> bool:
        """Return ``True`` if ``domain`` (or a subdomain) is allowed and not excluded."""
        target = domain.lower().rstrip(".")
        if any(_matches(target, excluded) for excluded in self.excluded_domains):
            return False
        return any(_matches(target, allowed) for allowed in self.allowed_domains)


def _matches(target: str, pattern: str) -> bool:
    """Return ``True`` if ``target`` equals ``pattern`` or is one of its subdomains."""
    normalized = pattern.lower().rstrip(".")
    return target == normalized or target.endswith(f".{normalized}")


def load_scope(path: Path) -> Scope:
    """Load and validate a JSON scope file.

    Expected shape::

        {
          "engagement": "olympus-demo-corp-2026",
          "allowed_domains": ["olympusdemocorp.example"],
          "excluded_domains": []
        }
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ScopeError(f"scope file not found: {path}") from exc
    except OSError as exc:
        raise ScopeError(f"scope file could not be read: {path} ({exc})") from exc

    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ScopeError(f"scope file is not valid JSON: {path} ({exc})") from exc

    if not isinstance(raw, dict):
        raise ScopeError(f"scope file {path} must contain a JSON object")

    try:
        engagement = str(raw["engagement"])
        allowed = tuple(str(item) for item in raw["allowed_domains"])
    except (KeyError, TypeError) as exc:
        raise ScopeError(
            f"scope file {path} must define 'engagement' and 'allowed_domains'"
        ) from exc
    if not allowed:
        raise ScopeError(f"scope file {path} defines no allowed_domains")

    excluded = tuple(str(item) for item in raw.get("excluded_domains", []))
    return Scope(engagement=engagement, allowed_domains=allowed, excluded_domains=excluded)


def log_blocked(domain: str, scope_path: Path, log_path: Path) -> None:
    """Append an audit record for a blocked, out-of-scope scan attempt."""
    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "domain": domain,
        "scope_file": str(scope_path),
        "action": "blocked_out_of_scope",
    }
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def enforce_scope(domain: str, scope_path: Path, log_path: Path) -> Scope:
    """Load ``scope_path`` and ensure ``domain`` is covered.

    Blocks (raises :class:`OutOfScopeError`) and logs the attempt otherwise.
    """
    scope = load_scope(scope_path)
    if not scope.covers(domain):
        log_blocked(domain, scope_path, log_path)
        raise OutOfScopeError(domain, scope_path)
    return scope
