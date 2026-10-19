"""Validate the time-boxed pip-audit exception registry (SEC-I).

Dependency vulnerabilities are a blocking CI gate. On the rare occasion a fix is
not yet available, a vulnerability may be *temporarily* waived — but only with a
recorded motivation, an owner and an expiry date. This checker enforces that
discipline so the allowlist can never become permanent:

* every entry must carry ``id``, ``package``, ``reason``, ``owner``, ``added``
  and ``expires`` (ISO ``YYYY-MM-DD`` dates);
* ``expires`` must be today or in the future and not before ``added``;
* an expired or malformed entry fails the gate.

With no registry file, or an empty one, there are no exceptions and the gate
behaves exactly as an unfiltered ``pip-audit`` run.

Usage:
    python scripts/check_audit_exceptions.py [PATH]            # validate (default)
    python scripts/check_audit_exceptions.py --emit-ignores [PATH]
        print the active (valid, unexpired) vulnerability ids, one per line, for
        ``pip-audit --ignore-vuln``.
"""

from __future__ import annotations

import sys
import tomllib
from datetime import date
from pathlib import Path

DEFAULT_REGISTRY = Path(".github/audit-exceptions.toml")
_REQUIRED = ("id", "package", "reason", "owner", "added", "expires")


def _parse_date(value: object, field: str, index: int) -> date | str:
    if not isinstance(value, str):
        return f"exception #{index}: {field} must be an ISO date string (YYYY-MM-DD)"
    try:
        return date.fromisoformat(value)
    except ValueError:
        return f"exception #{index}: {field} is not a valid ISO date: {value!r}"


def load_exceptions(path: Path) -> tuple[list[dict[str, object]], list[str]]:
    """Return (raw_entries, errors) from the registry, or ([], []) if absent."""
    if not path.is_file():
        return [], []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [], [f"cannot read {path}: {exc}"]
    entries = data.get("exception", [])
    if not isinstance(entries, list):
        return [], [f"{path}: 'exception' must be an array of tables"]
    return entries, []


def active_ignores(path: Path = DEFAULT_REGISTRY, *, today: date | None = None) -> list[str]:
    """Return the ids that are valid and not yet expired (for --ignore-vuln)."""
    today = today or date.today()
    entries, errors = load_exceptions(path)
    if errors:
        return []
    ignores: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        identifier = entry.get("id")
        expires = entry.get("expires")
        if not isinstance(identifier, str) or not identifier.strip():
            continue
        parsed = _parse_date(expires, "expires", 0)
        if isinstance(parsed, date) and parsed >= today:
            ignores.append(identifier.strip())
    return ignores


def validate(path: Path = DEFAULT_REGISTRY, *, today: date | None = None) -> list[str]:
    """Return a list of human-readable problems; empty means the registry is valid."""
    today = today or date.today()
    entries, errors = load_exceptions(path)
    problems = list(errors)
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            problems.append(f"exception #{index}: must be a table")
            continue
        for field in _REQUIRED:
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"exception #{index}: missing or empty {field!r}")
        added = _parse_date(entry.get("added"), "added", index)
        expires = _parse_date(entry.get("expires"), "expires", index)
        if isinstance(added, str):
            problems.append(added)
        if isinstance(expires, str):
            problems.append(expires)
        if isinstance(added, date) and isinstance(expires, date) and expires < added:
            problems.append(f"exception #{index}: expires is before added")
        if isinstance(expires, date) and expires < today:
            problems.append(
                f"exception #{index} ({entry.get('id')}): expired on {expires.isoformat()} "
                "— update the dependency or renew the exception with a justification"
            )
    return problems


def main(argv: list[str]) -> int:
    emit = "--emit-ignores" in argv
    positional = [arg for arg in argv if not arg.startswith("--")]
    path = Path(positional[0]) if positional else DEFAULT_REGISTRY

    if emit:
        for identifier in active_ignores(path):
            print(identifier)
        return 0

    problems = validate(path)
    if problems:
        print("Audit-exception registry invalid:", file=sys.stderr)
        for problem in problems:
            print(f"- {problem}", file=sys.stderr)
        return 1
    active = active_ignores(path)
    if active:
        print(f"Audit-exception registry valid: {len(active)} active exception(s): {active}")
    else:
        print("Audit-exception registry valid: no active exceptions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
