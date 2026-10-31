"""Tests for the time-boxed pip-audit exception registry checker (SEC-I)."""

from __future__ import annotations

import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_audit_exceptions.py"

_TODAY = date.today()
_FUTURE = (_TODAY + timedelta(days=30)).isoformat()
_PAST = (_TODAY - timedelta(days=1)).isoformat()
_ADDED = (_TODAY - timedelta(days=5)).isoformat()


def _run(path: Path, *flags: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), *flags, str(path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def _entry(**overrides: str) -> str:
    fields = {
        "id": "GHSA-test-0000-0000",
        "package": "example-package",
        "reason": "No fixed release yet; path not reachable.",
        "owner": "security-maintainers",
        "added": _ADDED,
        "expires": _FUTURE,
    }
    fields.update(overrides)
    body = "\n".join(f'{key} = "{value}"' for key, value in fields.items())
    return "[[exception]]\n" + body + "\n"


def test_absent_registry_is_valid_with_no_ignores(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    assert _run(missing).returncode == 0
    emitted = _run(missing, "--emit-ignores")
    assert emitted.returncode == 0
    assert emitted.stdout.strip() == ""


def test_empty_registry_is_valid_with_no_ignores(tmp_path: Path) -> None:
    registry = tmp_path / "audit.toml"
    registry.write_text("# no exceptions\n", encoding="utf-8")
    assert _run(registry).returncode == 0
    assert _run(registry, "--emit-ignores").stdout.strip() == ""


def test_valid_future_entry_passes_and_is_emitted(tmp_path: Path) -> None:
    registry = tmp_path / "audit.toml"
    registry.write_text(_entry(), encoding="utf-8")
    validate = _run(registry)
    assert validate.returncode == 0, validate.stderr
    assert "1 active exception" in validate.stdout
    assert _run(registry, "--emit-ignores").stdout.strip() == "GHSA-test-0000-0000"


def test_expired_entry_fails_and_is_not_emitted(tmp_path: Path) -> None:
    registry = tmp_path / "audit.toml"
    registry.write_text(_entry(expires=_PAST), encoding="utf-8")
    result = _run(registry)
    assert result.returncode == 1
    assert "expired" in result.stderr
    # An expired waiver must never silently keep suppressing the vulnerability.
    assert _run(registry, "--emit-ignores").stdout.strip() == ""


def test_missing_field_fails(tmp_path: Path) -> None:
    registry = tmp_path / "audit.toml"
    registry.write_text(
        "[[exception]]\n"
        'id = "GHSA-test-0000-0000"\n'
        'package = "example-package"\n'
        'added = "' + _ADDED + '"\n'
        'expires = "' + _FUTURE + '"\n',
        encoding="utf-8",
    )
    result = _run(registry)
    assert result.returncode == 1
    assert "reason" in result.stderr and "owner" in result.stderr


def test_expires_before_added_fails(tmp_path: Path) -> None:
    registry = tmp_path / "audit.toml"
    registry.write_text(
        _entry(added=_FUTURE, expires=_ADDED),
        encoding="utf-8",
    )
    result = _run(registry)
    assert result.returncode == 1
    assert "before added" in result.stderr or "expired" in result.stderr


def test_committed_registry_is_valid() -> None:
    """The registry shipped in the repository must always pass the gate."""
    assert _run(ROOT / ".github" / "audit-exceptions.toml").returncode == 0
