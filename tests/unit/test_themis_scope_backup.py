"""WEB-J-01: Themis scope backup, verify and restore (synthetic data, offline)."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.themis.scope_backup import (
    ScopeBackupError,
    backup_scope,
    restore_scope,
    verify_scope_backup,
)

runner = CliRunner()


def _scope(path: Path, **overrides: object) -> Path:
    doc: dict[str, object] = {
        "schema_name": "olympus.themis-scope",
        "schema_version": "1.0.0",
        "allowed_hosts": ["lab.example"],
        "allowed_domains": ["corp.example"],
        "allowed_cidrs": ["192.0.2.0/24"],
    }
    doc.update(overrides)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_round_trip_is_byte_exact_and_owner_only(tmp_path: Path) -> None:
    src = _scope(tmp_path / "scope.json")
    snap = tmp_path / "snap.json"
    info = backup_scope(src, snap)
    assert (info.hosts, info.domains, info.cidrs) == (1, 1, 1)
    assert snap.read_bytes() == src.read_bytes()
    assert stat.S_IMODE(snap.stat().st_mode) == 0o600
    restored = tmp_path / "restored.json"
    assert restore_scope(snap, restored).sha256 == info.sha256
    assert verify_scope_backup(restored) == verify_scope_backup(snap)


def test_refuses_overwrite_and_symlink(tmp_path: Path) -> None:
    src = _scope(tmp_path / "scope.json")
    existing = tmp_path / "exists.json"
    existing.write_text("keep", encoding="utf-8")
    with pytest.raises(ScopeBackupError, match="overwrite"):
        backup_scope(src, existing)
    assert existing.read_text() == "keep"
    link = tmp_path / "link.json"
    link.symlink_to(existing)
    with pytest.raises(ScopeBackupError):
        backup_scope(src, link)
    with pytest.raises(ScopeBackupError):
        verify_scope_backup(link)


@pytest.mark.parametrize(
    "mutation",
    [
        {"allowed_hosts": [], "allowed_domains": [], "allowed_cidrs": []},
        {"allowed_hosts": ["a.example", "A.example"]},
        {"allowed_hosts": ["bad\nhost"]},
        {"unexpected": True},
        {"schema_version": "9.9.9"},
    ],
)
def test_invalid_perimeter_is_never_snapshotted(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    src = _scope(tmp_path / "scope.json", **mutation)
    snap = tmp_path / "snap.json"
    with pytest.raises(ScopeBackupError):
        backup_scope(src, snap)
    assert not snap.exists()


def test_corrupt_and_missing_inputs(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ScopeBackupError):
        verify_scope_backup(bad)
    with pytest.raises(ScopeBackupError, match="does not exist"):
        verify_scope_backup(tmp_path / "missing.json")
    big = tmp_path / "big.json"
    big.write_bytes(b" " * 1_000_001)
    with pytest.raises(ScopeBackupError):
        verify_scope_backup(big)


def test_tampered_snapshot_fails_verification(tmp_path: Path) -> None:
    src = _scope(tmp_path / "scope.json")
    snap = tmp_path / "snap.json"
    backup_scope(src, snap)
    snap.write_text(snap.read_text().replace("lab.example", ""), encoding="utf-8")
    with pytest.raises(ScopeBackupError):
        verify_scope_backup(snap)


def test_cli_round_trip_and_refusals(tmp_path: Path) -> None:
    src = _scope(tmp_path / "scope.json")
    snap, restored = tmp_path / "snap.json", tmp_path / "restored.json"
    res = runner.invoke(
        app, ["themis", "scope", "backup", "--scope", str(src), "--destination", str(snap)]
    )
    assert res.exit_code == 0, res.output
    fingerprint = json.loads(res.stdout)["sha256"]
    res = runner.invoke(app, ["themis", "scope", "verify-backup", "--backup", str(snap)])
    assert res.exit_code == 0 and json.loads(res.stdout)["sha256"] == fingerprint
    res = runner.invoke(
        app,
        ["themis", "scope", "restore", "--backup", str(snap), "--destination", str(restored)],
    )
    assert res.exit_code == 0, res.output
    again = runner.invoke(
        app,
        ["themis", "scope", "restore", "--backup", str(snap), "--destination", str(restored)],
    )
    assert again.exit_code != 0
    snap.write_text("{}", encoding="utf-8")
    assert (
        runner.invoke(app, ["themis", "scope", "verify-backup", "--backup", str(snap)]).exit_code
        != 0
    )
