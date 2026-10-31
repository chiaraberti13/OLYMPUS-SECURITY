"""Coordinated backup manifest tests (WEB-J-01); synthetic data only."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core import backup_manifest as bm


@pytest.fixture
def snap(tmp_path: Path) -> Path:
    (tmp_path / "e.db").write_bytes(b"engagements")
    (tmp_path / "j.db").write_bytes(b"jobs")
    return tmp_path


COMPONENTS = {"engagements": "e.db", "jobs": "j.db"}


def _create(snap: Path) -> None:
    manifest = bm.build_manifest(snap, COMPONENTS, created_at=datetime(2026, 1, 1, tzinfo=UTC))
    bm.write_manifest(snap, manifest)


def test_roundtrip_and_determinism(snap: Path) -> None:
    first = bm.build_manifest(snap, COMPONENTS, created_at=datetime(2026, 1, 1, tzinfo=UTC))
    second = bm.build_manifest(
        snap, dict(reversed(COMPONENTS.items())), created_at=datetime(2026, 1, 1, tzinfo=UTC)
    )
    assert first == second
    _create(snap)
    assert [c.name for c in bm.verify_manifest(snap)] == ["engagements", "jobs"]


def test_modified_missing_and_extra_files_are_rejected(snap: Path) -> None:
    _create(snap)
    (snap / "j.db").write_bytes(b"jobS")
    with pytest.raises(bm.BackupManifestError, match="jobs"):
        bm.verify_manifest(snap)
    (snap / "j.db").write_bytes(b"jobs")
    (snap / "stray.db").write_bytes(b"x")
    with pytest.raises(bm.BackupManifestError, match="unlisted"):
        bm.verify_manifest(snap)
    (snap / "stray.db").unlink()
    (snap / "j.db").unlink()
    with pytest.raises(bm.BackupManifestError):
        bm.verify_manifest(snap)


def test_unsafe_inputs(snap: Path) -> None:
    for bad in ("../e.db", "/etc/passwd", "sub/e.db", "missing.db"):
        with pytest.raises(bm.BackupManifestError):
            bm.build_manifest(snap, {"x": bad})
    (snap / "link.db").symlink_to(snap / "e.db")
    with pytest.raises(bm.BackupManifestError):
        bm.build_manifest(snap, {"x": "link.db"})
    with pytest.raises(bm.BackupManifestError):
        bm.build_manifest(snap, {"Bad Name": "e.db"})
    with pytest.raises(bm.BackupManifestError):
        bm.build_manifest(snap, {"a": "e.db", "b": "e.db"})
    with pytest.raises(bm.BackupManifestError):
        bm.build_manifest(snap, {})


def test_manifest_is_create_only_and_malformed_is_rejected(snap: Path) -> None:
    _create(snap)
    with pytest.raises(bm.BackupManifestError, match="overwrite"):
        _create(snap)
    path = snap / bm.MANIFEST_NAME
    data = json.loads(path.read_text())
    data["components"][0]["sha256"] = "zz"
    path.write_text(json.dumps(data))
    with pytest.raises(bm.BackupManifestError, match="malformed"):
        bm.verify_manifest(snap)
    path.write_text("not json")
    with pytest.raises(bm.BackupManifestError):
        bm.verify_manifest(snap)


def test_cli_create_and_verify(snap: Path) -> None:
    runner = CliRunner()
    args = ["core", "backup-manifest", "--directory", str(snap)]
    created = runner.invoke(
        app, [*args, "--component", "engagements=e.db", "--component", "jobs=j.db"]
    )
    assert created.exit_code == 0, created.output
    assert runner.invoke(app, [*args, "--verify"]).exit_code == 0
    (snap / "e.db").write_bytes(b"tampered")
    failed = runner.invoke(app, [*args, "--verify"])
    assert failed.exit_code != 0
    assert runner.invoke(app, [*args, "--component", "broken"]).exit_code != 0
