from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.themis.jobs import SCHEMA_VERSION, JobStoreError, SchemaVersionError, ThemisJobStore

runner = CliRunner()


def _seed_store(tmp_path: Path) -> tuple[ThemisJobStore, str]:
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "schema_name": "olympus.themis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.0/8"],
            }
        ),
        encoding="utf-8",
    )
    store = ThemisJobStore(tmp_path / "jobs.sqlite3")
    job = store.submit(
        scanner="synthetic",
        target="127.0.0.1",
        target_kind="host",
        scope_path=scope,
        authorized=True,
    )
    return store, job.job_id


def test_online_backup_verifies_and_restores_committed_wal(tmp_path: Path) -> None:
    store, job_id = _seed_store(tmp_path)
    backup = tmp_path / "snapshots" / "jobs.sqlite3"
    reader = store._connect()
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM themis_jobs").fetchone()
    scope = tmp_path / "scope.json"
    second_job = store.submit(
        scanner="synthetic",
        target="127.0.0.1",
        target_kind="host",
        scope_path=scope,
        authorized=True,
    )
    wal = Path(f"{store.path}-wal")
    assert wal.is_file() and wal.stat().st_size > 0

    try:
        info = store.backup(backup)
    finally:
        reader.rollback()
        reader.close()

    assert info.schema_version == SCHEMA_VERSION
    assert info.job_count == 2
    assert info.size_bytes == backup.stat().st_size
    assert len(info.sha256) == 64
    assert ThemisJobStore.verify_backup(backup) == info
    if os.name == "posix":
        assert backup.stat().st_mode & 0o777 == 0o600

    restored = tmp_path / "restore" / "jobs.sqlite3"
    restored_info = ThemisJobStore.restore_backup(backup, restored)
    assert restored_info == info
    assert ThemisJobStore(restored).get(job_id).job_id == job_id
    assert ThemisJobStore(restored).get(second_job.job_id).job_id == second_job.job_id


def test_verify_backup_rejects_corrupt_and_future_schema_files(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a SQLite database")
    with pytest.raises(JobStoreError):
        ThemisJobStore.verify_backup(corrupt)

    future = tmp_path / "future.sqlite3"
    with sqlite3.connect(future) as database:
        database.execute("CREATE TABLE themis_jobs (job_id TEXT)")
        database.execute("PRAGMA user_version = 999")
    with pytest.raises(SchemaVersionError):
        ThemisJobStore.verify_backup(future)


def test_restore_refuses_existing_destination_without_changing_it(tmp_path: Path) -> None:
    store, _ = _seed_store(tmp_path)
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    destination = tmp_path / "existing.sqlite3"
    original = b"preserve this operator file"
    destination.write_bytes(original)

    with pytest.raises(FileExistsError, match="must be absent"):
        ThemisJobStore.restore_backup(backup, destination)

    assert destination.read_bytes() == original
    assert not list(tmp_path.glob(".existing.sqlite3.*.restore"))


def test_restore_refuses_existing_request_sidecar(tmp_path: Path) -> None:
    store, _ = _seed_store(tmp_path)
    backup = tmp_path / "backup.sqlite3"
    store.backup(backup)
    destination = tmp_path / "restore.sqlite3"
    sidecar = Path(f"{destination}.requests")
    sidecar.write_bytes(b"preserve prior lease state")

    with pytest.raises(FileExistsError, match="sidecars must be absent"):
        ThemisJobStore.restore_backup(backup, destination)

    assert sidecar.read_bytes() == b"preserve prior lease state"


def test_backup_verification_failure_preserves_previous_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = _seed_store(tmp_path)
    destination = tmp_path / "backup.sqlite3"
    destination.write_bytes(b"previous snapshot")

    def reject_snapshot(_: Path) -> None:
        raise JobStoreError("synthetic verification failure")

    monkeypatch.setattr(ThemisJobStore, "verify_backup", staticmethod(reject_snapshot))
    with pytest.raises(JobStoreError, match="verification failure"):
        store.backup(destination)

    assert destination.read_bytes() == b"previous snapshot"
    assert not list(tmp_path.glob(".backup.sqlite3.*.tmp"))


def test_store_rejects_dangling_symlink_database(tmp_path: Path) -> None:
    target = tmp_path / "missing.sqlite3"
    link = tmp_path / "dangling.sqlite3"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(OSError, match="non-symlink"):
        ThemisJobStore(link).initialize()


def test_jobs_backup_verify_restore_cli_round_trip(tmp_path: Path) -> None:
    store, job_id = _seed_store(tmp_path)
    backup = tmp_path / "cli-backup.sqlite3"
    destination = tmp_path / "cli-restore.sqlite3"

    created = runner.invoke(
        app,
        ["themis", "jobs", "backup", "--database", str(store.path), "--destination", str(backup)],
    )
    assert created.exit_code == 0, created.output
    assert json.loads(created.output)["job_count"] == 1

    verified = runner.invoke(app, ["themis", "jobs", "verify-backup", "--backup", str(backup)])
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["verified"] is True

    restored = runner.invoke(
        app,
        ["themis", "jobs", "restore", "--backup", str(backup), "--destination", str(destination)],
    )
    assert restored.exit_code == 0, restored.output
    assert json.loads(restored.output)["services_must_be_stopped_before_switching_config"] is True
    assert ThemisJobStore(destination).get(job_id).job_id == job_id
