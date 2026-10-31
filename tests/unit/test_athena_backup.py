"""Offline backup/restore tests for Athena's durable SQLite store."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.athena.cli import app
from olympus.athena.domain.assessment import Assessment, Job
from olympus.athena.domain.contracts import AssessmentResult, load_plan


def _plan():
    return load_plan(
        {
            "engagement_id": "ENG-BACKUP",
            "name": "synthetic backup fixture",
            "targets": [{"kind": "domain", "value": "example.com"}],
            "adapters": ["dns"],
            "scope": {"allowed_domains": ["example.com"]},
            "authorization": {
                "engagement_id": "ENG-BACKUP",
                "approval_reference": "SYNTHETIC-TEST",
                "confirmed": True,
            },
        }
    )


def _seed(path: Path) -> SqliteAssessmentRepository:
    repository = SqliteAssessmentRepository(path)
    plan_id = repository.save_plan(_plan())
    job = Job(job_id="JOB-BACKUP", adapter="dns", target_kind="domain", target_value="example.com")
    repository.save_assessment(
        Assessment(assessment_id="ASSESS-BACKUP", plan_id=plan_id, jobs=(job,))
    )
    document = AssessmentResult(
        assessment_id="ASSESS-BACKUP",
        job=job.to_contract("ASSESS-BACKUP").model_copy(update={"state": "succeeded"}),
    ).canonical_json()
    result_id = repository.save_result("ASSESS-BACKUP", "JOB-BACKUP", document)
    with repository._conn:
        repository._conn.execute(
            "UPDATE jobs SET state = 'succeeded', result_id = ? WHERE job_id = ?",
            (result_id, "JOB-BACKUP"),
        )
    repository.append_audit(
        "ASSESS-BACKUP", 0, "2026-01-01T00:00:00Z", "run", "ok", None, json.dumps({"count": "1"})
    )
    return repository


def test_athena_backup_verify_restore_preserves_store(tmp_path: Path) -> None:
    source_path = tmp_path / "source" / "athena.db"
    source_path.parent.mkdir()
    repository = _seed(source_path)
    backup_path = tmp_path / "backup" / "athena.snapshot.db"
    try:
        info = repository.backup(backup_path)
        assert info.plan_count == 1
        assert (
            info.assessment_count
            == info.job_count
            == info.result_count
            == info.audit_event_count
            == 1
        )
        assert backup_path.stat().st_mode & 0o777 == 0o600
        assert not Path(f"{backup_path}-wal").exists()
        assert SqliteAssessmentRepository.verify_backup(backup_path) == info
        restored_path = tmp_path / "restored" / "athena.db"
        restored_info = SqliteAssessmentRepository.restore_backup(backup_path, restored_path)
        assert restored_info.sha256 != info.sha256
        assert restored_info.audit_event_count == info.audit_event_count
    finally:
        repository.close()

    restored = SqliteAssessmentRepository(restored_path)
    try:
        assessment = restored.load_assessment("ASSESS-BACKUP")
        assert assessment is not None and assessment.jobs[0].result_id
        assert restored.load_result(assessment.jobs[0].result_id) is not None
        assert restored.audit_events("ASSESS-BACKUP")[0]["action"] == "run"
        assert restored.load_plan(assessment.plan_id) == _plan()
    finally:
        restored.close()


def test_athena_backup_rejects_future_schema_and_restore_preserves_destination(
    tmp_path: Path,
) -> None:
    repository = _seed(tmp_path / "source.db")
    backup_path = tmp_path / "athena.snapshot.db"
    try:
        repository.backup(backup_path)
    finally:
        repository.close()
    connection = sqlite3.connect(backup_path)
    connection.execute("PRAGMA user_version = 999")
    connection.close()
    with pytest.raises(ValueError, match="unsupported Athena backup schema version"):
        SqliteAssessmentRepository.verify_backup(backup_path)

    valid_path = tmp_path / "valid.snapshot.db"
    seed = _seed(tmp_path / "valid-source.db")
    try:
        seed.backup(valid_path)
    finally:
        seed.close()
    destination = tmp_path / "existing.db"
    destination.write_bytes(b"preserve")
    with pytest.raises(FileExistsError):
        SqliteAssessmentRepository.restore_backup(valid_path, destination)
    assert destination.read_bytes() == b"preserve"


def test_athena_cli_backup_verify_restore_round_trip(tmp_path: Path) -> None:
    runner = CliRunner()
    storage = tmp_path / "store"
    repository = _seed(storage / "athena.db")
    repository.close()
    backup_path = tmp_path / "athena.snapshot.db"

    created = runner.invoke(
        app, ["store", "backup", "--storage", str(storage), "--output", str(backup_path)]
    )
    assert created.exit_code == 0, created.output
    verified = runner.invoke(app, ["store", "verify-backup", "--backup", str(backup_path)])
    assert verified.exit_code == 0, verified.output
    restored_storage = tmp_path / "restored"
    restored = runner.invoke(
        app,
        [
            "store",
            "restore-backup",
            "--backup",
            str(backup_path),
            "--storage",
            str(restored_storage),
        ],
    )
    assert restored.exit_code == 0, restored.output
    assert json.loads(verified.stdout)["audit_event_count"] == 1
    restored_repo = SqliteAssessmentRepository(restored_storage / "athena.db")
    try:
        assert restored_repo.load_assessment("ASSESS-BACKUP") is not None
    finally:
        restored_repo.close()


def test_athena_cli_backup_does_not_create_missing_store(tmp_path: Path) -> None:
    runner = CliRunner()
    storage = tmp_path / "missing"
    result = runner.invoke(
        app, ["store", "backup", "--storage", str(storage), "--output", str(tmp_path / "x.db")]
    )
    assert result.exit_code != 0
    assert not storage.exists()
