"""WEB-J-01: structured audit log backup, verify and restore (synthetic data)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.audit_backup import (
    AuditBackupError,
    backup_audit_log,
    restore_audit_backup,
    verify_audit_backup,
)
from olympus.core.execution import StructuredAuditRecord, append_structured_audit

runner = CliRunner()


def _log(path: Path, n: int = 3) -> Path:
    for i in range(n):
        append_structured_audit(
            path,
            StructuredAuditRecord(
                timestamp=f"2026-11-01T00:00:0{i}Z",
                execution_id=f"exec-{i}",
                action="job.submit",
                outcome="ok",
                target="https://lab.example/x?token=abc",
                metadata={"password": "hunter2", "note": "synthetic"},
            ),
        )
    return path


def test_round_trip_and_fingerprint(tmp_path: Path) -> None:
    log = _log(tmp_path / "audit.jsonl")
    info = backup_audit_log(log, tmp_path / "b.jsonl")
    assert info.records == 3
    assert info.first_timestamp == "2026-11-01T00:00:00Z"
    assert info.last_timestamp == "2026-11-01T00:00:02Z"
    assert (tmp_path / "b.jsonl").stat().st_mode & 0o777 == 0o600
    restored = restore_audit_backup(tmp_path / "b.jsonl", tmp_path / "r" / "a.jsonl")
    assert restored.sha256 == info.sha256 == verify_audit_backup(log).sha256
    assert b"hunter2" not in (tmp_path / "r" / "a.jsonl").read_bytes()


def test_refuses_overwrite_and_symlink(tmp_path: Path) -> None:
    log = _log(tmp_path / "a.jsonl")
    (tmp_path / "exists").write_text("x")
    with pytest.raises(AuditBackupError, match="overwrite"):
        backup_audit_log(log, tmp_path / "exists")
    (tmp_path / "link").symlink_to(log)
    with pytest.raises(AuditBackupError):
        backup_audit_log(log, tmp_path / "link")
    with pytest.raises(AuditBackupError):
        verify_audit_backup(tmp_path / "link")
    assert (tmp_path / "exists").read_text() == "x"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b[:-5],  # torn tail
        lambda b: b + b"not json\n",
        lambda b: b + b'{"timestamp":"t"}\n',
        lambda b: b + b"[]\n",
        lambda b: b + b"\xff\xfe\n",
        lambda b: b.replace(b'"outcome":"ok"', b'"outcome":""', 1),
    ],
)
def test_rejects_corrupt_logs(tmp_path: Path, mutate) -> None:  # type: ignore[no-untyped-def]
    log = _log(tmp_path / "a.jsonl")
    log.write_bytes(mutate(log.read_bytes()))
    with pytest.raises(AuditBackupError):
        backup_audit_log(log, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_rejects_unredacted_metadata(tmp_path: Path) -> None:
    record = {
        "timestamp": "t",
        "execution_id": "e",
        "action": "a",
        "outcome": "ok",
        "target": None,
        "metadata": {"api_key": "sekret"},
    }
    log = tmp_path / "a.jsonl"
    log.write_text(json.dumps(record) + "\n")
    with pytest.raises(AuditBackupError, match="unredacted"):
        verify_audit_backup(log)


def test_missing_and_oversized(tmp_path: Path) -> None:
    with pytest.raises(AuditBackupError, match="does not exist"):
        verify_audit_backup(tmp_path / "nope")
    log = _log(tmp_path / "a.jsonl")
    with pytest.raises(AuditBackupError):
        verify_audit_backup(log, max_bytes=10)


def test_empty_log_is_valid(tmp_path: Path) -> None:
    empty = tmp_path / "e.jsonl"
    empty.write_bytes(b"")
    assert verify_audit_backup(empty).records == 0


def test_cli_round_trip_and_tamper(tmp_path: Path) -> None:
    log = _log(tmp_path / "a.jsonl")
    b = tmp_path / "b.jsonl"
    ok = runner.invoke(
        app, ["core", "audit-backup", "backup", "--source", str(log), "--destination", str(b)]
    )
    assert ok.exit_code == 0, ok.output
    assert json.loads(ok.stdout)["records"] == 3
    again = runner.invoke(
        app, ["core", "audit-backup", "backup", "--source", str(log), "--destination", str(b)]
    )
    assert again.exit_code != 0
    b.write_bytes(b.read_bytes() + b"junk\n")
    bad = runner.invoke(app, ["core", "audit-backup", "verify", "--source", str(b)])
    assert bad.exit_code != 0
    no_dest = runner.invoke(app, ["core", "audit-backup", "restore", "--source", str(log)])
    assert no_dest.exit_code != 0
