"""Offline recovery checks for the finding-lifecycle store (WEB-J-01)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.core.enums import FindingStatus, Source
from olympus.core.finding_lifecycle import record_transition
from olympus.core.models import Finding
from olympus.core.secrets import EnvSecretProvider
from olympus.findings.store import (
    FINDINGS_ENCRYPTION_KEY_ENV,
    SqliteFindingTransitionStore,
)
from olympus.vulcan.cli import app


def _transition():
    finding = Finding(asset_id="AST-2026-00001", source=Source.THEMIS, title="Synthetic finding")
    _, record = record_transition(
        finding,
        FindingStatus.CONFIRMED,
        actor="synthetic-analyst@example.test",
        reason="synthetic recovery fixture",
    )
    return finding, record


def test_encrypted_transition_backup_and_restore_preserve_rows_and_wal(tmp_path: Path) -> None:
    database = tmp_path / "live" / "transitions.db"
    provider = EnvSecretProvider(environ={FINDINGS_ENCRYPTION_KEY_ENV: "k" * 32})
    store = SqliteFindingTransitionStore(database, secrets=provider)
    finding, record = _transition()
    store.append(record)
    assert Path(f"{database}-wal").exists()
    store.close()

    backup = tmp_path / "snapshots" / "transitions.sqlite3"
    info = SqliteFindingTransitionStore.backup_database(database, backup)
    assert info.transition_count == 1
    assert SqliteFindingTransitionStore.verify_backup(backup) == info
    assert b"synthetic-analyst@example.test" not in backup.read_bytes()

    restored_path = tmp_path / "restored" / "transitions.db"
    restored_info = SqliteFindingTransitionStore.restore_backup(backup, restored_path)
    assert restored_info.schema_version == info.schema_version
    assert restored_info.transition_count == info.transition_count
    restored = SqliteFindingTransitionStore(restored_path, secrets=provider)
    try:
        assert restored.history(finding.finding_id) == [record]
    finally:
        restored.close()


def test_finding_transition_restore_refuses_existing_destination_and_future_schema(
    tmp_path: Path,
) -> None:
    database = tmp_path / "live.db"
    store = SqliteFindingTransitionStore(database)
    _, record = _transition()
    store.append(record)
    store.close()
    backup = tmp_path / "backup.db"
    SqliteFindingTransitionStore.backup_database(database, backup)

    destination = tmp_path / "existing.db"
    destination.write_bytes(b"preserve existing data")
    with pytest.raises(FileExistsError):
        SqliteFindingTransitionStore.restore_backup(backup, destination)
    assert destination.read_bytes() == b"preserve existing data"

    with sqlite3.connect(backup) as connection:
        connection.execute("PRAGMA user_version = 999")
    with pytest.raises(ValueError, match="schema version"):
        SqliteFindingTransitionStore.verify_backup(backup)


def test_finding_transition_verifier_rejects_sidecars(tmp_path: Path) -> None:
    database = tmp_path / "live.db"
    SqliteFindingTransitionStore(database).close()
    backup = tmp_path / "backup.db"
    SqliteFindingTransitionStore.backup_database(database, backup)

    Path(f"{backup}-wal").write_bytes(b"untrusted sidecar")
    with pytest.raises(ValueError, match="self-contained"):
        SqliteFindingTransitionStore.verify_backup(backup)


def test_finding_transition_backup_cli_round_trip(tmp_path: Path) -> None:
    database = tmp_path / "live.db"
    store = SqliteFindingTransitionStore(database)
    finding, record = _transition()
    store.append(record)
    store.close()
    runner = CliRunner()

    backup = tmp_path / "cli-backup.db"
    result = runner.invoke(
        app,
        [
            "findings",
            "transitions",
            "backup",
            "--database",
            str(database),
            "--output",
            str(backup),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["transition_count"] == 1

    verified = runner.invoke(
        app,
        ["findings", "transitions", "verify-backup", "--backup", str(backup)],
    )
    assert verified.exit_code == 0, verified.output

    restored_path = tmp_path / "restored" / "transitions.db"
    restored = runner.invoke(
        app,
        [
            "findings",
            "transitions",
            "restore-backup",
            "--backup",
            str(backup),
            "--database",
            str(restored_path),
        ],
    )
    assert restored.exit_code == 0, restored.output
    reopened = SqliteFindingTransitionStore(restored_path)
    try:
        assert reopened.history(finding.finding_id) == [record]
    finally:
        reopened.close()
