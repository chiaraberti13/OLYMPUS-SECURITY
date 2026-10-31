"""Offline recovery checks for the engagements store (WEB-J-01)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.core.models import Engagement, EngagementScope
from olympus.engagements.cli import app
from olympus.engagements.store import SqliteEngagementStore


def _engagement() -> Engagement:
    return Engagement(
        name="Synthetic recovery case",
        client="Example Org",
        scope=EngagementScope(included=("example.test",)),
        authorization_reference="SYNTHETIC-ONLY",
    )


def test_engagement_backup_includes_wal_and_all_authorization_tables(tmp_path: Path) -> None:
    source_path = tmp_path / "live" / "engagements.db"
    store = SqliteEngagementStore(source_path)
    engagement = _engagement()
    store.save(engagement)
    with store._conn:
        store._conn.execute(
            "INSERT INTO manifest_revocations(identifier, revoked_at) VALUES (?, ?)",
            ("synthetic-revocation", "2026-10-31T12:00:00+00:00"),
        )
        store._conn.execute(
            "INSERT INTO signed_manifests(manifest_sha256, document, stored_at) VALUES (?, ?, ?)",
            ("a" * 64, '{"synthetic":true}', "2026-10-31T12:00:00+00:00"),
        )
    assert source_path.with_name(f"{source_path.name}-wal").exists()

    backup = tmp_path / "snapshots" / "engagements.sqlite3"
    info = store.backup(backup)
    store.close()

    assert info.engagement_count == 1
    assert info.manifest_revocation_count == 1
    assert info.signed_manifest_count == 1
    assert SqliteEngagementStore.verify_backup(backup) == info

    restored_path = tmp_path / "restored" / "engagements.db"
    restored_info = SqliteEngagementStore.restore_backup(backup, restored_path)
    assert restored_info.schema_version == info.schema_version
    assert restored_info.engagement_count == info.engagement_count
    assert restored_info.manifest_revocation_count == info.manifest_revocation_count
    assert restored_info.signed_manifest_count == info.signed_manifest_count
    restored = SqliteEngagementStore(restored_path)
    try:
        assert restored.require(engagement.engagement_id).name == engagement.name
        assert restored.revoked_manifest_identifiers() == {"synthetic-revocation"}
        assert restored._conn.execute("SELECT count(*) FROM signed_manifests").fetchone()[0] == 1
    finally:
        restored.close()


def test_engagement_backup_rejects_future_schema_and_preserves_existing_restore(
    tmp_path: Path,
) -> None:
    store = SqliteEngagementStore(tmp_path / "live.db")
    store.save(_engagement())
    backup = tmp_path / "backup.db"
    store.backup(backup)
    store.close()

    destination = tmp_path / "existing.db"
    destination.write_bytes(b"keep this destination")
    with pytest.raises(FileExistsError):
        SqliteEngagementStore.restore_backup(backup, destination)
    assert destination.read_bytes() == b"keep this destination"

    with sqlite3.connect(backup) as database:
        database.execute("PRAGMA user_version = 999")
    with pytest.raises(ValueError, match="schema version"):
        SqliteEngagementStore.verify_backup(backup)


def test_engagement_backup_verifier_rejects_sqlite_sidecars(tmp_path: Path) -> None:
    store = SqliteEngagementStore(tmp_path / "live.db")
    backup = tmp_path / "backup.db"
    store.backup(backup)
    store.close()

    Path(f"{backup}-wal").write_bytes(b"untrusted sidecar")
    with pytest.raises(ValueError, match="self-contained"):
        SqliteEngagementStore.verify_backup(backup)


def test_engagement_backup_cli_round_trip(tmp_path: Path) -> None:
    storage = tmp_path / "source"
    store = SqliteEngagementStore(storage / "engagements.db")
    expected = _engagement()
    store.save(expected)
    store.close()

    runner = CliRunner()
    backup = tmp_path / "cli-backup.db"
    result = runner.invoke(app, ["backup", "--storage", str(storage), "--output", str(backup)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["engagement_count"] == 1

    verified = runner.invoke(app, ["verify-backup", "--backup", str(backup)])
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.stdout)["engagement_count"] == 1

    restored_storage = tmp_path / "restored"
    restored = runner.invoke(
        app,
        ["restore-backup", "--backup", str(backup), "--storage", str(restored_storage)],
    )
    assert restored.exit_code == 0, restored.output
    check = SqliteEngagementStore(restored_storage / "engagements.db")
    try:
        assert check.require(expected.engagement_id).name == expected.name
    finally:
        check.close()
