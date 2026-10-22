from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from olympus.cli import app
from olympus.themis.legacy_vap import LegacyVapSnapshotError, create_legacy_vap_snapshot


def _legacy_database(
    path: Path,
    *,
    target: str = "https://example.test/search?token=super-secret",
    state: str = "completed",
) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            """CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            target TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            deleted_at TEXT,
            findings_json TEXT,
            scan_configuration_json TEXT
            )"""
        )
        db.execute(
            """INSERT INTO scans VALUES
            (1, ?, 'nmap', ?, '2026-01-01T00:00:00+00:00',
             '2026-01-01T00:01:00+00:00', NULL, '[{"severity":"high"}]', '{"rate":1}')""",
            (target, state),
        )
        db.execute(
            """CREATE TABLE consent_records (
            id INTEGER PRIMARY KEY, subject_id TEXT, consent_type TEXT, version TEXT
            )"""
        )
        db.execute("INSERT INTO consent_records VALUES (1, 'person-1', 'terms', 'v1')")


def test_snapshot_is_read_only_consistent_minimized_and_deterministic(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "vap.backup.db"
    manifest = tmp_path / "vap.snapshot.json"
    _legacy_database(source)
    before = source.read_bytes()

    snapshot = create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    assert source.read_bytes() == before
    assert snapshot.source_sha256 == hashlib.sha256(before).hexdigest()
    assert snapshot.backup_sha256 == hashlib.sha256(backup.read_bytes()).hexdigest()
    assert snapshot.scan_count == 1
    scan = snapshot.scans[0]
    assert scan.native_state == "succeeded"
    assert scan.conversion_decision == "convertible_terminal"
    assert (
        scan.migration_key
        == hashlib.sha256(f"{snapshot.backup_sha256}:scans:1".encode()).hexdigest()
    )
    assert "super-secret" not in manifest.read_text(encoding="utf-8")
    assert "example.test" not in manifest.read_text(encoding="utf-8")
    assert snapshot.excluded_tables[0].name == "consent_records"
    assert snapshot.excluded_tables[0].row_count == 1
    with sqlite3.connect(backup) as db:
        assert db.execute("SELECT subject_id FROM consent_records").fetchone()[0] == "person-1"


def test_active_and_unknown_states_never_become_executable_jobs(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    _legacy_database(source, state="running")
    snapshot = create_legacy_vap_snapshot(
        source, backup=tmp_path / "backup.db", manifest=tmp_path / "manifest.json"
    )
    assert snapshot.scans[0].native_state is None
    assert snapshot.scans[0].conversion_decision == "blocked_active"

    with sqlite3.connect(source) as db:
        db.execute("UPDATE scans SET status = 'report_failed'")
    second = create_legacy_vap_snapshot(
        source, backup=tmp_path / "backup-2.db", manifest=tmp_path / "manifest-2.json"
    )
    assert second.scans[0].native_state is None
    assert second.scans[0].conversion_decision == "unmapped"


def test_snapshot_refuses_foreign_schema_collisions_and_symlinks(tmp_path: Path) -> None:
    foreign = tmp_path / "foreign.db"
    with sqlite3.connect(foreign) as db:
        db.execute("CREATE TABLE unrelated (id INTEGER)")
    with pytest.raises(LegacyVapSnapshotError, match="no scans table"):
        create_legacy_vap_snapshot(
            foreign, backup=tmp_path / "backup.db", manifest=tmp_path / "manifest.json"
        )

    source = tmp_path / "vap.db"
    _legacy_database(source)
    backup = tmp_path / "existing.db"
    backup.write_bytes(b"preserve")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        create_legacy_vap_snapshot(source, backup=backup, manifest=tmp_path / "manifest-2.json")
    assert backup.read_bytes() == b"preserve"

    link = tmp_path / "vap-link.db"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(OSError, match="must not be a symlink"):
        create_legacy_vap_snapshot(
            link, backup=tmp_path / "backup-3.db", manifest=tmp_path / "manifest-3.json"
        )


def test_invalid_legacy_row_rolls_back_new_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_database(source)
    with sqlite3.connect(source) as db:
        db.execute("UPDATE scans SET scan_type = ?", ("x" * 51,))

    with pytest.raises(ValueError, match="at most 50 characters"):
        create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    assert not backup.exists()
    assert not manifest.exists()


def test_cli_emits_only_minimized_counts_and_digests(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    _legacy_database(source)
    result = CliRunner().invoke(
        app,
        [
            "themis",
            "legacy-snapshot",
            "--source",
            str(source),
            "--backup",
            str(tmp_path / "backup.db"),
            "--output",
            str(tmp_path / "manifest.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["scan_count"] == 1
    assert payload["conversion_decisions"] == {"convertible_terminal": 1}
    assert "super-secret" not in result.output
    assert "example.test" not in result.output


@settings(max_examples=12, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(
    target=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%",
        min_size=1,
        max_size=120,
    )
)
def test_hostile_targets_remain_bounded_json_data(tmp_path: Path, target: str) -> None:
    source = tmp_path / "fuzz-vap.db"
    backup = tmp_path / "fuzz-backup.db"
    manifest = tmp_path / "fuzz-manifest.json"
    for path in (source, backup, manifest):
        path.unlink(missing_ok=True)
    _legacy_database(source, target=target)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    parsed = json.loads(manifest.read_text(encoding="utf-8"))
    scan = parsed["scans"][0]
    assert scan["target_sha256"] == hashlib.sha256(target.encode()).hexdigest()
    assert set(scan).isdisjoint({"target", "target_redacted", "raw_target"})
