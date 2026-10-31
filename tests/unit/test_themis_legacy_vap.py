from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import EngagementScope
from olympus.core.signing import generate_keypair
from olympus.engagements.manifest import EngagementManifest, SignedEngagementManifest
from olympus.themis.jobs import JobState, ThemisJobStore
from olympus.themis.legacy_vap import (
    LegacyVapSnapshotError,
    approve_legacy_vap_import,
    create_legacy_vap_conversion_plan,
    create_legacy_vap_snapshot,
    import_legacy_vap_history,
    verify_legacy_vap_snapshot,
)


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


def _approval_artifacts(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path, Path, str, datetime]:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "snapshot.json"
    plan = tmp_path / "plan.json"
    signed_path = tmp_path / "signed.json"
    key_path = tmp_path / "approver.pub.pem"
    _legacy_database(source)
    snapshot = create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    create_legacy_vap_conversion_plan(
        source,
        backup=backup,
        manifest=manifest,
        output=plan,
        native_scanners=frozenset({"nmap"}),
    )
    now = datetime(2026, 10, 23, 8, 0, tzinfo=UTC)
    private_key, public_key = generate_keypair()
    engagement = EngagementManifest(
        engagement_id="ENG-2026-00001",
        client="Synthetic Client",
        owner="Synthetic Owner",
        approver="Synthetic Approver",
        contract_id="SYNTHETIC-CONTRACT",
        scope=EngagementScope(
            included=("https://example.test/search?token=super-secret",), excluded=()
        ),
        valid_from=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
        allowed_techniques=("nmap",),
        max_targets=1,
    )
    signed = SignedEngagementManifest.sign_manifest(engagement, private_key_pem=private_key)
    signed_path.write_text(signed.model_dump_json(), encoding="utf-8")
    key_path.write_text(public_key, encoding="utf-8")
    return (
        source,
        backup,
        manifest,
        plan,
        signed_path,
        key_path,
        snapshot.scans[0].migration_key,
        now,
    )


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


def test_verify_reconstructs_inventory_and_cli_emits_no_legacy_content(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_database(source)
    created = create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    verified = verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    assert verified == created
    result = CliRunner().invoke(
        app,
        [
            "themis",
            "legacy-verify",
            "--source",
            str(source),
            "--backup",
            str(backup),
            "--manifest",
            str(manifest),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["verified"] is True
    assert payload["scan_count"] == 1
    assert "super-secret" not in result.output
    assert "example.test" not in result.output


def test_conversion_plan_is_review_only_minimized_and_create_only(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "plan.json"
    _legacy_database(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    plan = create_legacy_vap_conversion_plan(
        source,
        backup=backup,
        manifest=manifest,
        output=output,
        native_scanners=frozenset({"nmap"}),
    )

    assert plan.entry_count == 1
    assert plan.entries[0].disposition == "review_terminal"
    assert plan.entries[0].native_scanner == "nmap"
    assert plan.executable_jobs_created == 0
    assert plan.authorization_inherited is False
    rendered = output.read_text(encoding="utf-8")
    assert "super-secret" not in rendered
    assert "example.test" not in rendered
    with pytest.raises(ValueError, match="refusing to overwrite"):
        create_legacy_vap_conversion_plan(
            source,
            backup=backup,
            manifest=manifest,
            output=output,
            native_scanners=frozenset({"nmap"}),
        )


def test_import_approval_is_signed_selected_minimized_and_non_executable(tmp_path: Path) -> None:
    source, backup, manifest, plan, signed, key, migration_key, now = _approval_artifacts(tmp_path)
    output = tmp_path / "approval.json"

    approval = approve_legacy_vap_import(
        source,
        backup=backup,
        manifest=manifest,
        plan_path=plan,
        signed_manifest_path=signed,
        trusted_public_key_path=key,
        output=output,
        migration_keys=(migration_key,),
        native_scanners=frozenset({"nmap"}),
        now=now,
    )

    assert approval.approved_count == 1
    assert approval.approvals[0].disposition == "approved_historical_import"
    assert approval.approvals[0].historical_execution_authorized is False
    assert approval.historical_execution_authorized is False
    assert approval.executable_jobs_created == 0
    rendered = output.read_text(encoding="utf-8")
    assert "super-secret" not in rendered
    assert "example.test" not in rendered


def test_historical_import_is_terminal_partial_redacted_and_idempotent(tmp_path: Path) -> None:
    source, backup, manifest, plan, signed, key, migration_key, now = _approval_artifacts(tmp_path)
    approval_path = tmp_path / "approval.json"
    approve_legacy_vap_import(
        source,
        backup=backup,
        manifest=manifest,
        plan_path=plan,
        signed_manifest_path=signed,
        trusted_public_key_path=key,
        output=approval_path,
        migration_keys=(migration_key,),
        native_scanners=frozenset({"nmap"}),
        now=now,
    )
    database = tmp_path / "native.db"
    receipt = import_legacy_vap_history(
        source,
        backup=backup,
        manifest=manifest,
        plan_path=plan,
        approval_path=approval_path,
        signed_manifest_path=signed,
        trusted_public_key_path=key,
        database=database,
        output=tmp_path / "receipt.json",
        native_scanners=frozenset({"nmap"}),
        now=now,
    )

    assert receipt.imported_count == 1
    assert receipt.imports[0].native_job_state == "partial"
    assert receipt.historical_execution_authorized is False
    assert receipt.executable_jobs_created == 0
    store = ThemisJobStore(database)
    jobs = store.list()
    assert len(jobs) == 1
    assert jobs[0].state is JobState.PARTIAL
    assert jobs[0].authorized is False
    assert jobs[0].manifest_sha256 is None
    assert jobs[0].attempts == 0
    assert jobs[0].target.endswith("token=[REDACTED]")
    assert store.claim_next("test-worker") is None
    assert "super-secret" not in database.read_bytes().decode("utf-8", errors="ignore")

    repeated = import_legacy_vap_history(
        source,
        backup=backup,
        manifest=manifest,
        plan_path=plan,
        approval_path=approval_path,
        signed_manifest_path=signed,
        trusted_public_key_path=key,
        database=database,
        output=tmp_path / "receipt-2.json",
        native_scanners=frozenset({"nmap"}),
        now=now,
    )
    assert repeated.imports[0].job_id == receipt.imports[0].job_id
    assert len(store.list()) == 1


@pytest.mark.parametrize(
    ("legacy_state", "expected"),
    [("failed", JobState.FAILED), ("canceled", JobState.CANCELLED)],
)
def test_historical_import_preserves_failure_outcomes(
    tmp_path: Path, legacy_state: str, expected: JobState
) -> None:
    source = tmp_path / "vap.db"
    _legacy_database(source, state=legacy_state)
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "snapshot.json"
    plan = tmp_path / "plan.json"
    signed = tmp_path / "signed.json"
    key = tmp_path / "key.pem"
    snapshot = create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    create_legacy_vap_conversion_plan(
        source,
        backup=backup,
        manifest=manifest,
        output=plan,
        native_scanners=frozenset({"nmap"}),
    )
    now = datetime(2026, 10, 23, 8, 0, tzinfo=UTC)
    private_key, public_key = generate_keypair()
    engagement = EngagementManifest(
        engagement_id="ENG-2026-00001",
        client="Synthetic Client",
        owner="Synthetic Owner",
        approver="Synthetic Approver",
        contract_id="SYNTHETIC-CONTRACT",
        scope=EngagementScope(
            included=("https://example.test/search?token=super-secret",), excluded=()
        ),
        valid_from=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
        allowed_techniques=("nmap",),
        max_targets=1,
    )
    signed.write_text(
        SignedEngagementManifest.sign_manifest(
            engagement, private_key_pem=private_key
        ).model_dump_json(),
        encoding="utf-8",
    )
    key.write_text(public_key, encoding="utf-8")
    approval = tmp_path / "approval.json"
    approve_legacy_vap_import(
        source,
        backup=backup,
        manifest=manifest,
        plan_path=plan,
        signed_manifest_path=signed,
        trusted_public_key_path=key,
        output=approval,
        migration_keys=(snapshot.scans[0].migration_key,),
        native_scanners=frozenset({"nmap"}),
        now=now,
    )
    receipt = import_legacy_vap_history(
        source,
        backup=backup,
        manifest=manifest,
        plan_path=plan,
        approval_path=approval,
        signed_manifest_path=signed,
        trusted_public_key_path=key,
        database=tmp_path / "native.db",
        output=tmp_path / "receipt.json",
        native_scanners=frozenset({"nmap"}),
        now=now,
    )
    assert receipt.imports[0].native_job_state == expected.value
    assert ThemisJobStore(tmp_path / "native.db").list()[0].state is expected


@pytest.mark.parametrize("failure", ["revoked", "wrong-key", "unselected", "active"])
def test_import_approval_fails_closed(tmp_path: Path, failure: str) -> None:
    source, backup, manifest, plan, signed, key, migration_key, now = _approval_artifacts(tmp_path)
    revoked: tuple[str, ...] = ()
    selected = (migration_key,)
    if failure == "revoked":
        signed_document = SignedEngagementManifest.model_validate_json(
            signed.read_text(encoding="utf-8")
        )
        revoked = (signed_document.manifest_sha256,)
    elif failure == "wrong-key":
        _private, other_public = generate_keypair()
        key.write_text(other_public, encoding="utf-8")
    elif failure == "unselected":
        selected = ("0" * 64,)
    else:
        with sqlite3.connect(source) as db:
            db.execute("UPDATE scans SET status = 'running'")

    with pytest.raises(ValueError):
        approve_legacy_vap_import(
            source,
            backup=backup,
            manifest=manifest,
            plan_path=plan,
            signed_manifest_path=signed,
            trusted_public_key_path=key,
            output=tmp_path / "approval.json",
            migration_keys=selected,
            native_scanners=frozenset({"nmap"}),
            revoked=revoked,
            now=now,
        )
    assert not (tmp_path / "approval.json").exists()


def test_legacy_approve_cli_emits_only_receipt_metadata(tmp_path: Path) -> None:
    source, backup, manifest, plan, signed, key, migration_key, _now = _approval_artifacts(tmp_path)
    signed_document = SignedEngagementManifest.model_validate_json(
        signed.read_text(encoding="utf-8")
    )
    current_time = datetime.now(UTC)
    signed_document.manifest = signed_document.manifest.model_validate(
        {
            **signed_document.manifest.model_dump(),
            "valid_from": current_time - timedelta(hours=1),
            "expires_at": current_time + timedelta(hours=1),
        }
    )
    private_key, public_key = generate_keypair()
    current = SignedEngagementManifest.sign_manifest(
        signed_document.manifest, private_key_pem=private_key
    )
    signed.write_text(current.model_dump_json(), encoding="utf-8")
    key.write_text(public_key, encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "themis",
            "legacy-approve",
            "--source",
            str(source),
            "--backup",
            str(backup),
            "--manifest",
            str(manifest),
            "--plan",
            str(plan),
            "--signed-manifest",
            str(signed),
            "--manifest-public-key",
            str(key),
            "--migration-key",
            migration_key,
            "--output",
            str(tmp_path / "approval.json"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["approved_count"] == 1
    assert payload["historical_execution_authorized"] is False
    assert payload["executable_jobs_created"] == 0
    assert "super-secret" not in result.output
    assert "example.test" not in result.output

    revoked = CliRunner().invoke(
        app,
        [
            "themis",
            "legacy-approve",
            "--source",
            str(source),
            "--backup",
            str(backup),
            "--manifest",
            str(manifest),
            "--plan",
            str(plan),
            "--signed-manifest",
            str(signed),
            "--manifest-public-key",
            str(key),
            "--migration-key",
            migration_key,
            "--revoked",
            current.manifest_sha256,
            "--output",
            str(tmp_path / "revoked.json"),
        ],
    )
    assert revoked.exit_code == 4
    assert not (tmp_path / "revoked.json").exists()


def test_legacy_import_cli_is_non_executable_and_revocation_aware(tmp_path: Path) -> None:
    source, backup, manifest, plan, signed, key, migration_key, _now = _approval_artifacts(tmp_path)
    signed_document = SignedEngagementManifest.model_validate_json(
        signed.read_text(encoding="utf-8")
    )
    current_time = datetime.now(UTC)
    signed_document.manifest = signed_document.manifest.model_validate(
        {
            **signed_document.manifest.model_dump(),
            "valid_from": current_time - timedelta(hours=1),
            "expires_at": current_time + timedelta(hours=1),
        }
    )
    private_key, public_key = generate_keypair()
    current = SignedEngagementManifest.sign_manifest(
        signed_document.manifest, private_key_pem=private_key
    )
    signed.write_text(current.model_dump_json(), encoding="utf-8")
    key.write_text(public_key, encoding="utf-8")
    approval = tmp_path / "approval.json"
    approve_legacy_vap_import(
        source,
        backup=backup,
        manifest=manifest,
        plan_path=plan,
        signed_manifest_path=signed,
        trusted_public_key_path=key,
        output=approval,
        migration_keys=(migration_key,),
        native_scanners=frozenset({"nmap"}),
        now=current_time,
    )

    result = CliRunner().invoke(
        app,
        [
            "themis",
            "legacy-import",
            "--source",
            str(source),
            "--backup",
            str(backup),
            "--manifest",
            str(manifest),
            "--plan",
            str(plan),
            "--approval",
            str(approval),
            "--signed-manifest",
            str(signed),
            "--manifest-public-key",
            str(key),
            "--database",
            str(tmp_path / "native.db"),
            "--output",
            str(tmp_path / "receipt.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["imported_count"] == 1
    assert payload["historical_execution_authorized"] is False
    assert payload["executable_jobs_created"] == 0
    assert "super-secret" not in result.output
    assert "example.test" not in result.output
    assert ThemisJobStore(tmp_path / "native.db").claim_next("cli-worker") is None

    revoked = CliRunner().invoke(
        app,
        [
            "themis",
            "legacy-import",
            "--source",
            str(source),
            "--backup",
            str(backup),
            "--manifest",
            str(manifest),
            "--plan",
            str(plan),
            "--approval",
            str(approval),
            "--signed-manifest",
            str(signed),
            "--manifest-public-key",
            str(key),
            "--database",
            str(tmp_path / "revoked.db"),
            "--revoked",
            current.manifest_sha256,
            "--output",
            str(tmp_path / "revoked-receipt.json"),
        ],
    )
    assert revoked.exit_code == 4
    assert not (tmp_path / "revoked.db").exists()
    assert not (tmp_path / "revoked-receipt.json").exists()


@pytest.mark.parametrize(
    ("state", "scan_type", "deleted", "expected"),
    [
        ("running", "nmap", False, "retain_active"),
        ("report_failed", "nmap", False, "retain_unmapped_state"),
        ("completed", "full", False, "retain_unmapped_scanner"),
        ("completed", "nmap", True, "retain_deleted"),
    ],
)
def test_conversion_plan_fails_closed_by_disposition(
    tmp_path: Path, state: str, scan_type: str, deleted: bool, expected: str
) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_database(source, state=state)
    with sqlite3.connect(source) as db:
        db.execute(
            "UPDATE scans SET scan_type = ?, deleted_at = ?",
            (scan_type, "2026-01-02T00:00:00+00:00" if deleted else None),
        )
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    plan = create_legacy_vap_conversion_plan(
        source,
        backup=backup,
        manifest=manifest,
        output=tmp_path / "plan.json",
        native_scanners=frozenset({"nmap"}),
    )
    assert plan.entries[0].disposition == expected
    assert plan.entries[0].requires_operator_review is True


def test_legacy_plan_cli_emits_only_counts_and_never_creates_jobs(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "plan.json"
    _legacy_database(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    result = CliRunner().invoke(
        app,
        [
            "themis",
            "legacy-plan",
            "--source",
            str(source),
            "--backup",
            str(backup),
            "--manifest",
            str(manifest),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["dispositions"] == {"review_terminal": 1}
    assert payload["executable_jobs_created"] == 0
    assert payload["authorization_inherited"] is False
    assert "super-secret" not in result.output
    assert "example.test" not in result.output


def test_conversion_plan_reverifies_snapshot_before_writing(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    output = tmp_path / "plan.json"
    _legacy_database(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    with sqlite3.connect(backup) as db:
        db.execute("UPDATE scans SET status = 'failed'")

    with pytest.raises(LegacyVapSnapshotError, match="does not match"):
        create_legacy_vap_conversion_plan(
            source,
            backup=backup,
            manifest=manifest,
            output=output,
            native_scanners=frozenset({"nmap"}),
        )
    assert not output.exists()


@pytest.mark.parametrize("artifact", ["source", "backup", "manifest"])
def test_verify_refuses_each_tampered_artifact(tmp_path: Path, artifact: str) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_database(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    if artifact == "source":
        with sqlite3.connect(source) as db:
            db.execute("UPDATE scans SET status = 'failed'")
    elif artifact == "backup":
        with sqlite3.connect(backup) as db:
            db.execute("UPDATE scans SET status = 'failed'")
    else:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        payload["scans"][0]["legacy_state"] = "failed"
        manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(LegacyVapSnapshotError, match="does not match"):
        verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)


def test_verify_refuses_invalid_contract_and_path_aliases(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_database(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["schema_version"] = "9.0.0"
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=r"1\.0\.0"):
        verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    with pytest.raises(LegacyVapSnapshotError, match="must be different"):
        verify_legacy_vap_snapshot(source, backup=source, manifest=manifest)


@settings(max_examples=12, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(tampered_state=st.text(min_size=1, max_size=30).filter(lambda value: value != "completed"))
def test_verify_fails_closed_for_hostile_manifest_state(
    tmp_path: Path, tampered_state: str
) -> None:
    source = tmp_path / "verify-fuzz-vap.db"
    backup = tmp_path / "verify-fuzz-backup.db"
    manifest = tmp_path / "verify-fuzz-manifest.json"
    for path in (source, backup, manifest):
        path.unlink(missing_ok=True)
    _legacy_database(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["scans"][0]["legacy_state"] = tampered_state
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)


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
