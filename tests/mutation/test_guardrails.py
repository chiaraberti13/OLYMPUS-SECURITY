"""Focused mutation tests for security and correctness boundaries."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from olympus.athena.application.coordinator import RunOutcome
from olympus.athena.cli import _exit_code_for
from olympus.athena.domain.assessment import (
    AssessmentState,
    Job,
    JobState,
    TransitionError,
    advance_job,
    derive_terminal_state,
)
from olympus.athena.scope import TargetOutOfScopeError, ensure_target_allowed
from olympus.core.coverage import Coverage, RunStatus, exit_code_for
from olympus.core.execution import redact_mapping, redact_text, safe_terminal_text
from olympus.core.exit_codes import ExitCode
from olympus.core.models import EngagementScope
from olympus.core.signing import generate_keypair
from olympus.engagements.manifest import (
    EngagementManifest,
    ManifestAuthorizationError,
    ManifestVerificationError,
    SignedEngagementManifest,
)
from olympus.themis.adapters.nmap import NmapAdapter
from olympus.themis.adapters.nuclei import NucleiAdapter
from olympus.themis.api import ApiSettings, RequestConcurrencyGate
from olympus.themis.base import ParseError
from olympus.themis.legacy_vap import (
    LegacyVapSnapshotError,
    _decision,
    approve_legacy_vap_import,
    create_legacy_vap_conversion_plan,
    create_legacy_vap_snapshot,
    verify_legacy_vap_snapshot,
)
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput


def test_api_concurrency_gate_rejects_overflow_and_recovers_after_release() -> None:
    gate = RequestConcurrencyGate(1)

    assert gate.try_acquire() is True
    assert gate.try_acquire() is False
    gate.release()
    assert gate.try_acquire() is True
    gate.release()


def test_api_settings_default_shared_key_scope_is_minimum_and_validated(tmp_path: Path) -> None:
    settings = ApiSettings(
        database=tmp_path / "jobs.sqlite3",
        scope_directory=tmp_path,
        api_key="a" * 32,
    )
    settings.validate()
    assert settings.api_key_scopes == ("capabilities:read",)

    with pytest.raises(ValueError, match="unknown Themis API key scopes"):
        ApiSettings(
            database=tmp_path / "jobs.sqlite3",
            scope_directory=tmp_path,
            api_key="a" * 32,
            api_key_scopes=("jobs:admin",),
        ).validate()
    with pytest.raises(ValueError, match="scopes must be strings"):
        ApiSettings(
            database=tmp_path / "jobs.sqlite3",
            scope_directory=tmp_path,
            api_key="a" * 32,
            api_key_scopes=(42,),  # type: ignore[arg-type]
        ).validate()


def test_api_settings_manifest_trust_anchor_is_nonempty_and_has_revocation_store(
    tmp_path: Path,
) -> None:
    database = tmp_path / "engagements.db"
    valid = ApiSettings(
        database=tmp_path / "jobs.sqlite3",
        scope_directory=tmp_path,
        api_key="a" * 32,
        engagements_database=database,
        trusted_manifest_public_key_pem="-----BEGIN PUBLIC KEY-----\nsynthetic\n",
    )
    valid.validate()

    with pytest.raises(ValueError, match="public key must not be empty"):
        ApiSettings(
            database=tmp_path / "jobs.sqlite3",
            scope_directory=tmp_path,
            api_key="a" * 32,
            engagements_database=database,
            trusted_manifest_public_key_pem=" \n\t",
        ).validate()
    with pytest.raises(ValueError, match="require an engagement database"):
        ApiSettings(
            database=tmp_path / "jobs.sqlite3",
            scope_directory=tmp_path,
            api_key="a" * 32,
            trusted_manifest_public_key_pem="pinned-key",
        ).validate()


def test_scope_gate_accepts_domain_and_subdomain_but_rejects_suffix_spoof() -> None:
    allowed = ("example.com",)

    assert ensure_target_allowed("domain", "example.com", allowed) == "example.com"
    assert ensure_target_allowed("domain", "api.example.com", allowed) == "api.example.com"
    assert ensure_target_allowed("domain", "API.EXAMPLE.COM.", allowed) == "api.example.com"
    with pytest.raises(TargetOutOfScopeError):
        ensure_target_allowed("domain", "notexample.com", allowed)
    with pytest.raises(TargetOutOfScopeError):
        ensure_target_allowed("domain", "attacker.invalid", allowed)


def test_redaction_covers_nested_sensitive_keys_and_url_queries() -> None:
    result = redact_mapping(
        {
            "Authorization": "Bearer hidden-auth",
            "details": [
                {
                    "api_key": "hidden-key",
                    "url": "https://example.test/?token=hidden-token&page=2#results",
                }
            ],
            "x-api-key": "hidden-header-key",
        }
    )
    serialized = str(result)

    assert result["Authorization"] == "[REDACTED]"
    assert result["details"][0]["api_key"] == "[REDACTED]"  # type: ignore[index]
    assert "hidden-auth" not in serialized
    assert "hidden-key" not in serialized
    assert "hidden-token" not in serialized
    assert "hidden-header-key" not in serialized
    assert "[REDACTED]" in serialized
    assert "page=2" in serialized
    redacted_text = redact_text("failed https://example.test/?token=hidden-token&page=2")
    assert "hidden-token" not in redacted_text
    assert "[REDACTED]" in redacted_text
    assert "page=2" in redacted_text


def test_terminal_text_removes_control_sequences_and_redacts_secrets() -> None:
    safe = safe_terminal_text("ok\x1b]0;title\x07\r\nhttps://x.test/?token=secret")

    assert "\x1b" not in safe and "\n" not in safe
    assert "secret" not in safe and "[REDACTED]" in safe


def _signed_manifest() -> tuple[SignedEngagementManifest, str, datetime]:
    private_key, public_key = generate_keypair()
    valid_from = datetime(2026, 10, 19, tzinfo=UTC)
    manifest = EngagementManifest(
        engagement_id="ENG-2026-00001",
        client="Example Client",
        owner="Security Owner",
        approver="Authorized Approver",
        contract_id="CONTRACT-2026-01",
        scope=EngagementScope(included=("example.com",), excluded=("admin.example.com",)),
        valid_from=valid_from,
        expires_at=valid_from + timedelta(hours=8),
        allowed_techniques=("nmap",),
    )
    return (
        SignedEngagementManifest.sign_manifest(manifest, private_key_pem=private_key),
        public_key,
        valid_from,
    )


def test_signed_manifest_gate_enforces_trusted_signature_and_scope() -> None:
    signed, public_key, valid_from = _signed_manifest()
    authorized = signed.authorize(
        trusted_public_key_pem=public_key,
        target="www.example.com",
        technique="nmap",
        now=valid_from,
    )
    assert authorized.engagement_id == "ENG-2026-00001"

    with pytest.raises(ManifestAuthorizationError):
        signed.authorize(
            trusted_public_key_pem=public_key,
            target="admin.example.com",
            technique="nmap",
            now=valid_from,
        )
    with pytest.raises(ManifestAuthorizationError):
        signed.authorize(
            trusted_public_key_pem=public_key,
            target="www.example.com",
            technique="nmap",
            now=signed.manifest.expires_at,
        )

    _other_private, other_public = generate_keypair()
    with pytest.raises(ManifestVerificationError):
        signed.authorize(
            trusted_public_key_pem=other_public,
            target="www.example.com",
            technique="nmap",
            now=valid_from,
        )


def test_nmap_parser_emits_only_open_ports_and_flags_high_risk_port() -> None:
    xml = (
        "<nmaprun><host><ports>"
        '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>'
        '<port protocol="tcp" portid="8000"><state state="open"/><service name="http"/></port>'
        '<port protocol="tcp" portid="443"><state state="closed"/></port>'
        "</ports></host></nmaprun>"
    )
    request = ScanRequest(scanner="nmap", target="127.0.0.1", allowed=("127.0.0.1",))
    output = CommandOutput(exit_code=0, stdout=xml, stderr="")

    findings = NmapAdapter().parse(output, "127.0.0.1", request)

    assert len(findings) == 2
    assert "23/tcp" in findings[0].title
    assert findings[0].severity.value == "medium"
    assert "port=23/tcp" in findings[0].evidence
    assert "service=telnet" in findings[0].evidence
    assert "8000/tcp" in findings[1].title
    assert findings[1].severity.value == "info"
    assert "443/tcp" not in " ".join(finding.title for finding in findings)
    with pytest.raises(ParseError):
        NmapAdapter().parse(
            CommandOutput(exit_code=0, stdout="<broken", stderr=""), "127.0.0.1", request
        )


@pytest.mark.parametrize(
    "record",
    [
        "[]",
        "{}",
        '{"info":{}}',
        '{"template-id":"t"}',
        '{"template-id":"t","info":[]}',
        '{"template-id":"","info":{}}',
    ],
)
def test_nuclei_parser_rejects_json_without_required_record_fields(record: str) -> None:
    request = ScanRequest(scanner="nuclei", target="127.0.0.1", allowed=("127.0.0.1",))
    output = CommandOutput(exit_code=0, stdout=record, stderr="")

    with pytest.raises(ParseError):
        NucleiAdapter().parse(output, "127.0.0.1", request)


def test_nuclei_parser_accepts_a_structurally_valid_finding() -> None:
    request = ScanRequest(scanner="nuclei", target="127.0.0.1", allowed=("127.0.0.1",))
    output = CommandOutput(
        exit_code=0,
        stdout='{"template-id":"lab-template","info":{"name":"Lab finding"}}',
        stderr="",
    )

    findings = NucleiAdapter().parse(output, "127.0.0.1", request)

    assert len(findings) == 1
    assert findings[0].title == "Lab finding (lab-template)"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (RunStatus.CLEAN, ExitCode.OK),
        (RunStatus.FINDINGS, ExitCode.FINDINGS),
        (RunStatus.PARTIAL, ExitCode.PARTIAL),
        (RunStatus.FAILED, ExitCode.FAILED),
    ],
)
def test_exit_codes_preserve_run_status(status: RunStatus, expected: ExitCode) -> None:
    assert exit_code_for(status) is expected


def test_coverage_status_keeps_partial_and_failure_distinct() -> None:
    assert Coverage(planned=1, completed=1).status(0) is RunStatus.CLEAN
    assert Coverage(planned=1, completed=1).status(1) is RunStatus.FINDINGS
    assert Coverage(planned=2, completed=1, failed=1).status(1) is RunStatus.PARTIAL
    assert Coverage(planned=1, failed=1).status(0) is RunStatus.FAILED


@pytest.mark.parametrize(
    ("state", "findings", "expected"),
    [
        (AssessmentState.SUCCEEDED, [], ExitCode.OK),
        (AssessmentState.SUCCEEDED, [object()], ExitCode.FINDINGS),
        (AssessmentState.PARTIAL, [], ExitCode.PARTIAL),
        (AssessmentState.CANCELLED, [], ExitCode.CANCELLED),
        (AssessmentState.FAILED, [], ExitCode.FAILED),
    ],
)
def test_athena_exit_code_contract(state, findings, expected) -> None:
    outcome = RunOutcome(assessment_id="ASM-1", state=state, findings=findings)
    assert _exit_code_for(outcome) == expected


def test_job_state_machine_rejects_terminal_skip_and_derives_partial() -> None:
    queued = Job(job_id="JOB-1", adapter="nmap", target_kind="domain", target_value="example.com")
    running = advance_job(queued, JobState.RUNNING)
    succeeded = advance_job(running, JobState.SUCCEEDED, result_id="RES-1")

    assert succeeded.state is JobState.SUCCEEDED
    with pytest.raises(TransitionError):
        advance_job(queued, JobState.SUCCEEDED)
    with pytest.raises(TransitionError):
        advance_job(succeeded, JobState.FAILED)

    failed = Job(
        job_id="JOB-2",
        adapter="nmap",
        target_kind="domain",
        target_value="example.com",
        state=JobState.FAILED,
    )
    assert derive_terminal_state((succeeded, failed)) is AssessmentState.PARTIAL


@pytest.mark.parametrize(
    ("legacy_state", "native_state", "decision"),
    [
        ("completed", "succeeded", "convertible_terminal"),
        ("failed", "failed", "convertible_terminal"),
        ("canceled", "cancelled", "convertible_terminal"),
        ("queued", None, "blocked_active"),
        ("running", None, "blocked_active"),
        ("unknown", None, "unmapped"),
    ],
)
def test_legacy_vap_state_mapping_never_makes_active_rows_executable(
    legacy_state: str,
    native_state: str | None,
    decision: str,
) -> None:
    assert _decision(legacy_state) == (native_state, decision)


def _legacy_vap_fixture(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            """CREATE TABLE scans (
            id INTEGER PRIMARY KEY, target TEXT NOT NULL, scan_type TEXT NOT NULL,
            status TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT,
            deleted_at TEXT, findings_json TEXT, scan_configuration_json TEXT
            )"""
        )
        db.execute(
            """INSERT INTO scans VALUES
            (1, 'example.test', 'nmap', 'completed', '2026-01-01T00:00:00+00:00',
             '2026-01-01T00:01:00+00:00', NULL, '[]', '{}')"""
        )


def test_legacy_vap_verification_binds_all_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_vap_fixture(source)
    created = create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    assert verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest) == created

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["scans"][0]["legacy_state"] = "failed"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(LegacyVapSnapshotError, match="inventory does not match"):
        verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)


def test_legacy_vap_verification_refuses_source_and_backup_changes(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_vap_fixture(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    with sqlite3.connect(source) as db:
        db.execute("UPDATE scans SET status = 'failed'")
    with pytest.raises(LegacyVapSnapshotError, match="source does not match"):
        verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    source = tmp_path / "vap-backup-check.db"
    backup = tmp_path / "backup-check.db"
    manifest = tmp_path / "manifest-check.json"
    _legacy_vap_fixture(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    with sqlite3.connect(backup) as db:
        db.execute("UPDATE scans SET status = 'failed'")
    with pytest.raises(LegacyVapSnapshotError, match="backup does not match"):
        verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)


def test_legacy_vap_verification_refuses_alias_and_contract_drift(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_vap_fixture(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    with pytest.raises(LegacyVapSnapshotError, match="must be different"):
        verify_legacy_vap_snapshot(source, backup=source, manifest=manifest)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["schema_version"] = "9.0.0"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match=r"1\.0\.0"):
        verify_legacy_vap_snapshot(source, backup=backup, manifest=manifest)


def test_legacy_vap_conversion_plan_never_authorizes_or_creates_jobs(tmp_path: Path) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    _legacy_vap_fixture(source)
    create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)

    plan = create_legacy_vap_conversion_plan(
        source,
        backup=backup,
        manifest=manifest,
        output=tmp_path / "plan.json",
        native_scanners=frozenset({"nmap"}),
    )

    assert plan.entry_count == len(plan.entries) == 1
    assert plan.entries[0].disposition == "review_terminal"
    assert plan.entries[0].requires_operator_review is True
    assert plan.executable_jobs_created == 0
    assert plan.authorization_inherited is False


def test_legacy_vap_approval_requires_current_signed_scope_and_creates_no_jobs(
    tmp_path: Path,
) -> None:
    source = tmp_path / "vap.db"
    backup = tmp_path / "backup.db"
    manifest = tmp_path / "manifest.json"
    plan_path = tmp_path / "plan.json"
    signed_path = tmp_path / "signed.json"
    key_path = tmp_path / "approver.pub.pem"
    _legacy_vap_fixture(source)
    snapshot = create_legacy_vap_snapshot(source, backup=backup, manifest=manifest)
    create_legacy_vap_conversion_plan(
        source,
        backup=backup,
        manifest=manifest,
        output=plan_path,
        native_scanners=frozenset({"nmap"}),
    )
    private_key, public_key = generate_keypair()
    now = datetime(2026, 10, 23, 8, 0, tzinfo=UTC)
    current_manifest = EngagementManifest(
        engagement_id="ENG-2026-00001",
        client="Synthetic Client",
        owner="Synthetic Owner",
        approver="Synthetic Approver",
        contract_id="SYNTHETIC-CONTRACT",
        scope=EngagementScope(included=("example.test",), excluded=()),
        valid_from=now - timedelta(hours=1),
        expires_at=now + timedelta(hours=1),
        allowed_techniques=("nmap",),
        max_targets=1,
    )
    signed = SignedEngagementManifest.sign_manifest(current_manifest, private_key_pem=private_key)
    signed_path.write_text(signed.model_dump_json(), encoding="utf-8")
    key_path.write_text(public_key, encoding="utf-8")

    approval = approve_legacy_vap_import(
        source,
        backup=backup,
        manifest=manifest,
        plan_path=plan_path,
        signed_manifest_path=signed_path,
        trusted_public_key_path=key_path,
        output=tmp_path / "approval.json",
        migration_keys=(snapshot.scans[0].migration_key,),
        native_scanners=frozenset({"nmap"}),
        now=now,
    )

    assert approval.approved_count == len(approval.approvals) == 1
    assert approval.approvals[0].native_state == "succeeded"
    assert approval.historical_execution_authorized is False
    assert approval.executable_jobs_created == 0
    with pytest.raises(ValueError):
        approve_legacy_vap_import(
            source,
            backup=backup,
            manifest=manifest,
            plan_path=plan_path,
            signed_manifest_path=signed_path,
            trusted_public_key_path=key_path,
            output=tmp_path / "revoked.json",
            migration_keys=(snapshot.scans[0].migration_key,),
            native_scanners=frozenset({"nmap"}),
            revoked=(signed.manifest_sha256,),
            now=now,
        )
