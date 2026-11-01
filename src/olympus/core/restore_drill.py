"""Offline backup/restore drill on a declared synthetic dataset (ROADMAP WEB-J-01).

The drill creates a throw-away engagement store, a custody ledger, an identity
register and a structured audit log filled with synthetic rows, snapshots them
with their own store verifiers, binds the snapshots in a backup manifest,
restores them into a clean directory and checks that the restored data matches.
Phases are timed with a monotonic clock so the recovery time (RTO) of *this
dataset on this host* is measured, not assumed.

The recovery point is demonstrated, not promised: rows written after the
snapshot are deliberately absent from the restore, so the data-loss window equals
the interval since the last snapshot. Results say nothing about production
volumes, other stores or other hardware.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.athena.domain.assessment import Assessment, Job
from olympus.athena.domain.contracts import AssessmentPlan, AssessmentResult, load_plan
from olympus.core import backup_manifest as bm
from olympus.core.audit_backup import backup_audit_log, restore_audit_backup
from olympus.core.coverage import RunStatus
from olympus.core.execution import StructuredAuditRecord, append_structured_audit
from olympus.core.models import Engagement, EngagementScope, Evidence
from olympus.engagements.store import SqliteEngagementStore
from olympus.minerva.custody import (
    AcquisitionProvenance,
    CustodyAction,
    append_entry,
    backup_ledger,
    restore_ledger_backup,
)
from olympus.themis.identity import (
    IdentityRegister,
    add_identity,
    backup_register,
    restore_register_backup,
    save_register,
)
from olympus.themis.jobs import ThemisJobStore
from olympus.themis.scope_backup import backup_scope, restore_scope

SCHEMA_NAME = "olympus.restore-drill"
SCHEMA_VERSION = "1.0.0"
MAX_ENGAGEMENTS = 5_000
MAX_LEDGER_ENTRIES = 2_000
MAX_IDENTITIES = 200
MAX_AUDIT_RECORDS = 5_000
MAX_JOBS = 1_000
MAX_ASSESSMENTS = 500
_T0 = datetime(2026, 1, 1, tzinfo=UTC)


class RestoreDrillError(RuntimeError):
    """Raised when a restored artifact does not match what was backed up."""


def _engagement(index: int) -> Engagement:
    return Engagement(
        name=f"Synthetic drill engagement {index}",
        client="Example Org",
        scope=EngagementScope(included=("example.test",)),
        authorization_reference="SYNTHETIC-ONLY",
    )


def _evidence() -> Evidence:
    return Evidence(
        evidence_id="EVD-2026-00001",
        evidence_type="memory-image",
        uri="file://olympus-drill/memory.raw",
        sha256="a" * 64,
    )


def _athena_plan() -> AssessmentPlan:
    return load_plan(
        {
            "engagement_id": "ENG-DRILL",
            "name": "synthetic drill plan",
            "targets": [{"kind": "domain", "value": "example.com"}],
            "adapters": ["dns"],
            "scope": {"allowed_domains": ["example.com"]},
            "authorization": {
                "engagement_id": "ENG-DRILL",
                "approval_reference": "SYNTHETIC-ONLY",
                "confirmed": True,
            },
        }
    )


def _seed_athena(repo: SqliteAssessmentRepository, index: int, plan_id: str) -> None:
    """Persist one synthetic assessment with a job, a stored result and an audit row."""
    assessment_id, job_id = f"ASSESS-DRILL-{index}", f"JOB-DRILL-{index}"
    job = Job(job_id=job_id, adapter="dns", target_kind="domain", target_value="example.com")
    repo.save_assessment(Assessment(assessment_id=assessment_id, plan_id=plan_id, jobs=(job,)))
    document = AssessmentResult(
        assessment_id=assessment_id,
        job=job.to_contract(assessment_id).model_copy(update={"state": "succeeded"}),
    ).canonical_json()
    repo.save_result(assessment_id, job_id, document)
    repo.append_audit(assessment_id, 0, "2026-01-01T00:00:00Z", "drill", "ok", None, "{}")


def _timed(timings: dict[str, float], name: str, started: float) -> None:
    timings[name] = round(time.perf_counter() - started, 6)


def run_drill(
    workdir: Path,
    *,
    engagements: int = 100,
    ledger_entries: int = 50,
    post_snapshot: int = 5,
    identities: int = 10,
    audit_records: int = 50,
    jobs: int = 20,
    assessments: int = 5,
) -> dict[str, object]:
    """Run the drill under ``workdir`` (must not exist) and return a report."""
    if not 1 <= engagements <= MAX_ENGAGEMENTS:
        raise ValueError(f"engagements must be 1..{MAX_ENGAGEMENTS}")
    if not 1 <= ledger_entries <= MAX_LEDGER_ENTRIES:
        raise ValueError(f"ledger_entries must be 1..{MAX_LEDGER_ENTRIES}")
    if not 1 <= identities <= MAX_IDENTITIES:
        raise ValueError(f"identities must be 1..{MAX_IDENTITIES}")
    if not 1 <= audit_records <= MAX_AUDIT_RECORDS:
        raise ValueError(f"audit_records must be 1..{MAX_AUDIT_RECORDS}")
    if not 1 <= jobs <= MAX_JOBS:
        raise ValueError(f"jobs must be 1..{MAX_JOBS}")
    if not 1 <= assessments <= MAX_ASSESSMENTS:
        raise ValueError(f"assessments must be 1..{MAX_ASSESSMENTS}")
    if not 0 <= post_snapshot <= MAX_ENGAGEMENTS:
        raise ValueError("post_snapshot out of range")
    if workdir.exists() or workdir.is_symlink():
        raise FileExistsError("drill workdir must not exist")
    live, snaps, restored = workdir / "live", workdir / "snapshots", workdir / "restored"
    for directory in (live, snaps):
        directory.mkdir(parents=True, mode=0o700)

    store = SqliteEngagementStore(live / "engagements.db")
    ledger = live / "custody.json"
    athena = SqliteAssessmentRepository(live / "athena.db")
    try:
        athena_plan_id = athena.save_plan(_athena_plan())
        for index in range(assessments):
            _seed_athena(athena, index, athena_plan_id)
        for index in range(engagements):
            store.save(_engagement(index))
        evidence = _evidence()
        provenance = AcquisitionProvenance(
            tool="nmap",
            tool_version="7.95",
            policy_sha256="b" * 64,
            scope_sha256="c" * 64,
            command_template=("nmap", "-sV", "{target}"),
            coverage_status=RunStatus.CLEAN,
        )
        for index in range(ledger_entries):
            append_entry(
                ledger,
                evidence,
                CustodyAction.TRANSFERRED if index else CustodyAction.COLLECTED,
                "drill",
                _T0 + timedelta(minutes=index),
                acquisition=provenance if index == 0 else None,
            )

        register = IdentityRegister()
        for index in range(identities):
            register, _secret = add_identity(
                register, identity_id=f"drill-{index}", scopes=["jobs:read"]
            )
        register_path = live / "identities.json"
        save_register(register_path, register)
        audit_path = live / "audit.jsonl"
        for index in range(audit_records):
            append_structured_audit(
                audit_path,
                StructuredAuditRecord(
                    timestamp=(_T0 + timedelta(seconds=index)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    execution_id=f"drill-{index}",
                    action="drill.event",
                    outcome="ok",
                    target="example.test",
                    metadata={"note": "synthetic"},
                ),
            )

        scope_path = live / "scope.json"
        scope_path.write_text(
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
        job_store = ThemisJobStore(live / "jobs.sqlite3")
        job_ids = [
            job_store.submit(
                scanner="synthetic",
                target="127.0.0.1",
                target_kind="host",
                scope_path=scope_path,
                authorized=True,
            ).job_id
            for _ in range(jobs)
        ]
        # Cancel a share of the jobs so more than one lifecycle state is restored.
        for job_id in job_ids[::2]:
            job_store.cancel(job_id)
        states_before = job_store.counts_by_state()

        timings: dict[str, float] = {}
        started = time.perf_counter()
        eng_info = store.backup(snaps / "engagements.sqlite3")
        led_info = backup_ledger(ledger, snaps / "custody.json")
        id_info = backup_register(register_path, snaps / "identities.json")
        audit_info = backup_audit_log(audit_path, snaps / "audit.jsonl")
        jobs_info = job_store.backup(snaps / "jobs.sqlite3")
        scope_info = backup_scope(scope_path, snaps / "scope.json")
        athena_info = athena.backup(snaps / "athena.sqlite3")
        _timed(timings, "backup", started)

        started = time.perf_counter()
        bm.write_manifest(
            snaps,
            bm.build_manifest(
                snaps,
                {
                    "engagements": "engagements.sqlite3",
                    "custody": "custody.json",
                    "identities": "identities.json",
                    "audit": "audit.jsonl",
                    "themis-jobs": "jobs.sqlite3",
                    "themis-scope": "scope.json",
                    "athena": "athena.sqlite3",
                },
            ),
        )
        _timed(timings, "manifest", started)

        # Writes after the snapshot: these define the (non-zero) data-loss window.
        for index in range(post_snapshot):
            store.save(_engagement(engagements + index))
        for _ in range(post_snapshot):
            job_store.submit(
                scanner="synthetic",
                target="127.0.0.1",
                target_kind="host",
                scope_path=scope_path,
                authorized=True,
            )
        for index in range(assessments, assessments + post_snapshot):
            _seed_athena(athena, index, athena_plan_id)
    finally:
        store.close()
        athena.close()

    started = time.perf_counter()
    bm.verify_manifest(snaps)
    restored.mkdir(parents=True, mode=0o700)
    r_eng = SqliteEngagementStore.restore_backup(
        snaps / "engagements.sqlite3", restored / "engagements.db"
    )
    r_led = restore_ledger_backup(snaps / "custody.json", restored / "custody.json")
    r_id = restore_register_backup(snaps / "identities.json", restored / "identities.json")
    r_audit = restore_audit_backup(snaps / "audit.jsonl", restored / "audit.jsonl")
    r_jobs = ThemisJobStore.restore_backup(snaps / "jobs.sqlite3", restored / "jobs.sqlite3")
    r_scope = restore_scope(snaps / "scope.json", restored / "scope.json")
    r_athena = SqliteAssessmentRepository.restore_backup(
        snaps / "athena.sqlite3", restored / "athena.db"
    )
    _timed(timings, "restore_and_verify", started)

    if r_eng.engagement_count != engagements or eng_info.engagement_count != engagements:
        raise RestoreDrillError("restored engagement count differs from the snapshot")
    if r_led.entries != ledger_entries or led_info.entries != ledger_entries:
        raise RestoreDrillError("restored ledger entry count differs from the snapshot")
    if r_id.identities != identities or id_info.identities != identities:
        raise RestoreDrillError("restored identity count differs from the snapshot")
    if r_audit.records != audit_records or audit_info.records != audit_records:
        raise RestoreDrillError("restored audit record count differs from the snapshot")
    if r_jobs.job_count != jobs or jobs_info.job_count != jobs:
        raise RestoreDrillError("restored Themis job count differs from the snapshot")
    if (r_scope.sha256, r_scope.hosts, r_scope.cidrs) != (
        scope_info.sha256,
        scope_info.hosts,
        scope_info.cidrs,
    ) or r_scope.sha256 != hashlib.sha256(scope_path.read_bytes()).hexdigest():
        raise RestoreDrillError("restored scope differs from the snapshot")
    athena_counts = (
        r_athena.plan_count,
        r_athena.assessment_count,
        r_athena.job_count,
        r_athena.result_count,
        r_athena.audit_event_count,
    )
    if athena_counts != (1, assessments, assessments, assessments, assessments) or (
        athena_counts
        != (
            athena_info.plan_count,
            athena_info.assessment_count,
            athena_info.job_count,
            athena_info.result_count,
            athena_info.audit_event_count,
        )
    ):
        raise RestoreDrillError("restored Athena store differs from the snapshot")
    states_after = ThemisJobStore(restored / "jobs.sqlite3").counts_by_state()
    if states_after != states_before:
        raise RestoreDrillError("restored Themis job states differ from the snapshot")

    return {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "dataset": {
            "synthetic": True,
            "engagements": engagements,
            "ledger_entries": ledger_entries,
            "identities": identities,
            "audit_records": audit_records,
            "jobs": jobs,
            "athena_assessments": assessments,
            "post_snapshot_writes": post_snapshot,
        },
        "timings_seconds": timings,
        "rto_seconds": round(timings["restore_and_verify"], 6),
        "recovery_point": {
            "restored_engagements": r_eng.engagement_count,
            "engagements_lost_after_snapshot": post_snapshot,
            "restored_jobs": r_jobs.job_count,
            "jobs_lost_after_snapshot": post_snapshot,
            "restored_athena_assessments": r_athena.assessment_count,
            "athena_assessments_lost_after_snapshot": post_snapshot,
            "note": "data written after the snapshot is not recovered",
        },
        "stores_covered": [
            "engagements",
            "custody-ledger",
            "identity",
            "audit",
            "themis-jobs",
            "themis-scope",
            "athena",
        ],
        "stores_not_covered": [
            "findings-transitions",
            "vault",
            "evidence-files",
            "encryption-keys",
        ],
        "disclaimer": (
            "Measured on this host with synthetic data only; not a production RPO/RTO guarantee."
        ),
    }
