"""Offline backup/restore drill on a declared synthetic dataset (ROADMAP WEB-J-01).

The drill creates a throw-away engagement store and a custody ledger filled with
synthetic rows, snapshots both with their own store verifiers, binds the
snapshots in a backup manifest, restores them into a clean directory and checks
that the restored data matches. Phases are timed with a monotonic clock so the
recovery time (RTO) of *this dataset on this host* is measured, not assumed.

The recovery point is demonstrated, not promised: rows written after the
snapshot are deliberately absent from the restore, so the data-loss window equals
the interval since the last snapshot. Results say nothing about production
volumes, other stores or other hardware.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from olympus.core import backup_manifest as bm
from olympus.core.coverage import RunStatus
from olympus.core.models import Engagement, EngagementScope, Evidence
from olympus.engagements.store import SqliteEngagementStore
from olympus.minerva.custody import (
    AcquisitionProvenance,
    CustodyAction,
    append_entry,
    backup_ledger,
    restore_ledger_backup,
)

SCHEMA_NAME = "olympus.restore-drill"
SCHEMA_VERSION = "1.0.0"
MAX_ENGAGEMENTS = 5_000
MAX_LEDGER_ENTRIES = 2_000
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


def _timed(timings: dict[str, float], name: str, started: float) -> None:
    timings[name] = round(time.perf_counter() - started, 6)


def run_drill(
    workdir: Path, *, engagements: int = 100, ledger_entries: int = 50, post_snapshot: int = 5
) -> dict[str, object]:
    """Run the drill under ``workdir`` (must not exist) and return a report."""
    if not 1 <= engagements <= MAX_ENGAGEMENTS:
        raise ValueError(f"engagements must be 1..{MAX_ENGAGEMENTS}")
    if not 1 <= ledger_entries <= MAX_LEDGER_ENTRIES:
        raise ValueError(f"ledger_entries must be 1..{MAX_LEDGER_ENTRIES}")
    if not 0 <= post_snapshot <= MAX_ENGAGEMENTS:
        raise ValueError("post_snapshot out of range")
    if workdir.exists() or workdir.is_symlink():
        raise FileExistsError("drill workdir must not exist")
    live, snaps, restored = workdir / "live", workdir / "snapshots", workdir / "restored"
    for directory in (live, snaps):
        directory.mkdir(parents=True, mode=0o700)

    store = SqliteEngagementStore(live / "engagements.db")
    ledger = live / "custody.json"
    try:
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

        timings: dict[str, float] = {}
        started = time.perf_counter()
        eng_info = store.backup(snaps / "engagements.sqlite3")
        led_info = backup_ledger(ledger, snaps / "custody.json")
        _timed(timings, "backup", started)

        started = time.perf_counter()
        bm.write_manifest(
            snaps,
            bm.build_manifest(
                snaps, {"engagements": "engagements.sqlite3", "custody": "custody.json"}
            ),
        )
        _timed(timings, "manifest", started)

        # Writes after the snapshot: these define the (non-zero) data-loss window.
        for index in range(post_snapshot):
            store.save(_engagement(engagements + index))
    finally:
        store.close()

    started = time.perf_counter()
    bm.verify_manifest(snaps)
    restored.mkdir(parents=True, mode=0o700)
    r_eng = SqliteEngagementStore.restore_backup(
        snaps / "engagements.sqlite3", restored / "engagements.db"
    )
    r_led = restore_ledger_backup(snaps / "custody.json", restored / "custody.json")
    _timed(timings, "restore_and_verify", started)

    if r_eng.engagement_count != engagements or eng_info.engagement_count != engagements:
        raise RestoreDrillError("restored engagement count differs from the snapshot")
    if r_led.entries != ledger_entries or led_info.entries != ledger_entries:
        raise RestoreDrillError("restored ledger entry count differs from the snapshot")

    return {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "dataset": {
            "synthetic": True,
            "engagements": engagements,
            "ledger_entries": ledger_entries,
            "post_snapshot_writes": post_snapshot,
        },
        "timings_seconds": timings,
        "rto_seconds": round(timings["restore_and_verify"], 6),
        "recovery_point": {
            "restored_engagements": r_eng.engagement_count,
            "engagements_lost_after_snapshot": post_snapshot,
            "note": "data written after the snapshot is not recovered",
        },
        "stores_covered": ["engagements", "custody-ledger"],
        "stores_not_covered": [
            "athena",
            "findings-transitions",
            "themis-jobs",
            "identity",
            "audit",
            "scope",
            "vault",
            "evidence-files",
            "encryption-keys",
        ],
        "disclaimer": (
            "Measured on this host with synthetic data only; not a production RPO/RTO guarantee."
        ),
    }
