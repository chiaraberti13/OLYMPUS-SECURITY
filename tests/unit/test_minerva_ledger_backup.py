"""WEB-J-01: custody ledger backup, verification and create-only restore (synthetic data)."""

from __future__ import annotations

import json
import stat
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.coverage import RunStatus
from olympus.core.models import Evidence
from olympus.minerva.custody import (
    CUSTODY_KEY_ENV,
    AcquisitionProvenance,
    CustodyAction,
    CustodyIntegrityError,
    append_entry,
    backup_ledger,
    load_ledger,
    restore_ledger_backup,
    verify_ledger_backup,
)

runner = CliRunner()
_T0 = datetime(2026, 8, 14, 9, tzinfo=UTC)


def _evidence() -> Evidence:
    return Evidence(
        evidence_id="EVD-2026-00001",
        evidence_type="memory-image",
        uri="file://olympus-demo/memory.raw",
        sha256="a" * 64,
    )


def _ledger(path: Path, *, key: bytes | None = None) -> Path:
    provenance = AcquisitionProvenance(
        tool="nmap",
        tool_version="7.95",
        policy_sha256="b" * 64,
        scope_sha256="c" * 64,
        command_template=("nmap", "-sV", "{target}"),
        coverage_status=RunStatus.CLEAN,
    )
    append_entry(
        path,
        _evidence(),
        CustodyAction.COLLECTED,
        "responder",
        _T0,
        acquisition=provenance,
        key=key,
    )
    append_entry(
        path,
        _evidence(),
        CustodyAction.TRANSFERRED,
        "forensics",
        _T0 + timedelta(minutes=5),
        key=key,
    )
    return path


def test_backup_round_trip_is_byte_exact_and_owner_only(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "custody.json")
    snapshot = tmp_path / "snap.json"

    info = backup_ledger(ledger, snapshot)
    restored = tmp_path / "restored.json"
    restore_info = restore_ledger_backup(snapshot, restored)

    assert info.entries == 2
    assert snapshot.read_bytes() == ledger.read_bytes() == restored.read_bytes()
    assert info == restore_info
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o600
    assert load_ledger(restored) == load_ledger(ledger)
    # The restored ledger stays appendable: the chain continues unbroken.
    append_entry(restored, _evidence(), CustodyAction.ANALYZED, "analyst", _T0 + timedelta(hours=1))
    assert len(load_ledger(restored)) == 3


def test_backup_refuses_overwrite_and_symlink(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "custody.json")
    existing = tmp_path / "exists.json"
    existing.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(existing)

    with pytest.raises(CustodyIntegrityError, match="already exists"):
        backup_ledger(ledger, existing)
    with pytest.raises(CustodyIntegrityError, match="symlink"):
        backup_ledger(ledger, link)
    assert existing.read_text(encoding="utf-8") == "keep"


def test_backup_refuses_tampered_source_and_leaves_no_snapshot(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "custody.json")
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entries"][0]["actor"] = "attacker"
    ledger.write_text(json.dumps(payload), encoding="utf-8")
    snapshot = tmp_path / "snap.json"

    with pytest.raises(CustodyIntegrityError):
        backup_ledger(ledger, snapshot)
    assert not snapshot.exists()


def test_verify_detects_truncated_and_missing_snapshots(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "custody.json")
    snapshot = tmp_path / "snap.json"
    backup_ledger(ledger, snapshot)
    snapshot.write_bytes(snapshot.read_bytes()[:-40])

    with pytest.raises((CustodyIntegrityError, ValueError)):
        verify_ledger_backup(snapshot)
    with pytest.raises(CustodyIntegrityError, match="does not exist"):
        verify_ledger_backup(tmp_path / "absent.json")


def test_signed_ledger_reports_signature_only_with_key(tmp_path: Path) -> None:
    key = b"k" * 32
    ledger = _ledger(tmp_path / "custody.json", key=key)
    snapshot = tmp_path / "snap.json"

    without_key = backup_ledger(ledger, snapshot)
    with_key = verify_ledger_backup(snapshot, key=key)

    assert without_key.signed and not without_key.signature_verified
    assert with_key.signed and with_key.signature_verified


def test_backup_during_concurrent_appends_is_a_valid_prefix(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "custody.json")
    stop = threading.Event()

    def _writer() -> None:
        moment = _T0 + timedelta(hours=1)
        while not stop.is_set():
            moment += timedelta(seconds=1)
            append_entry(ledger, _evidence(), CustodyAction.ANALYZED, "analyst", moment)

    thread = threading.Thread(target=_writer)
    thread.start()
    try:
        for index in range(5):
            info = backup_ledger(ledger, tmp_path / f"snap{index}.json")
            assert info.entries >= 2
    finally:
        stop.set()
        thread.join()


def test_cli_backup_verify_restore_and_tamper(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(CUSTODY_KEY_ENV, raising=False)
    ledger = _ledger(tmp_path / "custody.json")
    snapshot = tmp_path / "snap.json"
    restored = tmp_path / "restored.json"

    made = runner.invoke(
        app, ["minerva", "ledger-backup", "--ledger", str(ledger), "--destination", str(snapshot)]
    )
    again = runner.invoke(
        app, ["minerva", "ledger-backup", "--ledger", str(ledger), "--destination", str(snapshot)]
    )
    ok = runner.invoke(app, ["minerva", "ledger-verify-backup", "--backup", str(snapshot)])
    back = runner.invoke(
        app,
        ["minerva", "ledger-restore", "--backup", str(snapshot), "--destination", str(restored)],
    )
    payload = json.loads(snapshot.read_text(encoding="utf-8"))
    payload["entries"][1]["actor"] = "attacker"
    snapshot.write_text(json.dumps(payload), encoding="utf-8")
    bad = runner.invoke(app, ["minerva", "ledger-verify-backup", "--backup", str(snapshot)])

    assert made.exit_code == 0, made.output
    assert again.exit_code == 2
    assert ok.exit_code == 0 and json.loads(ok.stdout)["entries"] == 2
    assert back.exit_code == 0 and restored.exists()
    assert bad.exit_code == 2
