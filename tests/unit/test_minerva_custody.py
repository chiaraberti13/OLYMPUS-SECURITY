"""Tests for Minerva's tamper-evident evidence custody ledger."""

import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.execution import CancellationRequested, CancellationToken
from olympus.core.models import Evidence
from olympus.minerva.application import (
    MinervaApplicationService,
    MinervaLedgerRequest,
    MinervaRecordRequest,
)
from olympus.minerva.custody import (
    CUSTODY_KEY_ENV,
    GENESIS_HASH,
    SIGNED_CUSTODY_VERSION,
    CustodyAction,
    CustodyIntegrityError,
    CustodyKeyError,
    LegacyCustodyEntry,
    _entry_hash,
    _legacy_entry_hash,
    append_entry,
    inspect_ledger,
    load_custody_key,
    load_ledger,
)

runner = CliRunner()


def _evidence() -> Evidence:
    return Evidence(
        evidence_id="EVD-2026-00001",
        evidence_type="memory-image",
        uri="file://olympus-demo/memory.raw",
        sha256="a" * 64,
    )


def test_append_and_load_verified_chain(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    first = append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder", started)
    second = append_entry(
        ledger,
        _evidence(),
        CustodyAction.TRANSFERRED,
        "forensics",
        started + timedelta(minutes=30),
    )

    assert first.sequence == 1
    assert second.previous_hash == first.entry_hash
    assert first.evidence_sha256 == _evidence().sha256
    assert load_ledger(ledger) == [first, second]
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "2.0.0"
    assert stat.S_IMODE(ledger.stat().st_mode) == 0o600


def test_tampering_is_detected_before_append(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder")
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entries"][0]["actor"] = "attacker"
    ledger.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CustodyIntegrityError, match="hash mismatch"):
        load_ledger(ledger)
    with pytest.raises(CustodyIntegrityError):
        append_entry(ledger, _evidence(), CustodyAction.ANALYZED, "analyst")


def test_regressive_timestamp_is_rejected(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    later = datetime(2026, 8, 14, 10, tzinfo=UTC)
    append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder", later)
    with pytest.raises(CustodyIntegrityError, match="timestamps"):
        append_entry(
            ledger,
            _evidence(),
            CustodyAction.TRANSFERRED,
            "forensics",
            later - timedelta(hours=1),
        )
    assert len(load_ledger(ledger)) == 1


def test_record_and_verify_commands(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    evidence_path = tmp_path / "evidence.json"
    evidence = Evidence(
        evidence_type="memory-image", uri="file://case/mem.raw", sha256="a" * 64
    )
    evidence_path.write_text(evidence.model_dump_json(), encoding="utf-8")

    first = runner.invoke(
        app,
        ["minerva", "record", str(evidence_path), str(ledger),
         "--actor", "responder", "--action", "collected"],
    )
    second = runner.invoke(
        app,
        ["minerva", "record", str(evidence_path), str(ledger),
         "--actor", "forensics", "--action", "transferred"],
    )
    verified = runner.invoke(app, ["minerva", "verify", str(ledger)])

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert verified.exit_code == 0
    assert "2 entries" in verified.stdout


def test_timeline_command(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    evidence = Evidence(evidence_type="disk-image", uri="file://c/d.raw", sha256="b" * 64)
    append_entry(ledger, evidence, CustodyAction.COLLECTED, "resp")
    append_entry(ledger, evidence, CustodyAction.ANALYZED, "forensics")
    result = runner.invoke(app, ["minerva", "timeline", str(ledger), "--format", "json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.output)
    assert [r["action"] for r in rows] == ["collected", "analyzed"]
    assert rows[0]["evidence_sha256"] == "b" * 64


def test_missing_and_symlink_ledgers_do_not_verify_clean(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["minerva", "verify", str(tmp_path / "missing.json")])
    assert missing.exit_code == 2
    assert "does not exist" in missing.output

    ledger = tmp_path / "custody.json"
    append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder")
    link = tmp_path / "custody-link.json"
    link.symlink_to(ledger)
    linked = runner.invoke(app, ["minerva", "verify", str(link)])
    assert linked.exit_code == 2
    assert "symlink" in linked.output


def test_custody_transitions_and_limits_fail_before_overwrite(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    with pytest.raises(CustodyIntegrityError, match="first custody action"):
        append_entry(ledger, _evidence(), CustodyAction.ANALYZED, "analyst")
    assert not ledger.exists()

    append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder", max_entries=1)
    original = ledger.read_bytes()
    with pytest.raises(CustodyIntegrityError, match="entry limit"):
        append_entry(
            ledger,
            _evidence(),
            CustodyAction.TRANSFERRED,
            "forensics",
            max_entries=1,
        )
    assert ledger.read_bytes() == original


def test_legacy_ledger_is_verifiable_but_read_only_and_unanchored(tmp_path: Path) -> None:
    timestamp = datetime(2026, 8, 14, 9, tzinfo=UTC)
    provisional = LegacyCustodyEntry(
        sequence=1,
        evidence_id="EVD-2026-00001",
        action=CustodyAction.COLLECTED,
        actor="responder",
        occurred_at=timestamp,
        previous_hash="0" * 64,
        entry_hash="0" * 64,
    )
    entry = provisional.model_copy(update={"entry_hash": _legacy_entry_hash(provisional)})
    ledger = tmp_path / "legacy.json"
    ledger.write_text(
        json.dumps(
            {
                "schema_name": "olympus.custody",
                "schema_version": "1.0.0",
                "entries": [entry.model_dump(mode="json")],
            }
        ),
        encoding="utf-8",
    )

    inspection = inspect_ledger(ledger)
    assert inspection.evidence_anchored is False
    verified = runner.invoke(app, ["minerva", "verify", str(ledger)])
    assert verified.exit_code == 1
    assert "not digest-anchored" in verified.output
    with pytest.raises(CustodyIntegrityError, match="read-only"):
        append_entry(ledger, _evidence(), CustodyAction.TRANSFERRED, "forensics")


def test_application_rejects_conflict_and_observes_cancellation(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.json"
    evidence.write_text(_evidence().model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="must differ"):
        MinervaApplicationService().record(
            MinervaRecordRequest(evidence, evidence, "responder", CustodyAction.COLLECTED)
        )

    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        MinervaApplicationService(token).inspect(MinervaLedgerRequest(tmp_path / "any.json"))


# --- Ledger attacks: truncation, reorder, fork, full rewrite (roadmap §5.2) --- #
#
# A hash-linked, sequence-contiguous ledger detects any edit that breaks the
# chain: reordering entries, deleting a non-tail entry, or forging a fork with a
# duplicate sequence number all make the sequence non-contiguous or the
# `previous_hash` link fail. These tests lock that in.
#
# Two attacks are *not* detectable from an UNSIGNED (2.0.0) ledger's content
# alone, and the `documents_the_gap` tests below make that residual limitation
# explicit rather than hiding it:
#   * **tail truncation** — dropping the most recent entries leaves a shorter
#     but internally consistent chain; nothing inside the file records how long
#     it was meant to be, and
#   * **full rewrite** — an attacker who recomputes every `entry_hash` produces a
#     ledger indistinguishable from a legitimate one, because the hashes are not
#     keyed.
# Both are closed by *signing* the ledger (2.1.0): the HMAC section further down
# ("Signed ledger") proves that with an operator key both attacks are caught. The
# gap tests therefore still hold for the unsigned case an operator gets without a
# key, and the signed tests show the mitigation.


def _three_entry_ledger(tmp_path: Path) -> Path:
    """Append a verified collected → transferred → analyzed chain."""
    ledger = tmp_path / "custody.json"
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder", started)
    append_entry(
        ledger, _evidence(), CustodyAction.TRANSFERRED, "forensics",
        started + timedelta(minutes=10),
    )
    append_entry(
        ledger, _evidence(), CustodyAction.ANALYZED, "analyst",
        started + timedelta(minutes=20),
    )
    return ledger


def _rewrite(ledger: Path, payload: dict) -> None:
    ledger.write_text(json.dumps(payload), encoding="utf-8")


def test_reordering_entries_is_detected(tmp_path: Path) -> None:
    ledger = _three_entry_ledger(tmp_path)
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entries"][0], payload["entries"][1] = (
        payload["entries"][1], payload["entries"][0],
    )
    _rewrite(ledger, payload)
    with pytest.raises(CustodyIntegrityError, match="sequence is not contiguous"):
        load_ledger(ledger)


def test_deleting_a_middle_entry_is_detected(tmp_path: Path) -> None:
    ledger = _three_entry_ledger(tmp_path)
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    del payload["entries"][1]  # sequences become 1, 3
    _rewrite(ledger, payload)
    with pytest.raises(CustodyIntegrityError, match="sequence is not contiguous"):
        load_ledger(ledger)


def test_forking_with_a_duplicate_sequence_is_detected(tmp_path: Path) -> None:
    ledger = _three_entry_ledger(tmp_path)
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entries"][2]["sequence"] = 2  # two entries now claim sequence 2
    _rewrite(ledger, payload)
    with pytest.raises(CustodyIntegrityError, match="sequence is not contiguous"):
        load_ledger(ledger)


def test_tail_truncation_documents_the_gap(tmp_path: Path) -> None:
    """On an UNSIGNED ledger, dropping the last entry still verifies.

    This is the inherent limit of an append-only hash chain with no external
    anchor: the file does not record its intended length, so a shorter prefix is
    internally consistent. It is closed by signing the ledger — see
    `test_signed_ledger_detects_tail_truncation` — but an operator who runs
    without a key still has this exposure, so the behaviour is pinned here.
    """
    ledger = _three_entry_ledger(tmp_path)
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entries"] = payload["entries"][:-1]  # drop the analyzed entry
    _rewrite(ledger, payload)
    records = load_ledger(ledger)  # NOT rejected — the known gap
    assert [record.sequence for record in records] == [1, 2]


def test_full_rewrite_documents_the_gap(tmp_path: Path) -> None:
    """On an UNSIGNED ledger, a recomputed valid chain is accepted (unkeyed hashes).

    An attacker who controls the file can rebuild the whole ledger with any
    contents and recompute every `entry_hash`; without a secret key the result is
    indistinguishable from a genuine ledger. Signing closes this — see
    `test_signed_ledger_detects_full_rewrite`; the unsigned exposure is pinned
    here.
    """
    ledger = _three_entry_ledger(tmp_path)
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    digest = "a" * 64
    forged_hash = _entry_hash(
        1, "EVD-2026-00001", digest, CustodyAction.COLLECTED,
        "attacker", started, GENESIS_HASH,
    )
    forged = {
        "schema_name": "olympus.custody",
        "schema_version": "2.0.0",
        "entries": [
            {
                "sequence": 1,
                "evidence_id": "EVD-2026-00001",
                "evidence_sha256": digest,
                "action": "collected",
                "actor": "attacker",
                "occurred_at": started.isoformat(),
                "previous_hash": GENESIS_HASH,
                "entry_hash": forged_hash,
            }
        ],
    }
    _rewrite(ledger, forged)
    records = load_ledger(ledger)  # NOT rejected — the known gap
    assert records[0].actor == "attacker"


# --- Signed ledger: HMAC-SHA256 closes the truncation / rewrite gaps (§2) ---- #

_KEY = b"operator-signing-key"


def _signed_three_entry_ledger(tmp_path: Path) -> Path:
    ledger = tmp_path / "custody.json"
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    append_entry(ledger, _evidence(), CustodyAction.COLLECTED, "responder", started, key=_KEY)
    append_entry(
        ledger, _evidence(), CustodyAction.TRANSFERRED, "forensics",
        started + timedelta(minutes=10), key=_KEY,
    )
    append_entry(
        ledger, _evidence(), CustodyAction.ANALYZED, "analyst",
        started + timedelta(minutes=20), key=_KEY,
    )
    return ledger


def test_signed_ledger_is_written_and_verifies(tmp_path: Path) -> None:
    ledger = _signed_three_entry_ledger(tmp_path)
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    assert payload["schema_version"] == SIGNED_CUSTODY_VERSION
    assert payload["signature"]["algorithm"] == "HMAC-SHA256"
    assert payload["signature"]["entry_count"] == 3

    inspection = inspect_ledger(ledger, key=_KEY)
    assert inspection.signed is True
    assert inspection.signature_verified is True


def test_wrong_signing_key_is_rejected(tmp_path: Path) -> None:
    ledger = _signed_three_entry_ledger(tmp_path)
    with pytest.raises(CustodyIntegrityError, match="signature mismatch"):
        inspect_ledger(ledger, key=b"the-wrong-key")


def test_signed_ledger_detects_tail_truncation(tmp_path: Path) -> None:
    ledger = _signed_three_entry_ledger(tmp_path)
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entries"] = payload["entries"][:-1]  # keep the 3-entry signature
    _rewrite(ledger, payload)
    with pytest.raises(CustodyIntegrityError, match=r"truncation|commits to"):
        inspect_ledger(ledger, key=_KEY)


def test_signed_ledger_detects_full_rewrite(tmp_path: Path) -> None:
    ledger = _signed_three_entry_ledger(tmp_path)
    started = datetime(2026, 8, 14, 9, tzinfo=UTC)
    digest = "a" * 64
    forged_hash = _entry_hash(
        1, "EVD-2026-00001", digest, CustodyAction.COLLECTED,
        "attacker", started, GENESIS_HASH,
    )
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entries"] = [
        {
            "sequence": 1,
            "evidence_id": "EVD-2026-00001",
            "evidence_sha256": digest,
            "action": "collected",
            "actor": "attacker",
            "occurred_at": started.isoformat(),
            "previous_hash": GENESIS_HASH,
            "entry_hash": forged_hash,
        }
    ]
    # The attacker keeps the original signature (they cannot recompute it).
    _rewrite(ledger, payload)
    with pytest.raises(CustodyIntegrityError):
        inspect_ledger(ledger, key=_KEY)


def test_signed_ledger_without_key_verifies_chain_but_flags_signature(tmp_path: Path) -> None:
    ledger = _signed_three_entry_ledger(tmp_path)
    inspection = inspect_ledger(ledger)  # no key
    assert inspection.signed is True
    assert inspection.signature_verified is False  # chain checked, HMAC not


def test_appending_to_a_signed_ledger_without_a_key_is_refused(tmp_path: Path) -> None:
    ledger = _signed_three_entry_ledger(tmp_path)
    with pytest.raises(CustodyKeyError, match="signed"):
        append_entry(ledger, _evidence(), CustodyAction.ARCHIVED, "x")


def test_load_custody_key_reads_the_environment() -> None:
    assert load_custody_key({CUSTODY_KEY_ENV: "secret"}) == b"secret"
    assert load_custody_key({CUSTODY_KEY_ENV: "   "}) is None  # blank is unset
    assert load_custody_key({}) is None


def test_verify_command_reports_signed_and_verified(tmp_path: Path, monkeypatch) -> None:
    ledger = _signed_three_entry_ledger(tmp_path)
    monkeypatch.setenv(CUSTODY_KEY_ENV, _KEY.decode())
    result = runner.invoke(app, ["minerva", "verify", str(ledger)])
    assert result.exit_code == 0, result.output
    assert "signature verified" in result.output


def test_verify_command_fails_a_signed_ledger_without_a_key(tmp_path: Path, monkeypatch) -> None:
    ledger = _signed_three_entry_ledger(tmp_path)
    monkeypatch.delenv(CUSTODY_KEY_ENV, raising=False)
    result = runner.invoke(app, ["minerva", "verify", str(ledger)])
    assert result.exit_code == 1
    assert "no key to verify" in result.output
