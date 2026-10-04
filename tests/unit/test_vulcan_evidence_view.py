"""Unit tests for the finding evidence browser and its CLI (WEB-C)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import FindingStatus, Severity, Source
from olympus.core.models import Evidence, Finding
from olympus.minerva.custody import CustodyAction, CustodyEntry, append_entry
from olympus.vulcan.evidence_view import (
    EVIDENCE_ID_RE,
    build_finding_evidence_view,
)

runner = CliRunner()

_DIGEST = "a" * 64
_OTHER_DIGEST = "b" * 64


def _finding(evidence: list[str]) -> Finding:
    return Finding(
        finding_id="FND-EVID",
        asset_id="AST-1",
        source=Source.THEMIS,
        title="Example finding",
        severity=Severity.HIGH,
        status=FindingStatus.CONFIRMED,
        evidence=evidence,
    )


def _entry(sequence: int, evidence_id: str, action: CustodyAction, digest: str) -> CustodyEntry:
    # The view only reads fields; hashes need only satisfy the shape validators.
    return CustodyEntry(
        sequence=sequence,
        evidence_id=evidence_id,
        evidence_sha256=digest,
        action=action,
        actor="analyst",
        occurred_at=datetime(2026, 1, 1, 12, 0, sequence, tzinfo=UTC),
        previous_hash="0" * 64 if sequence == 1 else "c" * 64,
        entry_hash="d" * 64,
    )


def _evidence(evidence_id: str, digest: str) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        evidence_type="scanner-output",
        uri="https://scanner.example/report?token=secret123",
        sha256=digest,
    )


def test_evidence_id_pattern() -> None:
    assert EVIDENCE_ID_RE.fullmatch("EVD-2026-00001")
    assert not EVIDENCE_ID_RE.fullmatch("scanner=nmap")
    assert not EVIDENCE_ID_RE.fullmatch("EVD-26-1")


def test_inline_snippet_is_redacted_and_defanged() -> None:
    hostile = "url=https://t.example/p?apikey=supersecret\x1b[2Jcleared"
    view = build_finding_evidence_view(_finding([hostile]))
    item = view.items[0]
    assert item.structured is False
    assert item.integrity() == "inline"
    # The URL query secret is redacted and the terminal escape is gone.
    assert "supersecret" not in item.label
    assert "[REDACTED]" in item.label
    assert "\x1b" not in item.label


def test_structured_reference_anchored_when_digest_matches() -> None:
    evidence_id = "EVD-2026-00001"
    records = [
        _entry(1, evidence_id, CustodyAction.COLLECTED, _DIGEST),
        _entry(2, evidence_id, CustodyAction.ANALYZED, _DIGEST),
    ]
    view = build_finding_evidence_view(
        _finding([evidence_id]),
        custody_records=records,
        evidence_records={evidence_id: _evidence(evidence_id, _DIGEST)},
        signed=True,
        signature_verified=True,
    )
    item = view.items[0]
    assert item.structured is True
    assert item.evidence_id == evidence_id
    assert item.evidence_type == "scanner-output"
    assert item.in_ledger is True
    assert len(item.custody) == 2
    assert item.digest == _DIGEST
    assert item.digest_matches_custody is True
    assert item.integrity() == "anchored"
    # The resolved evidence URI is redacted, never leaking the token.
    assert item.uri is not None and "secret123" not in item.uri
    assert view.custody_signature() == "HMAC-SHA256 signature verified"


def test_structured_reference_without_custody_is_honest() -> None:
    evidence_id = "EVD-2026-00002"
    view = build_finding_evidence_view(_finding([evidence_id]))
    item = view.items[0]
    assert item.structured is True
    assert item.in_ledger is False
    assert item.custody == ()
    assert item.digest_matches_custody is None
    assert item.integrity() == "no-custody"


def test_digest_mismatch_is_flagged() -> None:
    evidence_id = "EVD-2026-00003"
    records = [_entry(1, evidence_id, CustodyAction.COLLECTED, _OTHER_DIGEST)]
    view = build_finding_evidence_view(
        _finding([evidence_id]),
        custody_records=records,
        evidence_records={evidence_id: _evidence(evidence_id, _DIGEST)},
    )
    item = view.items[0]
    assert item.digest_matches_custody is False
    assert item.integrity() == "digest-mismatch"


def test_custody_chain_is_filtered_by_evidence_id() -> None:
    wanted = "EVD-2026-00004"
    other = "EVD-2026-00005"
    records = [
        _entry(1, wanted, CustodyAction.COLLECTED, _DIGEST),
        _entry(2, other, CustodyAction.COLLECTED, _OTHER_DIGEST),
    ]
    view = build_finding_evidence_view(_finding([wanted]), custody_records=records)
    item = view.items[0]
    assert len(item.custody) == 1
    assert item.custody[0].action == "collected"


def test_signature_labels() -> None:
    base = _finding(["EVD-2026-00001"])
    assert build_finding_evidence_view(base).custody_signature() == "unsigned"
    assert (
        build_finding_evidence_view(base, signed=True).custody_signature()
        == "SIGNED but not verified (no key)"
    )
    assert (
        build_finding_evidence_view(base, evidence_anchored=False).custody_signature()
        == "legacy ledger (not digest-anchored)"
    )


def test_detail_is_json_serialisable() -> None:
    evidence_id = "EVD-2026-00001"
    records = [_entry(1, evidence_id, CustodyAction.COLLECTED, _DIGEST)]
    view = build_finding_evidence_view(
        _finding([evidence_id, "scanner=nmap"]), custody_records=records
    )
    detail = view.detail()
    # Round-trips through JSON without raising.
    assert json.loads(json.dumps(detail))["finding_id"] == "FND-EVID"
    assert len(detail["items"]) == 2  # type: ignore[arg-type]


def _write_findings(path: Path, findings: list[Finding]) -> Path:
    path.write_text(
        json.dumps([json.loads(f.model_dump_json()) for f in findings]), encoding="utf-8"
    )
    return path


def _write_evidence(path: Path, evidence: Evidence) -> Path:
    path.write_text(evidence.model_dump_json(), encoding="utf-8")
    return path


def test_cli_evidence_table_and_json(tmp_path: Path) -> None:
    evidence_id = "EVD-2026-00001"
    evidence = _evidence(evidence_id, _DIGEST)
    finding = _finding([evidence_id, "scanner=nmap"])
    findings_path = _write_findings(tmp_path / "findings.json", [finding])
    evidence_path = _write_evidence(tmp_path / "evidence.json", evidence)

    # Build a real, verified custody ledger for the evidence.
    ledger = tmp_path / "custody.json"
    append_entry(ledger, evidence, CustodyAction.COLLECTED, "analyst")

    table = runner.invoke(
        app,
        [
            "vulcan",
            "findings",
            "evidence",
            "FND-EVID",
            "--findings",
            str(findings_path),
            "--ledger",
            str(ledger),
            "--evidence",
            str(evidence_path),
        ],
    )
    assert table.exit_code == 0, table.output
    assert "anchored" in table.output
    assert "inline" in table.output
    assert "custody signature: evidence-anchored" not in table.output  # label is our own

    result = runner.invoke(
        app,
        [
            "vulcan",
            "findings",
            "evidence",
            "FND-EVID",
            "--findings",
            str(findings_path),
            "--ledger",
            str(ledger),
            "--evidence",
            str(evidence_path),
            "--format",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["finding_id"] == "FND-EVID"
    items = {item["integrity"] for item in payload["items"]}
    assert items == {"anchored", "inline"}


def test_cli_unknown_finding_errors(tmp_path: Path) -> None:
    findings_path = _write_findings(tmp_path / "findings.json", [_finding(["scanner=nmap"])])
    result = runner.invoke(
        app,
        ["vulcan", "findings", "evidence", "FND-MISSING", "--findings", str(findings_path)],
    )
    assert result.exit_code != 0
    assert "no finding with id" in result.output
