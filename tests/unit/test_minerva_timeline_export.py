"""Minerva signed timeline export (DFIR).

`minerva timeline` already prints a verified custody timeline; these cover the
new portable, third-party-verifiable export: a canonical JSON artifact and an
Ed25519 signature over its exact bytes (reusing `core.signing`), so a recipient
can confirm provenance with `olympus core verify`.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.models import Evidence
from olympus.core.signing import generate_keypair, verify
from olympus.minerva.custody import CustodyAction, append_entry

runner = CliRunner()


def _ledger(tmp_path: Path) -> Path:
    ledger = tmp_path / "custody.json"
    evidence = Evidence(evidence_type="disk-image", uri="file://case/d.raw", sha256="b" * 64)
    append_entry(ledger, evidence, CustodyAction.COLLECTED, "responder")
    append_entry(ledger, evidence, CustodyAction.ANALYZED, "forensics")
    return ledger


def test_timeline_export_writes_a_canonical_artifact(tmp_path: Path) -> None:
    export = tmp_path / "tl.json"
    result = runner.invoke(
        app,
        [
            "minerva",
            "timeline",
            str(_ledger(tmp_path)),
            "--format",
            "json",
            "--export",
            str(export),
        ],
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(export.read_text(encoding="utf-8"))
    assert doc["schema_name"] == "olympus.minerva-timeline"
    assert doc["count"] == 2
    assert [row["action"] for row in doc["timeline"]] == ["collected", "analyzed"]


def test_signed_timeline_export_is_third_party_verifiable(tmp_path: Path) -> None:
    private_pem, public_pem = generate_keypair()
    key = tmp_path / "priv.pem"
    key.write_text(private_pem, encoding="utf-8")
    export = tmp_path / "tl.json"
    result = runner.invoke(
        app,
        [
            "minerva",
            "timeline",
            str(_ledger(tmp_path)),
            "--export",
            str(export),
            "--sign-key",
            str(key),
        ],
    )
    assert result.exit_code == 0, result.output
    signature = export.with_name(export.name + ".sig")
    assert signature.exists(), "expected a detached signature envelope"

    data = export.read_bytes()
    envelope = signature.read_text(encoding="utf-8")
    assert verify(data, envelope, public_pem=public_pem) is True
    # Any tampering with the exported timeline breaks verification.
    tampered = data.replace(b"forensics", b"attacker")
    assert tampered != data
    assert verify(tampered, envelope, public_pem=public_pem) is False


def test_sign_key_requires_export(tmp_path: Path) -> None:
    private_pem, _ = generate_keypair()
    key = tmp_path / "priv.pem"
    key.write_text(private_pem, encoding="utf-8")
    result = runner.invoke(
        app,
        ["minerva", "timeline", str(_ledger(tmp_path)), "--sign-key", str(key)],
    )
    assert result.exit_code == 2
    assert "--sign-key requires --export" in result.output
