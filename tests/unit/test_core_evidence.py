"""Evidence digests are computed from real artifact bytes at capture (§5.2).

A hand-written ``sha256`` on an evidence reference is trusted blindly: the model
only checks the hex shape. These tests exercise the capture path, which derives
the digest from the artifact's actual bytes, refuses symlinks and oversized
files, and can later re-verify a reference against the material on disk.
"""

from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.evidence import (
    capture_evidence,
    evidence_from_bytes,
    verify_evidence_artifact,
)

runner = CliRunner()


def test_evidence_from_bytes_hashes_the_material() -> None:
    data = b"an in-memory artifact\x00\x01"
    evidence = evidence_from_bytes(data, evidence_type="pcap", uri="mem://capture")
    assert evidence.sha256 == hashlib.sha256(data).hexdigest()
    assert evidence.evidence_type == "pcap"
    assert evidence.uri == "mem://capture"


def test_capture_evidence_matches_the_file_bytes(tmp_path: Path) -> None:
    artifact = tmp_path / "memory.raw"
    payload = b"real captured bytes" * 100
    artifact.write_bytes(payload)

    evidence = capture_evidence(artifact, evidence_type="memory-image")

    assert evidence.sha256 == hashlib.sha256(payload).hexdigest()
    assert evidence.uri == artifact.resolve().as_uri()  # defaults to the file:// path


def test_capture_evidence_uses_an_explicit_uri_when_given(tmp_path: Path) -> None:
    artifact = tmp_path / "disk.img"
    artifact.write_bytes(b"disk contents")
    evidence = capture_evidence(
        artifact, evidence_type="disk-image", uri="s3://case-42/disk.img"
    )
    assert evidence.uri == "s3://case-42/disk.img"


def test_capture_evidence_refuses_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real.bin"
    real.write_bytes(b"contents")
    link = tmp_path / "link.bin"
    link.symlink_to(real)
    with pytest.raises(OSError, match="symlink"):
        capture_evidence(link, evidence_type="blob")


def test_capture_evidence_enforces_the_byte_cap(tmp_path: Path) -> None:
    artifact = tmp_path / "big.bin"
    artifact.write_bytes(b"x" * 2000)
    with pytest.raises(ValueError, match="byte limit"):
        capture_evidence(artifact, evidence_type="blob", max_bytes=1000)


def test_verify_evidence_artifact_detects_drift(tmp_path: Path) -> None:
    artifact = tmp_path / "note.txt"
    artifact.write_bytes(b"original")
    evidence = capture_evidence(artifact, evidence_type="text")
    assert verify_evidence_artifact(artifact, evidence) is True

    artifact.write_bytes(b"tampered")  # the material changed after capture
    assert verify_evidence_artifact(artifact, evidence) is False


# --- CLI: minerva capture ---------------------------------------------------- #


def test_capture_command_writes_owner_only_anchored_evidence(tmp_path: Path) -> None:
    artifact = tmp_path / "memory.raw"
    artifact.write_bytes(b"forensic image bytes")
    output = tmp_path / "evidence.json"

    result = runner.invoke(
        app, ["minerva", "capture", str(artifact), str(output), "--type", "memory-image"]
    )

    assert result.exit_code == 0, result.output
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_name"] == "olympus.evidence"
    assert payload["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()


def test_captured_evidence_round_trips_into_the_custody_ledger(tmp_path: Path) -> None:
    artifact = tmp_path / "disk.img"
    artifact.write_bytes(b"disk image contents")
    evidence_file = tmp_path / "evidence.json"
    ledger = tmp_path / "custody.json"

    captured = runner.invoke(
        app, ["minerva", "capture", str(artifact), str(evidence_file), "--type", "disk-image"]
    )
    recorded = runner.invoke(
        app,
        ["minerva", "record", str(evidence_file), str(ledger),
         "--actor", "responder", "--action", "collected"],
    )

    assert captured.exit_code == 0, captured.output
    assert recorded.exit_code == 0, recorded.output
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert digest in recorded.output  # the ledger anchors the captured digest


def test_capture_command_reports_a_missing_artifact(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["minerva", "capture", str(tmp_path / "absent.raw"),
         str(tmp_path / "out.json"), "--type", "blob"],
    )
    assert result.exit_code == 2
    assert "capture error" in result.output
