"""Security and CLI tests for Minerva protected evidence storage."""

import json
import stat
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.secrets import EnvSecretProvider
from olympus.minerva.vault import (
    EVIDENCE_ENCRYPTION_KEY_ENV,
    ProtectedEvidenceError,
    load_evidence_encryption_key,
    load_protected_evidence,
    protect_evidence,
    restore_evidence,
)

runner = CliRunner()
_KEY = "correct horse battery staple evidence key"


def _provider(value: str = _KEY) -> EnvSecretProvider:
    return EnvSecretProvider(environ={EVIDENCE_ENCRYPTION_KEY_ENV: value})


@given(st.binary(max_size=4096))
@settings(
    max_examples=8,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_protected_evidence_round_trip_for_arbitrary_bytes(tmp_path: Path, data: bytes) -> None:
    source = tmp_path / "capture.bin"
    protected = tmp_path / "capture.olympus"
    restored = tmp_path / "restored.bin"
    source.write_bytes(data)

    evidence = protect_evidence(
        source, protected, evidence_type="memory", provider=_provider(), overwrite=True
    )
    restored_evidence = restore_evidence(protected, restored, provider=_provider(), overwrite=True)

    assert restored.read_bytes() == data
    assert restored_evidence == evidence
    assert stat.S_IMODE(protected.stat().st_mode) == 0o600
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600


def test_ciphertext_hides_payload_and_sensitive_uri(tmp_path: Path) -> None:
    source = tmp_path / "secret.bin"
    protected = tmp_path / "secret.olympus"
    source.write_bytes(b"credential-canary-123")
    protect_evidence(
        source,
        protected,
        evidence_type="disk",
        uri="case://operator-sensitive-location",
        provider=_provider(),
    )
    ciphertext = protected.read_bytes()
    assert b"credential-canary" not in ciphertext
    assert b"operator-sensitive-location" not in ciphertext


def test_wrong_key_and_tampering_fail_before_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    protected = tmp_path / "protected"
    restored = tmp_path / "restored"
    source.write_bytes(b"evidence")
    protect_evidence(source, protected, evidence_type="pcap", provider=_provider())

    with pytest.raises(ProtectedEvidenceError, match="decryption failed"):
        restore_evidence(protected, restored, provider=_provider("x" * 32))
    assert not restored.exists()

    raw = bytearray(protected.read_bytes())
    raw[-10] ^= 1
    protected.write_bytes(raw)
    with pytest.raises(ProtectedEvidenceError):
        restore_evidence(protected, restored, provider=_provider())
    assert not restored.exists()


def test_missing_and_short_key_fail_closed() -> None:
    with pytest.raises(ProtectedEvidenceError, match="is required"):
        load_evidence_encryption_key(provider=EnvSecretProvider(environ={}))
    with pytest.raises(ProtectedEvidenceError, match="at least 32"):
        load_evidence_encryption_key(provider=_provider("short"))


def test_paths_reject_collision_symlink_and_same_file(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"content")
    with pytest.raises(ProtectedEvidenceError, match="different"):
        protect_evidence(source, source, evidence_type="pcap", provider=_provider())

    output = tmp_path / "output"
    output.write_bytes(b"keep")
    with pytest.raises(ValueError, match="overwrite"):
        protect_evidence(source, output, evidence_type="pcap", provider=_provider())
    assert output.read_bytes() == b"keep"

    link = tmp_path / "link"
    link.symlink_to(output)
    with pytest.raises(ValueError, match="symlink"):
        protect_evidence(source, link, evidence_type="pcap", provider=_provider())


def test_delete_source_requires_verified_package_and_writes_minimal_receipt(tmp_path: Path) -> None:
    source = tmp_path / "source"
    protected = tmp_path / "protected"
    receipt = tmp_path / "receipt.json"
    source.write_bytes(b"sensitive evidence")
    evidence = protect_evidence(
        source,
        protected,
        evidence_type="memory",
        provider=_provider(),
        delete_source=True,
        receipt_path=receipt,
    )
    assert not source.exists()
    loaded, content = load_protected_evidence(protected, provider=_provider())
    assert loaded == evidence and content == b"sensitive evidence"
    record = json.loads(receipt.read_text())
    assert record["evidence_sha256"] == evidence.sha256
    assert record["storage_erasure_guaranteed"] is False
    assert "sensitive evidence" not in receipt.read_text()
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600


def test_receipt_without_deletion_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"data")
    with pytest.raises(ProtectedEvidenceError, match="requires delete_source"):
        protect_evidence(
            source,
            tmp_path / "protected",
            evidence_type="memory",
            provider=_provider(),
            receipt_path=tmp_path / "receipt",
        )
    with pytest.raises(ProtectedEvidenceError, match="must be different"):
        protect_evidence(
            source,
            tmp_path / "protected",
            evidence_type="memory",
            provider=_provider(),
            delete_source=True,
            receipt_path=source,
            overwrite=True,
        )


def test_cli_protect_and_restore_without_secret_disclosure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(EVIDENCE_ENCRYPTION_KEY_ENV, _KEY)
    source = tmp_path / "source"
    protected = tmp_path / "protected"
    restored = tmp_path / "restored"
    source.write_bytes(b"cli evidence")
    result = runner.invoke(
        app, ["minerva", "protect", str(source), str(protected), "--type", "pcap"]
    )
    assert result.exit_code == 0, result.output
    assert _KEY not in result.output
    result = runner.invoke(app, ["minerva", "restore", str(protected), str(restored)])
    assert result.exit_code == 0, result.output
    assert restored.read_bytes() == b"cli evidence"
    assert _KEY not in result.output
