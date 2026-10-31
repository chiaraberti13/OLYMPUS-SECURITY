"""Unit tests for finding-bundle encryption at rest (ROADMAP ``SEC-E``).

Covers the shared key policy, the encrypt/decrypt helpers, the transparent
decrypt-on-load path shared by the CLI and Web UI, and the ``vulcan
encrypt-bundle`` / ``decrypt-bundle`` commands. Every error path is asserted to
be fail-closed: a missing key, a wrong key or a tampered ciphertext must raise
and write nothing, never yield partial or guessed plaintext.
"""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.core.secrets import EnvSecretProvider
from olympus.findings.encryption import (
    FINDINGS_ENCRYPTION_KEY_ENV,
    MIN_ENCRYPTION_KEY_LENGTH,
    FindingsEncryptionError,
    decrypt_findings_document,
    encrypt_findings_document,
    is_encryption_envelope,
    load_findings_encryption_key,
    looks_encrypted,
)
from olympus.vulcan.aggregate import AggregationError, load_findings

runner = CliRunner()

_KEY = "k" * MIN_ENCRYPTION_KEY_LENGTH
_WRONG = "w" * MIN_ENCRYPTION_KEY_LENGTH


def _provider(key: str | None = _KEY) -> EnvSecretProvider:
    environ = {FINDINGS_ENCRYPTION_KEY_ENV: key} if key is not None else {}
    return EnvSecretProvider(environ=environ)


def _bundle() -> str:
    # Fixed timestamps so repeated calls produce byte-identical bundles, letting a
    # round-trip assert exact plaintext equality rather than a looser shape match.
    moment = datetime(2026, 1, 1, tzinfo=UTC)
    finding = Finding(
        asset_id="AST-X",
        source=Source.THEMIS,
        title="example issue",
        description="d",
        severity=Severity.HIGH,
        finding_id="FND-2026-09001",
        first_seen=moment,
        last_seen=moment,
    )
    return json.dumps([finding.model_dump(mode="json")], indent=2)


# --- module helpers -------------------------------------------------------


def test_round_trip_returns_exact_plaintext() -> None:
    provider = _provider()
    envelope = encrypt_findings_document(_bundle(), provider=provider)
    assert is_encryption_envelope(json.loads(envelope))
    assert looks_encrypted(envelope)
    assert json.loads(decrypt_findings_document(envelope, provider=provider)) == json.loads(
        _bundle()
    )


def test_ciphertext_is_not_plaintext() -> None:
    envelope = encrypt_findings_document(_bundle(), provider=_provider())
    assert "example issue" not in envelope  # the title must not leak into the envelope


def test_encrypt_without_key_is_fail_closed() -> None:
    with pytest.raises(FindingsEncryptionError, match=FINDINGS_ENCRYPTION_KEY_ENV):
        encrypt_findings_document(_bundle(), provider=_provider(key=None))


def test_decrypt_without_key_is_fail_closed() -> None:
    envelope = encrypt_findings_document(_bundle(), provider=_provider())
    with pytest.raises(FindingsEncryptionError, match=FINDINGS_ENCRYPTION_KEY_ENV):
        decrypt_findings_document(envelope, provider=_provider(key=None))


def test_decrypt_with_wrong_key_is_fail_closed() -> None:
    envelope = encrypt_findings_document(_bundle(), provider=_provider())
    with pytest.raises(FindingsEncryptionError, match="wrong key or corrupted"):
        decrypt_findings_document(envelope, provider=_provider(key=_WRONG))


def test_decrypt_rejects_tampered_ciphertext() -> None:
    envelope = encrypt_findings_document(_bundle(), provider=_provider())
    tampered = envelope.replace('"ciphertext": "', '"ciphertext": "A')
    with pytest.raises(FindingsEncryptionError):
        decrypt_findings_document(tampered, provider=_provider())


def test_decrypt_enforces_max_bytes() -> None:
    envelope = encrypt_findings_document(_bundle(), provider=_provider())
    with pytest.raises(FindingsEncryptionError, match="exceeds the size limit"):
        decrypt_findings_document(envelope, provider=_provider(), max_bytes=4)


def test_short_key_is_rejected() -> None:
    short = "x" * (MIN_ENCRYPTION_KEY_LENGTH - 1)
    with pytest.raises(FindingsEncryptionError, match="at least"):
        load_findings_encryption_key(_provider(key=short))


def test_absent_key_resolves_to_none() -> None:
    assert load_findings_encryption_key(_provider(key=None)) is None


def test_plaintext_bundle_is_not_an_envelope() -> None:
    assert not looks_encrypted(_bundle())
    assert not is_encryption_envelope(json.loads(_bundle()))
    # a bundle whose own data mentions the scheme string is still not an envelope
    assert not is_encryption_envelope([{"scheme": "olympus.enc.v1"}])


def test_invalid_json_is_not_an_envelope() -> None:
    assert not looks_encrypted("{not json")


# --- transparent decrypt-on-load (shared by CLI and Web UI) ---------------


def test_load_findings_transparently_decrypts(tmp_path: Path) -> None:
    provider = _provider()
    path = tmp_path / "bundle.json"
    path.write_text(encrypt_findings_document(_bundle(), provider=provider))
    loaded = load_findings([path], secrets=provider)
    assert [f.finding_id for f in loaded] == ["FND-2026-09001"]


def test_load_findings_reads_legacy_plaintext_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(_bundle())
    # No key configured at all: a plaintext bundle must still load.
    loaded = load_findings([path], secrets=_provider(key=None))
    assert [f.finding_id for f in loaded] == ["FND-2026-09001"]


def test_load_findings_without_key_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(encrypt_findings_document(_bundle(), provider=_provider()))
    with pytest.raises(AggregationError, match=FINDINGS_ENCRYPTION_KEY_ENV):
        load_findings([path], secrets=_provider(key=None))


def test_load_findings_with_wrong_key_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(encrypt_findings_document(_bundle(), provider=_provider()))
    with pytest.raises(AggregationError, match="wrong key or corrupted"):
        load_findings([path], secrets=_provider(key=_WRONG))


# --- CLI ------------------------------------------------------------------


def test_cli_encrypt_decrypt_round_trip(tmp_path: Path) -> None:
    env = {FINDINGS_ENCRYPTION_KEY_ENV: _KEY}
    plain = tmp_path / "plain.json"
    plain.write_text(_bundle())
    enc = tmp_path / "enc.json"
    back = tmp_path / "back.json"

    created = runner.invoke(
        app, ["vulcan", "encrypt-bundle", "-i", str(plain), "-o", str(enc)], env=env
    )
    assert created.exit_code == 0, created.output
    assert looks_encrypted(enc.read_text())
    assert stat.S_IMODE(enc.stat().st_mode) == 0o600

    restored = runner.invoke(
        app, ["vulcan", "decrypt-bundle", "-i", str(enc), "-o", str(back)], env=env
    )
    assert restored.exit_code == 0, restored.output
    assert json.loads(back.read_text()) == json.loads(_bundle())


def test_cli_encrypt_without_key_writes_nothing(tmp_path: Path) -> None:
    plain = tmp_path / "plain.json"
    plain.write_text(_bundle())
    out = tmp_path / "enc.json"
    result = runner.invoke(
        app, ["vulcan", "encrypt-bundle", "-i", str(plain), "-o", str(out)], env={}
    )
    assert result.exit_code == 2
    assert FINDINGS_ENCRYPTION_KEY_ENV in result.output
    assert not out.exists()


def test_cli_encrypt_rejects_non_json(tmp_path: Path) -> None:
    junk = tmp_path / "junk.json"
    junk.write_text("{not json")
    out = tmp_path / "enc.json"
    result = runner.invoke(
        app,
        ["vulcan", "encrypt-bundle", "-i", str(junk), "-o", str(out)],
        env={FINDINGS_ENCRYPTION_KEY_ENV: _KEY},
    )
    assert result.exit_code == 2
    assert not out.exists()


def test_cli_encrypt_rejects_already_encrypted(tmp_path: Path) -> None:
    env = {FINDINGS_ENCRYPTION_KEY_ENV: _KEY}
    enc = tmp_path / "enc.json"
    enc.write_text(encrypt_findings_document(_bundle(), provider=_provider()))
    out = tmp_path / "double.json"
    result = runner.invoke(
        app, ["vulcan", "encrypt-bundle", "-i", str(enc), "-o", str(out)], env=env
    )
    assert result.exit_code == 2
    assert "already an encryption envelope" in result.output
    assert not out.exists()


def test_cli_decrypt_rejects_plaintext(tmp_path: Path) -> None:
    plain = tmp_path / "plain.json"
    plain.write_text(_bundle())
    out = tmp_path / "x.json"
    result = runner.invoke(
        app,
        ["vulcan", "decrypt-bundle", "-i", str(plain), "-o", str(out)],
        env={FINDINGS_ENCRYPTION_KEY_ENV: _KEY},
    )
    assert result.exit_code == 2
    assert not out.exists()


def test_cli_decrypt_with_wrong_key_writes_nothing(tmp_path: Path) -> None:
    enc = tmp_path / "enc.json"
    enc.write_text(encrypt_findings_document(_bundle(), provider=_provider()))
    out = tmp_path / "back.json"
    result = runner.invoke(
        app,
        ["vulcan", "decrypt-bundle", "-i", str(enc), "-o", str(out)],
        env={FINDINGS_ENCRYPTION_KEY_ENV: _WRONG},
    )
    assert result.exit_code == 2
    assert not out.exists()
