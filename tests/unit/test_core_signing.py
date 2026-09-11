"""Ed25519 detached signatures for third-party verifiable provenance (core.signing).

A vetted-library wrapper (never hand-rolled). Tests cover the sign/verify
round-trip, that verification is PINNED to a trusted public key (an attacker
re-signing with their own key is rejected), tamper detection, and the CLI
keygen/sign/verify flow.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.signing import (
    SIGNATURE_SCHEME,
    SigningError,
    generate_keypair,
    sign,
    verify,
)

runner = CliRunner()


def test_sign_verify_round_trip() -> None:
    private_pem, public_pem = generate_keypair()
    data = b"custody ledger bytes"
    envelope = sign(data, private_pem)
    assert json.loads(envelope)["scheme"] == SIGNATURE_SCHEME
    assert verify(data, envelope, public_pem=public_pem) is True


def test_tampered_data_does_not_verify() -> None:
    private_pem, public_pem = generate_keypair()
    envelope = sign(b"original", private_pem)
    assert verify(b"tampered", envelope, public_pem=public_pem) is False


def test_verification_is_pinned_to_the_trusted_key() -> None:
    private_pem, _ = generate_keypair()
    _, other_public = generate_keypair()
    envelope = sign(b"data", private_pem)
    # A different trusted key must reject even a technically valid signature.
    with pytest.raises(SigningError, match="different key"):
        verify(b"data", envelope, public_pem=other_public)


def test_attacker_cannot_re_sign_under_the_trusted_identity() -> None:
    _, victim_public = generate_keypair()
    attacker_private, _ = generate_keypair()
    forged = sign(b"tampered", attacker_private)  # attacker signs with their own key
    with pytest.raises(SigningError, match="different key"):
        verify(b"tampered", forged, public_pem=victim_public)


def test_malformed_envelope_and_wrong_algorithm_are_rejected() -> None:
    _, public_pem = generate_keypair()
    with pytest.raises(SigningError, match="invalid signature envelope"):
        verify(b"x", "{not json", public_pem=public_pem)
    with pytest.raises(SigningError, match="not an Olympus signature envelope"):
        verify(b"x", json.dumps({"scheme": "nope"}), public_pem=public_pem)
    with pytest.raises(SigningError, match="unsupported signature algorithm"):
        verify(
            b"x",
            json.dumps({"scheme": SIGNATURE_SCHEME, "algorithm": "RSA", "public_key": public_pem}),
            public_pem=public_pem,
        )


def test_invalid_keys_are_rejected() -> None:
    with pytest.raises(SigningError, match="invalid Ed25519 private key"):
        sign(b"x", "not a pem")


# --- CLI ---------------------------------------------------------------------- #


def test_cli_keygen_sign_verify_flow(tmp_path: Path) -> None:
    private = tmp_path / "priv.pem"
    public = tmp_path / "pub.pem"
    keygen = runner.invoke(
        app, ["core", "keygen", "--private", str(private), "--public", str(public)]
    )
    assert keygen.exit_code == 0, keygen.output
    assert stat.S_IMODE(private.stat().st_mode) == 0o600

    artifact = tmp_path / "ledger.json"
    artifact.write_text('{"schema_name": "olympus.custody"}', encoding="utf-8")
    sig = tmp_path / "ledger.sig"
    signed = runner.invoke(
        app, ["core", "sign", str(artifact), "--key", str(private), "--output", str(sig)]
    )
    assert signed.exit_code == 0, signed.output
    assert stat.S_IMODE(sig.stat().st_mode) == 0o600

    ok = runner.invoke(
        app, ["core", "verify", str(artifact), str(sig), "--pubkey", str(public)]
    )
    assert ok.exit_code == 0
    assert "VALID" in ok.output


def test_cli_verify_detects_tampering_and_wrong_key(tmp_path: Path) -> None:
    private = tmp_path / "priv.pem"
    public = tmp_path / "pub.pem"
    runner.invoke(app, ["core", "keygen", "--private", str(private), "--public", str(public)])
    other_pub = tmp_path / "other.pem"
    other_priv = tmp_path / "other-priv.pem"
    runner.invoke(
        app, ["core", "keygen", "--private", str(other_priv), "--public", str(other_pub)]
    )

    artifact = tmp_path / "ledger.json"
    artifact.write_text("original", encoding="utf-8")
    sig = tmp_path / "ledger.sig"
    runner.invoke(app, ["core", "sign", str(artifact), "--key", str(private), "--output", str(sig)])

    artifact.write_text("tampered", encoding="utf-8")
    tampered = runner.invoke(
        app, ["core", "verify", str(artifact), str(sig), "--pubkey", str(public)]
    )
    assert tampered.exit_code == 1
    assert "INVALID" in tampered.output

    # A wrong trusted key is a usage error (exit 2), not a silent pass.
    artifact.write_text("original", encoding="utf-8")
    wrong_key = runner.invoke(
        app, ["core", "verify", str(artifact), str(sig), "--pubkey", str(other_pub)]
    )
    assert wrong_key.exit_code == 2
    assert "different key" in wrong_key.output
