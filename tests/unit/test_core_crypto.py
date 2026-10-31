"""Authenticated symmetric encryption primitive (core.crypto).

Fernet + scrypt via the vetted `cryptography` library — never hand-rolled. These
tests confirm round-trip, that authentication rejects a wrong passphrase and any
tampering, that output is non-deterministic (random salt), and the envelope
shape.
"""

from __future__ import annotations

import json

import pytest

from olympus.core.crypto import (
    ENCRYPTION_SCHEME,
    CryptoError,
    decrypt_to_bytes,
    decrypt_to_text,
    encrypt_bytes,
    encrypt_text,
)

_PASSPHRASE = "correct horse battery staple"  # noqa: S105 - test passphrase, not a secret


def test_text_round_trip() -> None:
    envelope = encrypt_text("sensitive CTI", _PASSPHRASE)
    assert decrypt_to_text(envelope, _PASSPHRASE) == "sensitive CTI"


def test_bytes_round_trip() -> None:
    data = bytes(range(256))
    envelope = encrypt_bytes(data, _PASSPHRASE)
    assert decrypt_to_bytes(envelope, _PASSPHRASE) == data


def test_envelope_is_self_describing_and_hides_plaintext() -> None:
    envelope = encrypt_text("TOPSECRETVALUE", _PASSPHRASE)
    document = json.loads(envelope)
    assert document["scheme"] == ENCRYPTION_SCHEME
    assert document["kdf"] == "scrypt"
    assert "salt" in document and "ciphertext" in document
    assert "TOPSECRETVALUE" not in envelope  # plaintext never present


def test_wrong_passphrase_is_rejected() -> None:
    envelope = encrypt_text("secret", _PASSPHRASE)
    with pytest.raises(CryptoError, match="wrong passphrase or corrupted"):
        decrypt_to_text(envelope, "not the passphrase")


def test_tampered_ciphertext_is_rejected() -> None:
    envelope = json.loads(encrypt_text("secret", _PASSPHRASE))
    envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"
    with pytest.raises(CryptoError):
        decrypt_to_text(json.dumps(envelope), _PASSPHRASE)


def test_non_envelope_and_empty_passphrase_are_rejected() -> None:
    with pytest.raises(CryptoError, match="not an Olympus encryption envelope"):
        decrypt_to_text(json.dumps({"nope": True}), _PASSPHRASE)
    with pytest.raises(CryptoError, match="invalid encryption envelope"):
        decrypt_to_text("{not json", _PASSPHRASE)
    with pytest.raises(CryptoError, match="must not be empty"):
        encrypt_text("x", "")


def test_encryption_is_non_deterministic() -> None:
    assert encrypt_text("x", _PASSPHRASE) != encrypt_text("x", _PASSPHRASE)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("n", 2**30, "invalid scrypt n"),  # memory bomb via huge n
        ("n", 40000, "invalid scrypt n"),  # not a power of two
        ("n", 0, "invalid scrypt n"),
        ("r", 64, "out-of-range KDF parameters"),  # huge r
        ("p", 999, "out-of-range KDF parameters"),  # huge p
    ],
)
def test_malicious_kdf_parameters_are_rejected_before_scrypt(
    field: str, value: int, match: str
) -> None:
    """A hostile envelope cannot turn decryption into a memory-exhaustion bomb."""
    envelope = json.loads(encrypt_text("secret", _PASSPHRASE))
    envelope[field] = value
    with pytest.raises(CryptoError, match=match):
        decrypt_to_text(json.dumps(envelope), _PASSPHRASE)
