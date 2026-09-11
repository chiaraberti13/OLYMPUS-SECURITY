"""Encrypted CTI case export/decrypt (§2 Metis — sensitive fields at rest).

Uses the vetted core.crypto primitive. These tests exercise the CLI round-trip
through a real case store and confirm the wrong key fails and plaintext never
touches disk in the encrypted file.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.metis.cli import METIS_KEY_ENV

runner = CliRunner()


def _seed_case(database: Path) -> str:
    created = runner.invoke(app, ["metis", "case", "create", str(database), "Sensitive case"])
    assert created.exit_code == 0, created.output
    case_id = created.stdout.strip()
    evidence = database.parent / "evidence.txt"
    evidence.write_text("beacon at evil.example 203.0.113.9", encoding="utf-8")
    ingested = runner.invoke(
        app,
        ["metis", "case", "ingest", str(database), case_id, str(evidence),
         "--source", "fixture", "--confidence", "70"],
    )
    assert ingested.exit_code == 0, ingested.output
    return case_id


def test_export_encrypted_then_decrypt_round_trips(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(METIS_KEY_ENV, "a strong operator passphrase")
    database = tmp_path / "cases.db"
    case_id = _seed_case(database)
    encrypted = tmp_path / "case.enc"
    decrypted = tmp_path / "case.json"

    exported = runner.invoke(
        app, ["metis", "case", "export-encrypted", str(database), case_id, str(encrypted)]
    )
    assert exported.exit_code == 0, exported.output
    # The sensitive indicator value must not appear in the encrypted artifact.
    assert "evil.example" not in encrypted.read_text(encoding="utf-8")
    import stat

    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600

    result = runner.invoke(app, ["metis", "case", "decrypt", str(encrypted), str(decrypted)])
    assert result.exit_code == 0, result.output
    document = json.loads(decrypted.read_text(encoding="utf-8"))
    assert document["case_id"] == case_id
    assert document["schema_name"] == "olympus.metis-case"
    assert "evil.example" in decrypted.read_text(encoding="utf-8")  # recovered in the clear


def test_decrypt_with_the_wrong_key_fails(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(METIS_KEY_ENV, "the right passphrase")
    database = tmp_path / "cases.db"
    case_id = _seed_case(database)
    encrypted = tmp_path / "case.enc"
    runner.invoke(
        app, ["metis", "case", "export-encrypted", str(database), case_id, str(encrypted)]
    )

    monkeypatch.setenv(METIS_KEY_ENV, "the WRONG passphrase")
    result = runner.invoke(
        app, ["metis", "case", "decrypt", str(encrypted), str(tmp_path / "out.json")]
    )
    assert result.exit_code == 2
    assert "wrong passphrase or corrupted" in result.output


def test_export_encrypted_requires_the_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(METIS_KEY_ENV, raising=False)
    database = tmp_path / "cases.db"
    case_id = _seed_case(database)
    result = runner.invoke(
        app, ["metis", "case", "export-encrypted", str(database), case_id, str(tmp_path / "x.enc")]
    )
    assert result.exit_code == 2
    assert METIS_KEY_ENV in result.output


# --- Encrypted backup / restore of the whole store --------------------------- #


def test_encrypted_backup_round_trips_and_hides_plaintext(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(METIS_KEY_ENV, "offsite backup passphrase")
    database = tmp_path / "cases.db"
    case_id = _seed_case(database)
    encrypted = tmp_path / "store.enc"

    backed = runner.invoke(
        app, ["metis", "case", "backup", str(database), str(encrypted), "--encrypt"]
    )
    assert backed.exit_code == 0, backed.output
    import stat

    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600
    assert "evil.example" not in encrypted.read_text(encoding="utf-8")

    restored = tmp_path / "restored.db"
    result = runner.invoke(app, ["metis", "case", "restore", str(encrypted), str(restored)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["cases"] == 1
    shown = runner.invoke(app, ["metis", "case", "show", str(restored), case_id])
    assert "evil.example" in shown.output


def test_plain_backup_still_restores_without_a_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(METIS_KEY_ENV, raising=False)
    database = tmp_path / "cases.db"
    case_id = _seed_case(database)
    plain = tmp_path / "store.db"
    assert runner.invoke(app, ["metis", "case", "backup", str(database), str(plain)]).exit_code == 0

    restored = tmp_path / "restored.db"
    result = runner.invoke(app, ["metis", "case", "restore", str(plain), str(restored)])
    assert result.exit_code == 0, result.output  # no key needed for a plain snapshot
    assert case_id in runner.invoke(app, ["metis", "case", "show", str(restored), case_id]).output


def test_encrypted_backup_restore_with_the_wrong_key_fails(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(METIS_KEY_ENV, "right key")
    database = tmp_path / "cases.db"
    _seed_case(database)
    encrypted = tmp_path / "store.enc"
    runner.invoke(app, ["metis", "case", "backup", str(database), str(encrypted), "--encrypt"])

    monkeypatch.setenv(METIS_KEY_ENV, "wrong key")
    result = runner.invoke(
        app, ["metis", "case", "restore", str(encrypted), str(tmp_path / "x.db")]
    )
    assert result.exit_code == 2
    assert "wrong passphrase or corrupted" in result.output
