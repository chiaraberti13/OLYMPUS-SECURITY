"""Command-line surface for METIS capability routing and CTI cases."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.core.crypto import (
    CryptoError,
    decrypt_to_bytes,
    decrypt_to_text,
    encrypt_bytes,
    encrypt_text,
)
from olympus.core.fileio import atomic_write_text, read_regular_text
from olympus.metis.cases import (
    BackupError,
    CaseStore,
    _indicator,
    export_report,
    restore_backup,
    verify_backup,
)
from olympus.metis.catalog import CAPABILITIES, recommend
from olympus.metis.labs import LABS
from olympus.metis.misp import MispError, event_to_indicators, indicators_to_event
from olympus.metis.models import IntelCaseDocument
from olympus.metis.planner import build_plan
from olympus.metis.stix import StixError, bundle_to_indicators, indicators_to_bundle

DEFAULT_MAX_STIX_BYTES = 50_000_000
#: Cap on an encrypted backup envelope read back for restore (base64 of a DB).
DEFAULT_MAX_ENCRYPTED_BACKUP_BYTES = 500_000_000
#: Passphrase for encrypting/decrypting sensitive CTI at rest (never stored).
METIS_KEY_ENV = "OLYMPUS_METIS_KEY"


def _metis_passphrase() -> str:
    passphrase = os.environ.get(METIS_KEY_ENV, "").strip()
    if not passphrase:
        raise ValueError(f"set {METIS_KEY_ENV} to a strong passphrase")
    return passphrase

app = typer.Typer(
    help="Deterministic planning, capability routing and CTI casework.", no_args_is_help=True
)
case_app = typer.Typer(help="Local-first cyber threat-intelligence cases.", no_args_is_help=True)


def _fail(exc: Exception) -> None:
    typer.echo(f"metis: {exc}", err=True)
    raise typer.Exit(code=2) from exc


@app.command("capabilities")
def capabilities(
    as_json: bool = typer.Option(False, "--json", help="Emit the strict catalog as JSON."),
) -> None:
    """List the independently implemented Olympus capability catalog."""
    if as_json:
        typer.echo(json.dumps([item.model_dump(mode="json") for item in CAPABILITIES], indent=2))
        return
    for item in CAPABILITIES:
        gate = "authorization" if item.requires_authorization else "ready"
        typer.echo(f"{item.capability_id:32} {item.mode.value:8} {gate:13} {item.title}")


@app.command("recommend")
def recommend_command(
    task: str = typer.Argument(..., help="Free-form security objective."),
    limit: int = typer.Option(5, min=1, max=20),
    advisory_only: bool = typer.Option(
        False, "--advisory-only", help="Exclude active-execution capabilities."
    ),
) -> None:
    """Route an objective to the best matching local capabilities."""
    try:
        results = recommend(task, limit=limit, include_active=not advisory_only)
    except ValueError as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            [
                {
                    "capability_id": item.capability.capability_id,
                    "title": item.capability.title,
                    "score": item.score,
                    "matched_terms": item.matched_terms,
                    "mode": item.capability.mode.value,
                    "noise": item.capability.noise.value,
                    "requires_authorization": item.capability.requires_authorization,
                    "commands": item.capability.commands,
                }
                for item in results
            ],
            indent=2,
        )
    )


@app.command("plan")
def plan_command(
    objective: str = typer.Argument(..., help="Security objective to plan."),
    scope: list[str] | None = typer.Option(
        None, "--scope", help="Authorized scope entry; repeatable."
    ),
    include_active: bool = typer.Option(False, help="Include active capabilities in the plan."),
    authorized: bool = typer.Option(
        False,
        "--i-am-authorized",
        help="Confirm documented authorization for the supplied scope.",
    ),
    output: Path | None = typer.Option(None, help="Owner-only JSON output path."),
) -> None:
    """Build a safe, non-executing engagement plan."""
    try:
        plan = build_plan(
            objective,
            scope=tuple(scope or ()),
            authorization_confirmed=authorized,
            include_active=include_active,
        )
    except (ValueError, AssertionError) as exc:
        _fail(exc)
    payload = plan.model_dump_json(indent=2) + "\n"
    if output is None:
        typer.echo(payload, nl=False)
    else:
        atomic_write_text(output, payload, mode=0o600)
        typer.echo(str(output))


@app.command("labs")
def labs_command(
    level: str | None = typer.Option(None, help="foundation, beginner, intermediate or advanced."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List safe guided labs built from native Olympus capabilities."""
    if level is not None and level not in {"foundation", "beginner", "intermediate", "advanced"}:
        _fail(ValueError("level must be foundation, beginner, intermediate, or advanced"))
    selected = [item for item in LABS if level is None or item.level == level]
    if as_json:
        typer.echo(json.dumps([item.__dict__ for item in selected], indent=2))
        return
    for item in selected:
        typer.echo(f"{item.lab_id:34} {item.level:12} {item.title}")


@case_app.command("init")
def case_init(database: Path = typer.Argument(..., help="SQLite case database.")) -> None:
    """Initialize or verify an owner-only case database."""
    try:
        with CaseStore(database):
            pass
    except (OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(str(database))


@case_app.command("create")
def case_create(
    database: Path = typer.Argument(...),
    title: str = typer.Argument(...),
) -> None:
    """Create a new CTI case and print its stable identifier."""
    try:
        with CaseStore(database) as store:
            case_id = store.create_case(title)
    except (ValueError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(case_id)


@case_app.command("ingest")
def case_ingest(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    evidence: Path = typer.Argument(...),
    source: str = typer.Option(..., help="Analyst-visible evidence provenance."),
    confidence: int = typer.Option(50, min=0, max=100),
) -> None:
    """Extract normalized indicators from one bounded local evidence file."""
    try:
        with CaseStore(database) as store:
            count = store.ingest_file(case_id, evidence, source=source, confidence=confidence)
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(json.dumps({"case_id": case_id, "inserted": count}))


@case_app.command("finding")
def case_finding(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    title: str = typer.Option(...),
    assessment: str = typer.Option(...),
    source: str = typer.Option(...),
    confidence: int = typer.Option(..., min=0, max=100),
    indicator: list[str] | None = typer.Option(
        None, "--indicator", help="Linked IOC ID; repeatable."
    ),
) -> None:
    """Record a sourced analytic finding and optional IOC links."""
    try:
        with CaseStore(database) as store:
            finding_id = store.add_finding(
                case_id,
                title=title,
                assessment=assessment,
                source=source,
                confidence=confidence,
                indicator_ids=tuple(indicator or ()),
            )
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(finding_id)


@case_app.command("show")
def case_show(database: Path = typer.Argument(...), case_id: str = typer.Argument(...)) -> None:
    """Print one strict, portable CTI case document."""
    try:
        with CaseStore(database) as store:
            document = store.load_case(case_id)
    except (LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(document.model_dump_json(indent=2))


@case_app.command("report")
def case_report(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    output: Path = typer.Argument(...),
    format: str = typer.Option("markdown", help="markdown or json."),
) -> None:
    """Export an owner-only CTI case report."""
    try:
        with CaseStore(database) as store:
            document = store.load_case(case_id)
        export_report(document, output, format=format)
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(str(output))


@case_app.command("stix-export")
def case_stix_export(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    output: Path = typer.Argument(..., help="STIX 2.1 bundle output path (owner-only)."),
) -> None:
    """Export a case's indicators as a deterministic STIX 2.1 bundle."""
    try:
        with CaseStore(database) as store:
            document = store.load_case(case_id)
        bundle = indicators_to_bundle(document.indicators)
        atomic_write_text(
            output, json.dumps(bundle, indent=2, sort_keys=True) + "\n", mode=0o600
        )
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(
        json.dumps({"case_id": case_id, "objects": len(bundle["objects"]), "output": str(output)})
    )


@case_app.command("stix-import")
def case_stix_import(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    bundle: Path = typer.Argument(..., help="STIX 2.1 bundle JSON to import."),
    source: str = typer.Option(..., help="Analyst-visible provenance for imported IOCs."),
    confidence: int = typer.Option(50, min=0, max=100),
    max_bytes: int = typer.Option(DEFAULT_MAX_STIX_BYTES, "--max-bytes"),
) -> None:
    """Import the faithful (simple-equality) IOCs from a STIX 2.1 bundle into a case.

    Compound or non-equality patterns cannot be represented as exact IOCs and are
    reported as skipped, never silently mangled.
    """
    try:
        parsed = bundle_to_indicators(
            read_regular_text(bundle, max_bytes=max_bytes, label="STIX bundle")
        )
        indicators = [
            _indicator(item.indicator_type, item.value, source, confidence)
            for item in parsed.indicators
        ]
        with CaseStore(database) as store:
            inserted = store.add_indicators(case_id, indicators)
    except (StixError, ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "case_id": case_id,
                "imported": len(parsed.indicators),
                "inserted": inserted,
                "skipped": len(parsed.skipped),
            }
        )
    )
    for item in parsed.skipped:
        typer.echo(f"metis: skipped {item.reason}: {item.pattern}", err=True)


@case_app.command("misp-export")
def case_misp_export(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    output: Path = typer.Argument(..., help="MISP event JSON output path (owner-only)."),
) -> None:
    """Export a case's indicators as a conservative (org-only) MISP event."""
    try:
        with CaseStore(database) as store:
            document = store.load_case(case_id)
        event = indicators_to_event(document.indicators, info=document.title)
        atomic_write_text(
            output, json.dumps(event, indent=2, sort_keys=True) + "\n", mode=0o600
        )
    except (ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "case_id": case_id,
                "attributes": len(event["Event"]["Attribute"]),
                "output": str(output),
            }
        )
    )


@case_app.command("misp-import")
def case_misp_import(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    event: Path = typer.Argument(..., help="MISP event JSON to import."),
    source: str = typer.Option(..., help="Analyst-visible provenance for imported IOCs."),
    confidence: int = typer.Option(50, min=0, max=100),
    max_bytes: int = typer.Option(DEFAULT_MAX_STIX_BYTES, "--max-bytes"),
) -> None:
    """Import the mappable IOCs from a MISP event into a case.

    MISP attribute types Olympus does not represent are reported as skipped,
    never guessed.
    """
    try:
        parsed = event_to_indicators(
            read_regular_text(event, max_bytes=max_bytes, label="MISP event")
        )
        indicators = [
            _indicator(item.indicator_type, item.value, source, confidence)
            for item in parsed.indicators
        ]
        with CaseStore(database) as store:
            inserted = store.add_indicators(case_id, indicators)
    except (MispError, ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "case_id": case_id,
                "imported": len(parsed.indicators),
                "inserted": inserted,
                "skipped": len(parsed.skipped),
            }
        )
    )
    for item in parsed.skipped:
        typer.echo(f"metis: skipped {item.misp_type} ({item.reason}): {item.value}", err=True)


@case_app.command("export-encrypted")
def case_export_encrypted(
    database: Path = typer.Argument(...),
    case_id: str = typer.Argument(...),
    output: Path = typer.Argument(..., help="Encrypted case document output (owner-only)."),
) -> None:
    """Export a case as an authenticated-encrypted document (sensitive CTI at rest).

    The whole case (indicators, findings, assessments) is encrypted under the
    ``OLYMPUS_METIS_KEY`` passphrase with Fernet + scrypt; decrypt it later with
    ``metis case decrypt``.
    """
    try:
        passphrase = _metis_passphrase()
        with CaseStore(database) as store:
            document = store.load_case(case_id)
        envelope = encrypt_text(document.model_dump_json(indent=2), passphrase)
        atomic_write_text(output, envelope, mode=0o600)
    except (CryptoError, ValueError, LookupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(json.dumps({"case_id": case_id, "encrypted": str(output)}))


@case_app.command("decrypt")
def case_decrypt(
    encrypted: Path = typer.Argument(..., help="Encrypted case document to decrypt."),
    output: Path = typer.Argument(..., help="Decrypted JSON output (owner-only)."),
    max_bytes: int = typer.Option(DEFAULT_MAX_STIX_BYTES, "--max-bytes"),
) -> None:
    """Decrypt a case document produced by ``export-encrypted`` back to JSON.

    Verifies the case document parses; a wrong ``OLYMPUS_METIS_KEY`` or any
    tampering fails loudly (the ciphertext is authenticated).
    """
    try:
        passphrase = _metis_passphrase()
        plaintext = decrypt_to_text(
            read_regular_text(encrypted, max_bytes=max_bytes, label="encrypted case"), passphrase
        )
        document = IntelCaseDocument.model_validate_json(plaintext)
        atomic_write_text(output, document.model_dump_json(indent=2) + "\n", mode=0o600)
    except (CryptoError, ValidationError, ValueError, OSError) as exc:
        _fail(exc)
    typer.echo(json.dumps({"case_id": document.case_id, "decrypted": str(output)}))


@case_app.command("backup")
def case_backup(
    database: Path = typer.Argument(..., help="Live SQLite case database."),
    output: Path = typer.Argument(..., help="Owner-only snapshot destination."),
    encrypt: bool = typer.Option(
        False, "--encrypt", help="Encrypt the snapshot under OLYMPUS_METIS_KEY (authenticated)."
    ),
) -> None:
    """Write a consistent owner-only snapshot of the whole case store.

    With ``--encrypt`` the consistent snapshot is taken to a private temp file and
    then written out encrypted (Fernet + scrypt) under ``OLYMPUS_METIS_KEY`` — a
    safe offsite backup. ``restore`` auto-detects and decrypts it.
    """
    try:
        if encrypt:
            passphrase = _metis_passphrase()
            with tempfile.TemporaryDirectory() as scratch:
                snapshot = Path(scratch) / "snapshot.db"
                with CaseStore(database) as store:
                    store.backup(snapshot)
                envelope = encrypt_bytes(snapshot.read_bytes(), passphrase)
            atomic_write_text(output, envelope, mode=0o600)
            written = output.resolve()
        else:
            with CaseStore(database) as store:
                written = store.backup(output)
    except (CryptoError, ValueError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(str(written))


@case_app.command("verify-backup")
def case_verify_backup(
    backup: Path = typer.Argument(..., help="Snapshot file to validate."),
) -> None:
    """Confirm a snapshot is a real METIS store and print its row counts."""
    try:
        counts = verify_backup(backup)
    except (BackupError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(json.dumps(counts, sort_keys=True))


@case_app.command("restore")
def case_restore(
    backup: Path = typer.Argument(..., help="Snapshot file to restore from (plain or encrypted)."),
    database: Path = typer.Argument(..., help="Destination database (contents replaced)."),
    max_bytes: int = typer.Option(DEFAULT_MAX_ENCRYPTED_BACKUP_BYTES, "--max-bytes"),
) -> None:
    """Restore a verified snapshot into a database, replacing its contents.

    An encrypted backup (an ``export``/``backup --encrypt`` envelope) is detected
    automatically and decrypted with ``OLYMPUS_METIS_KEY`` before verification; a
    wrong key or any tampering fails loudly.
    """
    try:
        if _is_encryption_envelope(backup):
            passphrase = _metis_passphrase()
            envelope = read_regular_text(backup, max_bytes=max_bytes, label="encrypted backup")
            data = decrypt_to_bytes(envelope, passphrase)
            with tempfile.TemporaryDirectory() as scratch:
                snapshot = Path(scratch) / "snapshot.db"
                snapshot.write_bytes(data)
                counts = restore_backup(snapshot, database)
        else:
            counts = restore_backup(backup, database)
    except (CryptoError, BackupError, ValueError, OSError, sqlite3.Error) as exc:
        _fail(exc)
    typer.echo(json.dumps({"database": str(database), **counts}, sort_keys=True))


def _is_encryption_envelope(path: Path) -> bool:
    """True if the file looks like a JSON encryption envelope, not a SQLite DB.

    SQLite databases begin with the bytes ``SQLite format 3\\x00``; the envelope
    is JSON starting with ``{``. Only a small prefix is read.
    """
    try:
        if path.is_symlink() or not path.is_file():
            return False
        with path.open("rb") as handle:
            prefix = handle.read(16).lstrip()
    except OSError:
        return False
    return prefix.startswith(b"{")


app.add_typer(case_app, name="case")
