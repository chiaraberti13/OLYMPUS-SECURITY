"""Command-line interface for engagements (ROADMAP WEB-B).

The CLI holds no domain logic: it validates input, builds the shared
:class:`~olympus.core.models.Engagement` contract and persists it through the
same store every other interface will use. The engagement database lives in the
directory given by ``--storage``.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.core.enums import EngagementStatus
from olympus.core.exit_codes import ExitCode
from olympus.core.fileio import atomic_write_text, read_regular_text
from olympus.core.models import Engagement, EngagementScope
from olympus.engagements.portable import (
    MAX_LINE_BYTES,
    EngagementPortabilityError,
    export_engagements,
    import_engagements,
)
from olympus.engagements.store import (
    ENGAGEMENTS_DB_NAME,
    EngagementBackupInfo,
    EngagementStoreError,
    SqliteEngagementStore,
)

#: Bound the import file so a hostile NDJSON cannot exhaust memory on read.
_MAX_IMPORT_BYTES = 64 * 1024 * 1024

app = typer.Typer(help="Engagements — the top-level assessment container.", no_args_is_help=True)


def _open_store(storage: Path) -> SqliteEngagementStore:
    return SqliteEngagementStore(storage / ENGAGEMENTS_DB_NAME)


def _summary(engagement: Engagement) -> dict[str, object]:
    return {
        "engagement_id": engagement.engagement_id,
        "name": engagement.name,
        "client": engagement.client,
        "status": engagement.status.value,
        "included": list(engagement.scope.included),
        "excluded": list(engagement.scope.excluded),
        "digest": engagement.digest(),
    }


def _backup_payload(info: EngagementBackupInfo) -> dict[str, object]:
    return {
        "schema_version": info.schema_version,
        "engagement_count": info.engagement_count,
        "manifest_revocation_count": info.manifest_revocation_count,
        "signed_manifest_count": info.signed_manifest_count,
        "size_bytes": info.size_bytes,
        "sha256": info.sha256,
    }


@app.command("backup")
def backup_command(
    storage: Path = typer.Option(..., "--storage", help="Directory holding engagements.db."),
    output: Path = typer.Option(..., "--output", help="Snapshot destination."),
) -> None:
    """Create an atomic, verified snapshot of engagements.db only."""
    store = _open_store(storage)
    try:
        info = store.backup(output)
    except (OSError, ValueError, sqlite3.Error) as exc:
        typer.echo(f"engagement: backup failed: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    finally:
        store.close()
    typer.echo(json.dumps(_backup_payload(info), indent=2, sort_keys=True))


@app.command("verify-backup")
def verify_backup_command(
    backup: Path = typer.Option(..., "--backup", help="Snapshot file to verify."),
) -> None:
    """Verify one engagements database snapshot."""
    try:
        info = SqliteEngagementStore.verify_backup(backup)
    except (OSError, ValueError, sqlite3.Error) as exc:
        typer.echo(f"engagement: backup verification failed: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    typer.echo(json.dumps(_backup_payload(info), indent=2, sort_keys=True))


@app.command("restore-backup")
def restore_backup_command(
    backup: Path = typer.Option(..., "--backup", help="Verified engagements snapshot."),
    storage: Path = typer.Option(..., "--storage", help="New empty storage directory."),
) -> None:
    """Restore to an absent engagements.db; stop services before switching config."""
    destination = storage / ENGAGEMENTS_DB_NAME
    try:
        info = SqliteEngagementStore.restore_backup(backup, destination)
    except (OSError, ValueError, sqlite3.Error) as exc:
        typer.echo(f"engagement: restore failed: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    typer.echo(json.dumps(_backup_payload(info), indent=2, sort_keys=True))


@app.command()
def create(
    name: str = typer.Option(..., "--name", help="Human-readable engagement name."),
    include: list[str] = typer.Option(
        ..., "--include", help="Authorized in-scope target (repeatable)."
    ),
    exclude: list[str] = typer.Option(
        [], "--exclude", help="Explicitly out-of-scope target (repeatable)."
    ),
    client: str = typer.Option("", "--client", help="Client or owner name."),
    authorization_reference: str = typer.Option(
        "", "--authorization-reference", help="Contract/approval id (never a secret)."
    ),
    status: EngagementStatus = typer.Option(
        EngagementStatus.ACTIVE, "--status", help="Engagement lifecycle status."
    ),
    storage: Path = typer.Option(..., "--storage", help="Directory for the engagements database."),
) -> None:
    """Create and persist a new engagement; print its id, scope and digest."""
    try:
        engagement = Engagement(
            name=name,
            client=client,
            status=status,
            scope=EngagementScope(included=tuple(include), excluded=tuple(exclude)),
            authorization_reference=authorization_reference,
        )
    except ValidationError as exc:
        typer.echo(f"engagement: invalid input: {exc.errors()[0]['msg']}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    store = _open_store(storage)
    try:
        # Allocate the id and insert atomically: new_id() restarts per process, so
        # the id is derived from stored state, and create_next() keeps the read and
        # the write in one transaction (with a bounded retry on the primary key) so
        # even concurrent `engagement create` runs get distinct ids with no loss.
        engagement = store.create_next(engagement)
    except EngagementStoreError as exc:
        typer.echo(f"engagement: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    finally:
        store.close()
    typer.echo(json.dumps(_summary(engagement), indent=2, sort_keys=True))


@app.command("list")
def list_engagements(
    storage: Path = typer.Option(..., "--storage", help="Directory for the engagements database."),
) -> None:
    """List every stored engagement (most recent first)."""
    store = _open_store(storage)
    try:
        engagements = store.list()
    except EngagementStoreError as exc:
        typer.echo(f"engagement: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    finally:
        store.close()
    typer.echo(json.dumps([_summary(item) for item in engagements], indent=2, sort_keys=True))


@app.command()
def show(
    engagement_id: str = typer.Argument(..., help="Engagement id to display."),
    storage: Path = typer.Option(..., "--storage", help="Directory for the engagements database."),
) -> None:
    """Print the full stored engagement document, or fail if it does not exist."""
    store = _open_store(storage)
    try:
        engagement = store.get(engagement_id)
    except EngagementStoreError as exc:
        typer.echo(f"engagement: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    finally:
        store.close()
    if engagement is None:
        typer.echo(f"engagement: not found: {engagement_id}", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    typer.echo(json.dumps(engagement.model_dump(mode="json"), indent=2, sort_keys=True))


@app.command("export")
def export_command(
    storage: Path = typer.Option(..., "--storage", help="Directory for the engagements database."),
    output: Path = typer.Option(..., "--output", "-o", help="NDJSON file to write."),
    engagement_id: list[str] = typer.Option(
        [], "--id", help="Export only this engagement id (repeatable); default: all."
    ),
) -> None:
    """Export engagements to portable, versioned NDJSON (one per line, sorted by id).

    The file is reimportable into another installation with ``engagement import``
    without loss. Selecting unknown ids fails loudly rather than exporting fewer.
    """
    store = _open_store(storage)
    try:
        if engagement_id:
            engagements = [store.require(eid) for eid in engagement_id]
        else:
            engagements = store.list()
    except EngagementStoreError as exc:
        typer.echo(f"engagement: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    finally:
        store.close()
    atomic_write_text(output, export_engagements(engagements), mode=0o600)
    typer.echo(
        json.dumps({"exported": len(engagements), "output": str(output)}, indent=2, sort_keys=True)
    )


@app.command("import")
def import_command(
    storage: Path = typer.Option(..., "--storage", help="Directory for the engagements database."),
    input_file: Path = typer.Option(..., "--input", "-i", help="NDJSON file to import."),
) -> None:
    """Import engagements from portable NDJSON into the store (upsert by id).

    Strict and all-or-nothing: the whole file is parsed and validated against the
    ``olympus.engagement`` contract before anything is written, so a malformed
    record imports nothing. Existing engagements with the same id are replaced.
    """
    try:
        text = read_regular_text(input_file, max_bytes=_MAX_IMPORT_BYTES, label="engagement import")
    except (OSError, ValueError) as exc:
        typer.echo(f"engagement: cannot read import file: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    try:
        engagements = import_engagements(text, max_line_bytes=MAX_LINE_BYTES)
    except EngagementPortabilityError as exc:
        typer.echo(f"engagement: invalid import: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    store = _open_store(storage)
    try:
        for engagement in engagements:
            store.save(engagement)
    finally:
        store.close()
    typer.echo(
        json.dumps(
            {"imported": len(engagements), "ids": sorted(e.engagement_id for e in engagements)},
            indent=2,
            sort_keys=True,
        )
    )
