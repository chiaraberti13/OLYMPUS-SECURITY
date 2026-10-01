"""Command-line interface for engagements (ROADMAP WEB-B).

The CLI holds no domain logic: it validates input, builds the shared
:class:`~olympus.core.models.Engagement` contract and persists it through the
same store every other interface will use. The engagement database lives in the
directory given by ``--storage``.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import ValidationError

from olympus.core.enums import EngagementStatus
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Engagement, EngagementScope
from olympus.engagements.store import EngagementStoreError, SqliteEngagementStore

app = typer.Typer(help="Engagements — the top-level assessment container.", no_args_is_help=True)

_DB_NAME = "engagements.db"


def _open_store(storage: Path) -> SqliteEngagementStore:
    return SqliteEngagementStore(storage / _DB_NAME)


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
        store.save(engagement)
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
