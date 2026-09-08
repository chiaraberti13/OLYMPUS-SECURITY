"""Command-line presentation for bounded Minerva application workflows."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.core.contracts import ContractCompatibilityError
from olympus.core.evidence import DEFAULT_MAX_ARTIFACT_BYTES, capture_evidence
from olympus.core.execution import CancellationRequested, ExecutionPolicyError
from olympus.core.fileio import atomic_write_text, ensure_write_target
from olympus.core.output import OutputFormat, render
from olympus.core.paths import output_path
from olympus.minerva.application import (
    DEFAULT_MAX_EVIDENCE_BYTES,
    MinervaApplicationService,
    MinervaLedgerRequest,
    MinervaRecordRequest,
    MinervaTriageRequest,
)
from olympus.minerva.custody import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_LEDGER_BYTES,
    CustodyAction,
)
from olympus.minerva.triage import DEFAULT_MAX_ALERT_BYTES, DEFAULT_MAX_ALERTS, export_incident

app = typer.Typer(help="Minerva — incident response and DFIR.", no_args_is_help=True)
DEFAULT_LEDGER = output_path("minerva-custody.json")
DEFAULT_INCIDENT = output_path("minerva-incident.json")
_APPLICATION_ERRORS = (
    CancellationRequested,
    ContractCompatibilityError,
    ExecutionPolicyError,
    OSError,
    TimeoutError,
    ValueError,
)


@app.command()
def triage(
    alerts: Path,
    output: Path = typer.Option(DEFAULT_INCIDENT, "--output"),
    title: str = typer.Option(..., "--title"),
    owner: str | None = typer.Option(None, "--owner"),
    max_alert_bytes: int = typer.Option(DEFAULT_MAX_ALERT_BYTES, "--max-alert-bytes"),
    max_alerts: int = typer.Option(DEFAULT_MAX_ALERTS, "--max-alerts"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Create a stable Incident from one strict, bounded Apollo alert export."""
    try:
        incident = MinervaApplicationService().triage(
            MinervaTriageRequest(
                alerts_path=alerts,
                title=title,
                owner=owner,
                excluded_paths=(output,),
                max_alert_bytes=max_alert_bytes,
                max_alerts=max_alerts,
                deadline_seconds=deadline,
            )
        )
        export_incident(incident, output)
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"minerva: triage error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"minerva: incident {incident.incident_id} written to {output}")


@app.command()
def capture(
    artifact: Path,
    output: Path,
    evidence_type: str = typer.Option(..., "--type", help="e.g. memory-image, pcap, disk-image."),
    uri: str | None = typer.Option(
        None, "--uri", help="Provenance URI; defaults to the artifact's file:// path."
    ),
    max_bytes: int = typer.Option(DEFAULT_MAX_ARTIFACT_BYTES, "--max-bytes"),
    force: bool = typer.Option(
        False, "--force", help="Overwrite an existing evidence file (default: refuse)."
    ),
) -> None:
    """Hash a local artifact and write an evidence reference anchored to its bytes.

    The sha256 is computed from the artifact as it is captured — not supplied by
    hand — so the reference provably matches the material it points at. The
    destination is validated before writing (no symlink, no silent overwrite
    unless ``--force``).
    """
    try:
        evidence = capture_evidence(
            artifact, evidence_type=evidence_type, uri=uri, max_bytes=max_bytes
        )
        ensure_write_target(output, overwrite=force)
        payload = json.loads(evidence.model_dump_json())
        atomic_write_text(
            output,
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            mode=0o600,
            overwrite=force,
        )
    except (OSError, ValueError) as exc:
        typer.echo(f"minerva: capture error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"minerva: captured {evidence.evidence_id} "
        f"sha256={evidence.sha256} -> {output}"
    )


@app.command()
def record(
    evidence: Path,
    ledger: Path,
    actor: str = typer.Option(..., "--actor"),
    action: CustodyAction = typer.Option(..., "--action"),
    max_evidence_bytes: int = typer.Option(DEFAULT_MAX_EVIDENCE_BYTES, "--max-evidence-bytes"),
    max_ledger_bytes: int = typer.Option(DEFAULT_MAX_LEDGER_BYTES, "--max-ledger-bytes"),
    max_entries: int = typer.Option(DEFAULT_MAX_ENTRIES, "--max-entries"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Append an evidence-digest-anchored event after verifying the complete chain."""
    try:
        entry = MinervaApplicationService().record(
            MinervaRecordRequest(
                evidence_path=evidence,
                ledger_path=ledger,
                actor=actor,
                action=action,
                max_evidence_bytes=max_evidence_bytes,
                max_ledger_bytes=max_ledger_bytes,
                max_entries=max_entries,
                deadline_seconds=deadline,
            )
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"minerva: custody error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(
        f"minerva: recorded custody sequence {entry.sequence} "
        f"for {entry.evidence_id} sha256={entry.evidence_sha256}"
    )


@app.command()
def verify(
    ledger: Path,
    max_ledger_bytes: int = typer.Option(DEFAULT_MAX_LEDGER_BYTES, "--max-ledger-bytes"),
    max_entries: int = typer.Option(DEFAULT_MAX_ENTRIES, "--max-entries"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Verify every hash, digest, state and timestamp in an existing ledger."""
    try:
        outcome = MinervaApplicationService().inspect(
            MinervaLedgerRequest(ledger, max_ledger_bytes, max_entries, deadline)
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"minerva: custody integrity failure: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    qualifier = "evidence-anchored" if outcome.evidence_anchored else "legacy, not digest-anchored"
    typer.echo(
        f"minerva: custody {outcome.schema_version} verified "
        f"({len(outcome.entries)} entries; {qualifier})"
    )
    if not outcome.evidence_anchored:
        raise typer.Exit(code=1)


@app.command()
def timeline(
    ledger: Path,
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as table (human) or json (machine)."
    ),
    max_ledger_bytes: int = typer.Option(DEFAULT_MAX_LEDGER_BYTES, "--max-ledger-bytes"),
    max_entries: int = typer.Option(DEFAULT_MAX_ENTRIES, "--max-entries"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Print a verified custody timeline, including evidence digest provenance."""
    try:
        outcome = MinervaApplicationService().inspect(
            MinervaLedgerRequest(ledger, max_ledger_bytes, max_entries, deadline)
        )
    except _APPLICATION_ERRORS as exc:
        typer.echo(f"minerva: custody integrity failure: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    records: list[dict[str, object]] = [
        {
            "seq": entry.sequence,
            "occurred_at": entry.occurred_at.isoformat(),
            "action": entry.action.value,
            "actor": entry.actor,
            "evidence_id": entry.evidence_id,
            "evidence_sha256": getattr(entry, "evidence_sha256", None),
        }
        for entry in outcome.entries
    ]
    columns = ["seq", "occurred_at", "action", "actor", "evidence_id", "evidence_sha256"]
    typer.echo(
        render(records, columns, output_format, title=f"Custody timeline ({len(records)})")
    )
    if not outcome.evidence_anchored:
        typer.echo("minerva: legacy ledger has no evidence digest anchors", err=True)
        raise typer.Exit(code=1)
