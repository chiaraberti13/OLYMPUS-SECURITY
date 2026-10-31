"""Command-line interface for authorized Helios surface discovery."""

from __future__ import annotations

from pathlib import Path

import typer

from olympus.core.coverage import exit_code_for, summarize
from olympus.core.execution import (
    AuthorizationRequiredError,
    CancellationRequested,
    ExecutionPolicyError,
)
from olympus.core.exit_codes import ExitCode
from olympus.core.paths import audit_log_path, output_path
from olympus.helios.application import SurfaceScanRequest, SurfaceScanService
from olympus.helios.export import export_scan_result
from olympus.helios.scanner import SocketConnector
from olympus.helios.scope import OutOfScopeError, ScopeError

app = typer.Typer(help="Helios — authorized network attack-surface mapper.", no_args_is_help=True)
DEFAULT_SCOPE = Path("examples/input/helios-scope.json")
DEFAULT_LOG = audit_log_path("helios-blocked.log")
DEFAULT_OUTPUT = output_path("helios-findings.json")


@app.command()
def scan(
    target: str,
    ports: str = typer.Option("80,443", "--ports"),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope"),
    log: Path = typer.Option(DEFAULT_LOG, "--log"),
    asset_id: str = typer.Option(
        "AST-HELIOS-00001", "--asset-id", help="core.Asset id to attach findings to."
    ),
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output"),
    timeout: float = typer.Option(1.0, "--timeout", help="Per-port TCP connect timeout."),
    deadline: float | None = typer.Option(
        None, "--deadline", help="Overall budget for the whole scan, in seconds."
    ),
    concurrency: int = typer.Option(
        1, "--concurrency", help="How many ports to probe in parallel (1-64)."
    ),
    banner: bool = typer.Option(
        False,
        "--banner",
        help="Read (never send) the greeting of services that speak first, to identify them.",
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for this live scan."
    ),
) -> None:
    """Perform bounded TCP discovery only after scope authorization.

    Exits ``0`` when every port answered and nothing was found, ``1`` on
    findings, ``5`` when some ports could not be answered, and ``6`` when none
    could — a scan that lost coverage never reports as clean.
    """
    try:
        requested_ports = [int(port) for port in ports.split(",")]
        outcome = SurfaceScanService(SocketConnector(read_banner=banner)).run(
            SurfaceScanRequest(
                target=target,
                ports=tuple(requested_ports),
                scope_path=scope,
                audit_log_path=log,
                asset_id=asset_id,
                authorized=i_am_authorized,
                timeout_seconds=timeout,
                deadline_seconds=deadline,
                max_concurrency=concurrency,
            )
        )
    except AuthorizationRequiredError as exc:
        typer.echo("helios: explicit authorization confirmation is required", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    except ScopeError as exc:
        typer.echo(f"helios: scope error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    except OutOfScopeError as exc:
        typer.echo(f"helios: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=ExitCode.OUT_OF_SCOPE) from exc
    except CancellationRequested as exc:
        typer.echo("helios: scan cancelled", err=True)
        raise typer.Exit(code=ExitCode.CANCELLED) from exc
    except (ValueError, ExecutionPolicyError) as exc:
        typer.echo(f"helios: invalid scan request: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    export_scan_result(
        list(outcome.observations),
        list(outcome.findings),
        output,
        status=outcome.status,
        coverage=outcome.coverage,
    )
    typer.echo(
        f"helios: exported {len(outcome.observations)} observation(s) and "
        f"{len(outcome.findings)} finding(s) to {output}"
    )
    typer.echo(
        f"helios: {summarize(outcome.status, outcome.coverage, len(outcome.findings))}", err=True
    )
    raise typer.Exit(code=exit_code_for(outcome.status))
