"""``olympus engines`` - what engines Olympus drives, and whether they are really here."""

from __future__ import annotations

import json

import typer

from olympus.core.exit_codes import ExitCode
from olympus.core.output import OutputFormat, render_table
from olympus.engines.doctor import (
    EngineStatus,
    Environment,
    check_all,
    verdict,
)
from olympus.engines.loader import ManifestError, load_all
from olympus.engines.preflight import UnknownEngineError, preflight
from olympus.integrations.maturity import record_for
from olympus.integrations.scanners import by_name

app = typer.Typer(
    help="External scanner engines: pins, presence and install commands (no network, no target).",
    no_args_is_help=True,
)

_PROBE_TIMEOUT = 15.0
_PROBE_BYTES = 65_536


def system_environment() -> Environment:
    """The real host: PATH lookup and the sandboxed runner Themis uses for scanners."""
    from olympus.themis.runner import CommandError, CommandTimeout, run_command, which

    def probe(argv: list[str]) -> tuple[int, str]:
        try:
            output = run_command(argv, timeout=_PROBE_TIMEOUT, max_output_bytes=_PROBE_BYTES)
        except (CommandError, CommandTimeout, OSError) as exc:
            return -1, str(exc)
        return output.exit_code, (output.stdout + "\n" + output.stderr).strip()

    def git_head(directory: str) -> str | None:
        # safe.directory: the checkout belongs to root while the engine may run as another
        # user, and git refuses a checkout it considers foreign.
        code, text = probe(
            ["git", "-c", f"safe.directory={directory}", "-C", directory, "rev-parse", "HEAD"]
        )
        head = text.strip()
        return head if code == 0 and len(head) == 40 else None

    from olympus.themis.sandbox import SandboxError, SandboxPolicy

    try:
        memory = SandboxPolicy.from_environment().memory_bytes
    except (SandboxError, ValueError):
        memory = SandboxPolicy().memory_bytes
    return Environment(which=which, probe=probe, git_head=git_head, sandbox_memory_bytes=memory)


def _records(statuses: list[EngineStatus]) -> list[dict[str, object]]:
    return [status.to_dict() for status in statuses]


@app.command("list")
def engines_list(
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="table or json."
    ),
) -> None:
    """List every engine Olympus knows: maturity, pin, whether it must be present."""
    try:
        manifests = load_all()
    except ManifestError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    rows: list[dict[str, object]] = []
    for name, manifest in sorted(manifests.items()):
        engine = manifest.engine
        spec = by_name(name)
        rows.append(
            {
                "engine": name,
                "category": engine.category,
                "maturity": record_for(name).stage.value,
                "mandatory": engine.mandatory,
                "distribution": engine.distribution,
                "pinned_version": engine.pinned_version,
                "commit": engine.source.commit,
                "adapter": manifest.adapter is not None,
                "in_scanner_image": bool(spec and spec.in_scanner_image),
            }
        )
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(rows, indent=2, sort_keys=True))
        return
    columns = ["engine", "category", "maturity", "mandatory", "distribution", "pin", "adapter"]
    table = [
        [
            str(row["engine"]),
            str(row["category"]),
            str(row["maturity"]),
            "yes" if row["mandatory"] else "-",
            str(row["distribution"]),
            f"{row['pinned_version'] or '-'}"
            + (f" @ {str(row['commit'])[:7]}" if row["commit"] else ""),
            "yes" if row["adapter"] else "no",
        ]
        for row in rows
    ]
    typer.echo(render_table(columns, table, title=f"{len(rows)} engines"))


@app.command("doctor")
def engines_doctor(
    engine: list[str] = typer.Option([], "--engine", help="Check only this engine. Repeatable."),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Also require every engine the scanner image ships, not only the mandatory ones.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="table or json."
    ),
) -> None:
    """Check the host against the manifests; print the exact install command for any gap.

    Exit 0 when every mandatory engine is present at its pin; 8 (engine missing) when one is
    not. With --strict the same applies to every engine the scanner image ships. Optional
    engines that are missing are reported but do not change the exit code.
    """
    try:
        statuses = check_all(system_environment(), tuple(engine))
    except KeyError as exc:
        typer.echo(f"olympus: unknown engine: {exc.args[0]}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    result = verdict(statuses, strict=strict)
    if output_format is OutputFormat.JSON:
        typer.echo(
            json.dumps(
                {
                    "engines": _records(statuses),
                    "blocking": list(result.blocking),
                    "optional_missing": list(result.optional_missing),
                    "exit_code": int(result.exit_code),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        rows = [
            [
                status.name,
                status.state.value,
                "yes" if status.mandatory else "-",
                status.detected_version or status.detail or "-",
            ]
            for status in statuses
        ]
        typer.echo(render_table(["engine", "state", "mandatory", "detail"], rows, title="engines"))
        for status in statuses:
            for note in status.notes:
                typer.echo(f"note: {status.name}: {note}", err=True)
            if status.name in result.blocking or (not status.ok and status.install_command):
                label = "REQUIRED" if status.name in result.blocking else "optional"
                typer.echo(f"{label}: {status.name}: {status.detail}", err=True)
                if status.install_command:
                    typer.echo(f"  install: {status.install_command}", err=True)
    raise typer.Exit(code=result.exit_code)


@app.command("preflight")
def engines_preflight(
    engine: list[str] = typer.Option(
        [], "--engine", help="Also require this engine (repeatable), beyond the mandatory set."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="table or json."
    ),
) -> None:
    """Fail-closed readiness gate for a planned scan (no network, no target).

    Checks that every engine the run needs — the mandatory engines (nmap, nuclei, httpx)
    plus any passed with --engine — is present at its pinned version. Exits 0 when all are
    ready, 8 (engine missing) when one is not, printing the exact install command for each
    gap. Meant to be run by an operator, or to gate CI/automation, before launching a scan.
    """
    try:
        verdict = preflight(system_environment(), engines=tuple(engine))
    except UnknownEngineError as exc:
        typer.echo(f"olympus: unknown engine: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    if output_format is OutputFormat.JSON:
        typer.echo(
            json.dumps(
                {
                    "required": list(verdict.required),
                    "blocking": [status.name for status in verdict.blocking],
                    "ready": verdict.ok,
                    "exit_code": int(verdict.exit_code),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        if verdict.ok:
            typer.echo(f"preflight OK: {len(verdict.required)} required engine(s) present.")
        else:
            typer.echo(
                f"preflight BLOCKED: {len(verdict.blocking)} of {len(verdict.required)} "
                "required engine(s) missing.",
                err=True,
            )
            for status in verdict.blocking:
                typer.echo(f"REQUIRED: {status.name}: {status.detail}", err=True)
                if status.install_command:
                    typer.echo(f"  install: {status.install_command}", err=True)
    raise typer.Exit(code=verdict.exit_code)
