"""``olympus engines`` - what engines Olympus drives, and whether they are really here."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.core.execution import safe_terminal_text
from olympus.core.exit_codes import ExitCode
from olympus.core.fileio import read_regular_text
from olympus.core.output import OutputFormat, render_table
from olympus.engines.commands import UnknownCommandError, require_known
from olympus.engines.doctor import (
    Environment,
    build_report,
    check_all,
    verdict,
)
from olympus.engines.listing import build_list_report
from olympus.engines.loader import ManifestError
from olympus.engines.preflight import UnknownEngineError, build_preflight_report, preflight

_MAX_PUBLIC_KEY_BYTES = 16 * 1024

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


@app.command("list")
def engines_list(
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="table or json."
    ),
) -> None:
    """List every engine Olympus knows: maturity, pin, whether it must be present."""
    try:
        report = build_list_report()
    except ManifestError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    columns = ["engine", "category", "maturity", "mandatory", "distribution", "pin", "adapter"]
    table = [
        [
            entry.engine,
            entry.category,
            entry.maturity,
            "yes" if entry.mandatory else "-",
            entry.distribution,
            f"{entry.pinned_version or '-'}" + (f" @ {entry.commit[:7]}" if entry.commit else ""),
            "yes" if entry.adapter else "no",
        ]
        for entry in report.engines
    ]
    typer.echo(render_table(columns, table, title=f"{len(report.engines)} engines"))


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
        statuses = check_all(system_environment(), tuple(engine), strict=strict)
    except KeyError as exc:
        typer.echo(f"olympus: unknown engine: {exc.args[0]}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    result = verdict(statuses, strict=strict)
    if output_format is OutputFormat.JSON:
        report = build_report(statuses, result)
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
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
    command: str | None = typer.Option(
        None,
        "--command",
        help="Also require every engine this command needs (e.g. 'themis.run'); unknown → exit 2.",
    ),
    allow_missing: bool = typer.Option(
        False,
        "--allow-missing-engines",
        help="Tolerate a missing OPTIONAL engine (degraded, exit 5); mandatory still blocks.",
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="table or json."
    ),
) -> None:
    """Fail-closed readiness gate for a planned scan (no network, no target).

    Checks that every engine the run needs — the mandatory engines (nmap, nuclei, httpx),
    any passed with --engine, and any an engine-launching --command requires via its
    manifest's ``required_for_commands`` — is present at its pinned version. Exits 0 when
    all are ready, 8 (engine missing) when one is not, printing the exact install command
    for each gap. With --allow-missing-engines a missing *optional* engine is tolerated as
    degraded (exit 5) instead of blocking; a mandatory engine always blocks (exit 8). Meant
    to be run by an operator, or to gate CI/automation, before a scan.
    """
    try:
        commands = (require_known(command),) if command is not None else ()
    except UnknownCommandError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    try:
        verdict = preflight(
            system_environment(),
            engines=tuple(engine),
            commands=commands,
            allow_missing=allow_missing,
        )
    except UnknownEngineError as exc:
        typer.echo(f"olympus: unknown engine: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    if output_format is OutputFormat.JSON:
        report = build_preflight_report(verdict)
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        if verdict.blocking:
            typer.echo(
                f"preflight BLOCKED: {len(verdict.blocking)} of {len(verdict.required)} "
                "required engine(s) not ready.",
                err=True,
            )
            for status in verdict.blocking:
                typer.echo(
                    f"REQUIRED: {status.name} ({status.state.value}): {status.detail}", err=True
                )
                if status.install_command:
                    typer.echo(f"  install: {status.install_command}", err=True)
        elif verdict.degraded:
            typer.echo(
                f"preflight DEGRADED: {len(verdict.degraded)} optional engine(s) not ready "
                "(tolerated via --allow-missing-engines).",
                err=True,
            )
            for status in verdict.degraded:
                typer.echo(
                    f"OPTIONAL: {status.name} ({status.state.value}): {status.detail}", err=True
                )
                if status.install_command:
                    typer.echo(f"  install: {status.install_command}", err=True)
        else:
            typer.echo(f"preflight OK: {len(verdict.required)} required engine(s) present.")
    raise typer.Exit(code=verdict.exit_code)


@app.command("verify-evidence")
def engines_verify_evidence(
    path: Path = typer.Argument(..., help="Signed engine-run evidence JSON to verify."),
    public_key: Path = typer.Option(
        ..., "--public-key", help="Pinned Ed25519 public key used to verify the signature."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="table or json."
    ),
) -> None:
    """Verify signed run evidence with the single pinned-key verifier.

    The detached ``PATH.sig`` envelope is never trusted by itself: its embedded
    key must match ``--public-key`` and the signature must cover the canonical
    evidence bytes. Missing, altered or differently-signed evidence fails
    closed with exit 6.
    """
    from olympus.engines.evidence import EvidenceError, verify_evidence

    try:
        trusted_public_key = read_regular_text(
            public_key,
            max_bytes=_MAX_PUBLIC_KEY_BYTES,
            label="evidence verification public key",
        )
        report = verify_evidence(path, public_pem=trusted_public_key)
    except (EvidenceError, OSError, ValueError) as exc:
        typer.echo(safe_terminal_text(f"olympus: evidence verification failed: {exc}"), err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
        return
    evidence = report.evidence
    typer.echo(
        render_table(
            ["valid", "run", "job", "engine", "state", "sha256"],
            [
                [
                    "yes",
                    evidence.run_id,
                    evidence.authorization.job_id or "-",
                    evidence.engine.name,
                    evidence.outcome.state,
                    report.evidence_sha256,
                ]
            ],
            title="signed engine-run evidence",
        )
    )
