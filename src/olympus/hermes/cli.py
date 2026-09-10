"""Command-line interface for the Hermes secret scanner."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import typer

from olympus.core.contracts import ContractCompatibilityError
from olympus.core.execution import CancellationRequested, ExecutionPolicyError
from olympus.core.paths import output_path
from olympus.hermes.application import SecretScanRequest, SecretScanService
from olympus.hermes.sarif import write_sarif
from olympus.hermes.scanner import (
    DEFAULT_MAX_COMMITS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_HISTORY_BYTES,
    ScanLimitError,
    write_baseline,
)

app = typer.Typer(help="Hermes — secret and configuration scanner.", no_args_is_help=True)
DEFAULT_OUTPUT = output_path("hermes-results.sarif")


def _staged_files() -> list[Path]:
    """Return the added/copied/modified files staged in the current Git index."""
    git = shutil.which("git")
    if git is None:
        raise OSError("git executable not found")
    completed = subprocess.run(  # noqa: S603 - fixed executable and arguments
        [git, "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
        capture_output=True,
        check=True,
        timeout=30,
    )
    names = completed.stdout.decode("utf-8", errors="replace").split("\0")
    return [Path(name) for name in names if name]


@app.command()
def scan(
    paths: list[Path] = typer.Argument(...),
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output"),
    entropy_threshold: float = typer.Option(4.5, "--entropy-threshold", min=0.0, max=8.0),
    history: bool = typer.Option(False, "--history"),
    baseline: Path | None = typer.Option(
        None, "--baseline", help="JSON baseline of accepted fingerprints to ignore."
    ),
    allowlist: Path | None = typer.Option(
        None,
        "--allowlist",
        help="JSON allowlist of path globs / value regexes to suppress by shape.",
    ),
    write_baseline_path: Path | None = typer.Option(
        None, "--write-baseline", help="Write current findings' fingerprints as a baseline."
    ),
    timeout: float = typer.Option(30.0, "--timeout", help="Per-Git-process timeout in seconds."),
    deadline: float = typer.Option(600.0, "--deadline", help="Overall scan deadline in seconds."),
    max_file_bytes: int = typer.Option(DEFAULT_MAX_FILE_BYTES, "--max-file-bytes"),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
    max_history_bytes: int = typer.Option(DEFAULT_MAX_HISTORY_BYTES, "--max-history-bytes"),
    max_commits: int = typer.Option(DEFAULT_MAX_COMMITS, "--max-commits"),
) -> None:
    """Scan a path and optionally its Git history, emitting masked SARIF."""
    try:
        outcome = SecretScanService().run(
            SecretScanRequest(
                paths=tuple(paths),
                entropy_threshold=entropy_threshold,
                history=history,
                baseline_path=baseline,
                allowlist_path=allowlist,
                timeout_seconds=timeout,
                deadline_seconds=deadline,
                max_file_bytes=max_file_bytes,
                max_files=max_files,
                max_history_bytes=max_history_bytes,
                max_commits=max_commits,
                excluded_paths=tuple(
                    path
                    for path in (output, baseline, allowlist, write_baseline_path)
                    if path is not None
                ),
            )
        )
        findings = list(outcome.findings)
        if write_baseline_path is not None:
            write_baseline(findings, write_baseline_path)
        write_sarif(findings, output)
    except (
        CancellationRequested,
        ContractCompatibilityError,
        ExecutionPolicyError,
        OSError,
        ScanLimitError,
        subprocess.SubprocessError,
        TimeoutError,
        ValueError,
    ) as exc:
        typer.echo(f"hermes: scan error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if write_baseline_path is not None:
        typer.echo(
            f"hermes: wrote baseline ({len(findings)} fingerprint(s)) to {write_baseline_path}"
        )
    typer.echo(
        f"hermes: {len(findings)} potential secret(s) in {outcome.scanned_files} text file(s); "
        f"ignored {len(outcome.ignored_files)}; SARIF: {output}"
    )
    if outcome.partial_errors:
        for error in outcome.partial_errors:
            typer.echo(f"hermes: partial scan: {error.path}: {error.reason}", err=True)
        raise typer.Exit(code=2)
    if findings:
        raise typer.Exit(code=1)


@app.command("pre-commit")
def pre_commit(
    paths: list[Path] = typer.Argument(
        None, help="Files to scan; when omitted, the Git-staged files are scanned."
    ),
    entropy_threshold: float = typer.Option(4.5, "--entropy-threshold", min=0.0, max=8.0),
    baseline: Path | None = typer.Option(None, "--baseline"),
    allowlist: Path | None = typer.Option(None, "--allowlist"),
    max_file_bytes: int = typer.Option(DEFAULT_MAX_FILE_BYTES, "--max-file-bytes"),
    max_files: int = typer.Option(DEFAULT_MAX_FILES, "--max-files"),
) -> None:
    """Scan staged (or given) files and block the commit on any finding.

    A developer/CI guard: it prints masked findings to the console (no SARIF
    file), exits 0 when clean, 1 when a secret is found, and 2 on an error. With
    no path arguments it scans the current Git index, so it drops straight into a
    pre-commit hook or a CI step.
    """
    try:
        targets = list(paths) if paths else _staged_files()
        targets = [path for path in targets if path.is_file() and not path.is_symlink()]
        if not targets:
            typer.echo("hermes: no staged text files to scan", err=True)
            return
        outcome = SecretScanService().run(
            SecretScanRequest(
                paths=tuple(targets),
                entropy_threshold=entropy_threshold,
                history=False,
                baseline_path=baseline,
                allowlist_path=allowlist,
                max_file_bytes=max_file_bytes,
                max_files=max_files,
            )
        )
    except (
        CancellationRequested,
        ContractCompatibilityError,
        ExecutionPolicyError,
        OSError,
        ScanLimitError,
        subprocess.SubprocessError,
        TimeoutError,
        ValueError,
    ) as exc:
        typer.echo(f"hermes: pre-commit error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    for finding in outcome.findings:
        typer.echo(f"hermes: {finding.rule} in {finding.path}:{finding.line} ({finding.masked})")
    if outcome.partial_errors:
        for error in outcome.partial_errors:
            typer.echo(f"hermes: partial scan: {error.path}: {error.reason}", err=True)
        raise typer.Exit(code=2)
    if outcome.findings:
        typer.echo(
            f"hermes: {len(outcome.findings)} potential secret(s) found — commit blocked", err=True
        )
        raise typer.Exit(code=1)
    typer.echo(f"hermes: clean ({outcome.scanned_files} file(s) scanned)")
