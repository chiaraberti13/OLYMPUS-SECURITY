"""Command-line interface for Nemesis, the offline credential auditor."""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from pathlib import Path

import typer

from olympus.core.coverage import classify_run_status, exit_code_for
from olympus.core.execution import (
    AuthorizationRequiredError,
    ExecutionPolicy,
    ExecutionPolicyError,
    safe_terminal_text,
)
from olympus.core.exit_codes import ExitCode
from olympus.core.fileio import UnsafeWriteTarget, ensure_write_target
from olympus.core.output import OutputFormat, render_table
from olympus.nemesis.application import AuditRequest, run_audit
from olympus.nemesis.audit import PasswordPolicy, report_to_dict

app = typer.Typer(
    help="Nemesis — offline auditor of weak, default and reused credentials (no network).",
    no_args_is_help=True,
)


def _echo_safe(message: str, *, err: bool = False) -> None:
    typer.echo(safe_terminal_text(message), err=err)


def _write_owner_only(path: Path, payload: str) -> None:
    """Atomically write ``payload`` to ``path`` with owner-only (0600) permissions."""
    target = ensure_write_target(path)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(target)
        target.chmod(0o600)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


@app.command()
def audit(
    input_path: Path = typer.Argument(
        ..., help="Credentials to audit: NDJSON {account,secret} or 'account:secret' lines."
    ),
    wordlist: Path | None = typer.Option(
        None, "--wordlist", help="Local weak/default/breached-password list (one per line)."
    ),
    min_length: int = typer.Option(12, "--min-length", min=1, max=4096),
    max_length: int = typer.Option(128, "--max-length", min=1, max=4096),
    require_upper: bool = typer.Option(True, "--require-upper/--no-require-upper"),
    require_lower: bool = typer.Option(True, "--require-lower/--no-require-lower"),
    require_digit: bool = typer.Option(True, "--require-digit/--no-require-digit"),
    require_symbol: bool = typer.Option(True, "--require-symbol/--no-require-symbol"),
    min_entropy_bits: float = typer.Option(
        0.0, "--min-entropy-bits", min=0.0, max=1024.0, help="Estimated-bits floor (0 disables)."
    ),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="table or json."
    ),
    output: Path | None = typer.Option(
        None, "--output", help="Write the masked JSON report to this owner-only (0600) file."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm you are authorized to audit these credentials."
    ),
    approval_reference: str = typer.Option(
        "", "--approval-reference", help="Engagement/approval reference for the audit record."
    ),
) -> None:
    """Audit credentials offline for weak, default and reused secrets (secrets masked)."""
    try:
        policy = PasswordPolicy(
            min_length=min_length,
            max_length=max_length,
            require_uppercase=require_upper,
            require_lowercase=require_lower,
            require_digit=require_digit,
            require_symbol=require_symbol,
            min_entropy_bits=min_entropy_bits,
        )
        execution = ExecutionPolicy(
            authorized=i_am_authorized,
            approval_reference=approval_reference or None,
        )
        report = run_audit(
            AuditRequest(input_path=input_path, wordlist_path=wordlist, policy=policy),
            policy=execution,
        )
    except (
        AuthorizationRequiredError,
        ExecutionPolicyError,
        OSError,
        UnsafeWriteTarget,
        ValueError,
    ) as exc:
        _echo_safe(f"nemesis: audit error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    document = report_to_dict(report)
    if output is not None:
        try:
            _write_owner_only(output, json.dumps(document, indent=2, sort_keys=True) + "\n")
        except (OSError, UnsafeWriteTarget) as exc:
            _echo_safe(f"nemesis: cannot write report: {exc}", err=True)
            raise typer.Exit(code=ExitCode.USAGE) from exc

    if output_format is OutputFormat.JSON:
        typer.echo(json.dumps(document, indent=2, sort_keys=True))
    else:
        rows = [
            [
                f.account,
                f.masked_secret,
                "yes" if f.compliant else "no",
                ", ".join(w.value for w in f.weaknesses) or "-",
                f"{f.estimated_entropy_bits:g}",
            ]
            for f in report.findings
        ]
        _echo_safe(
            render_table(["account", "secret", "compliant", "weaknesses", "~entropy bits"], rows)
        )
        checked = "yes" if report.known_password_list_checked else "no (no --wordlist)"
        _echo_safe(
            f"nemesis: {report.audited} audited, {report.compliant} compliant, "
            f"{report.weak} weak, {report.reused_accounts} reused; known-password list: {checked}"
        )
    if report.weak:
        raise typer.Exit(code=exit_code_for(classify_run_status(report.weak)))
