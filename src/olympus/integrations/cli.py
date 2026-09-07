"""Olympus CLI surface for specialist-engine integrations.

* ``olympus aegis`` owns native execution, capability readiness, durable jobs
  and an authenticated API. The older VAP web/worker commands remain a temporary
  compatibility boundary while their professional contracts migrate.
* ``olympus vap`` is a deprecated alias that forwards to ``olympus aegis``.

Heavy upstream dependencies are imported lazily; missing dependencies, services,
or external scanner binaries fail gracefully with actionable guidance and are
never reported as working.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import typer

from olympus.core.exit_codes import ExitCode
from olympus.core.paths import audit_log_path, state_file_path
from olympus.integrations import scanners as scanner_registry
from olympus.integrations.capabilities import count_at_least, inventory_document
from olympus.integrations.diagnostics import (
    Check,
    Report,
    check_binary,
    check_env_set,
    check_python_module,
    check_tcp,
    check_writable_dir,
)
from olympus.integrations.maturity import LADDER, Maturity, verify_declarations
from olympus.integrations.vendored import (
    VAP_DIR,
    VendoredToolNotFoundError,
    ensure_on_path,
    optional_tool_path,
    tool_path,
)


def _os_environ() -> dict[str, str]:
    import os

    return dict(os.environ)


# --------------------------------------------------------------------------- #
# AEGIS — native control plane with temporary VAP compatibility commands
# --------------------------------------------------------------------------- #
aegis_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="AEGIS — Olympus vulnerability-assessment & scanner-orchestration platform.",
)
jobs_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Durable native AEGIS job queue (SQLite, no Redis/Celery required).",
)
identities_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="API identities: scoped credentials with rotation, expiry and revocation.",
)
retention_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Retention and best-effort secure deletion of logs, artefacts and jobs.",
)
aegis_app.add_typer(jobs_app, name="jobs")
aegis_app.add_typer(identities_app, name="identities")
aegis_app.add_typer(retention_app, name="retention")

#: Credential hashes are deployment state, not a report: they follow the
#: state directory rather than the working directory.
DEFAULT_IDENTITY_REGISTER = str(state_file_path("aegis-api-identities.json"))

#: AEGIS writes this audit log whether or not the operator asked for it, so it
#: defaults to the per-user state directory rather than the working directory.
DEFAULT_AEGIS_AUDIT_LOG = str(audit_log_path("aegis-audit.ndjson"))


def _emit_report(report: Report) -> None:
    typer.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))


def _require_vendored(name: str) -> Path:
    """Return a vendored tool's root, or exit with the reason it is unavailable."""
    try:
        return tool_path(name)
    except VendoredToolNotFoundError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _vendor_check() -> Check:
    """Report whether the vendored upstream tree this command can use is present."""
    path = optional_tool_path(VAP_DIR)
    if path is None:
        return Check(
            f"vendor:{VAP_DIR}",
            False,
            "not installed: the vendored upstream source is not packaged in the wheel. "
            "Native AEGIS commands work without it; 'aegis serve|migrate|workers' need "
            "a checkout or OLYMPUS_VENDOR_DIR.",
            optional=True,
        )
    ensure_on_path(VAP_DIR)
    return Check(f"vendor:{VAP_DIR}", True, str(path), optional=True)


@aegis_app.command("api")
def aegis_api(
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
    scope_directory: str = typer.Option(".olympus/scopes", "--scope-directory"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8443, "--port", min=1, max=65_535),
    api_key_env: str = typer.Option("OLYMPUS_AEGIS_API_KEY", "--api-key-env"),
    identities: str = typer.Option(
        "", "--identities", help="Identity register with scoped, revocable credentials."
    ),
    audit: str = typer.Option(
        DEFAULT_AEGIS_AUDIT_LOG, "--audit", help="Redacted per-request audit log."
    ),
    ssl_certfile: str = typer.Option("", "--ssl-certfile"),
    ssl_keyfile: str = typer.Option("", "--ssl-keyfile"),
) -> None:
    """Serve the authenticated native AEGIS API.

    Non-loopback binds require both a TLS certificate and key. Credentials come
    from an identity register or a single environment variable, never from the
    command line.
    """
    import ipaddress
    import os
    from pathlib import Path

    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not loopback and not (ssl_certfile and ssl_keyfile):
        typer.echo(
            "olympus: non-loopback AEGIS API binds require TLS certificate and key",
            err=True,
        )
        raise typer.Exit(code=2)
    api_key = os.environ.get(api_key_env, "")
    if not api_key and not identities:
        typer.echo(
            f"olympus: set {api_key_env} or pass --identities with a credential register",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        import uvicorn

        from olympus.aegis.api import ApiSettings, create_app

        application = create_app(
            ApiSettings(
                database=Path(database),
                scope_directory=Path(scope_directory),
                api_key=api_key,
                identities_path=Path(identities) if identities else None,
                audit_path=Path(audit) if audit else None,
            )
        )
    except (ImportError, OSError, ValueError) as exc:
        typer.echo(
            f'olympus: native API unavailable: {exc}; install with pip install -e ".[api]"',
            err=True,
        )
        raise typer.Exit(code=2) from exc

    uvicorn.run(
        application,
        host=host,
        port=port,
        ssl_certfile=ssl_certfile or None,
        ssl_keyfile=ssl_keyfile or None,
        proxy_headers=False,
        server_header=False,
    )


@aegis_app.command("serve")
def aegis_serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for the web app."),
    port: int = typer.Option(8000, "--port", help="Port for the web app."),
    allow_legacy_web: bool = typer.Option(
        False,
        "--allow-legacy-web",
        help="Acknowledge that the legacy VAP web surface is temporary and local-only.",
    ),
) -> None:
    """Serve the quarantined legacy VAP web application on loopback only."""
    import ipaddress

    if not allow_legacy_web:
        typer.echo(
            "olympus: legacy VAP web is quarantined; use the authenticated native "
            "'olympus aegis api' service, or explicitly acknowledge local-only use with "
            "--allow-legacy-web",
            err=True,
        )
        raise typer.Exit(code=2)
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not loopback:
        typer.echo(
            "olympus: legacy VAP web may only bind to a loopback address; "
            "use 'olympus aegis api' for an authenticated network service",
            err=True,
        )
        raise typer.Exit(code=2)
    path = _require_vendored(VAP_DIR)
    env = {**_os_environ(), "VAP_HOST": host, "VAP_PORT": str(port)}
    typer.echo(
        f"olympus: starting quarantined legacy VAP web app on http://{host}:{port} "
        f"(from {path})",
        err=True,
    )
    completed = subprocess.run([sys.executable, "app.py"], cwd=str(path), env=env, check=False)
    raise typer.Exit(code=completed.returncode)


@aegis_app.command("migrate")
def aegis_migrate() -> None:
    """Run the AEGIS database migrations (alembic upgrade head)."""
    path = _require_vendored(VAP_DIR)
    completed = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(path),
        env=_os_environ(),
        check=False,
    )
    raise typer.Exit(code=completed.returncode)


@aegis_app.command("workers")
def aegis_workers(
    queue: str = typer.Option("scans", "--queue", help="Celery queue to consume."),
    loglevel: str = typer.Option("info", "--loglevel", help="Celery worker log level."),
) -> None:
    """Start an AEGIS Celery worker that runs queued scans (Ctrl-C to stop)."""
    path = _require_vendored(VAP_DIR)
    typer.echo(f"olympus: starting AEGIS Celery worker on queue '{queue}' (from {path})", err=True)
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["celery", "-A", "celery_app.celery_app", "worker", "-Q", queue, "--loglevel", loglevel],  # noqa: S607
        cwd=str(path),
        env=_os_environ(),
        check=False,
    )
    raise typer.Exit(code=completed.returncode)


@aegis_app.command("scanners")
def aegis_scanners(
    check: bool = typer.Option(
        False, "--check", help="Also report whether each scanner's binary is available."
    ),
) -> None:
    """List the complete AEGIS scanner catalogue (all 24 integrations)."""
    specs = scanner_registry.REGISTRY
    if not check:
        typer.echo(
            json.dumps(
                {"count": len(specs), "scanners": scanner_registry.names()},
                indent=2,
                sort_keys=True,
            )
        )
        return
    rows = [
        {
            "name": spec.name,
            "category": spec.category,
            "binary": spec.binary,
            "licence": spec.licence,
            "redistributable": spec.redistributable,
            "in_scanner_image": spec.in_scanner_image,
            "available": spec.available(),
            "install": spec.install,
        }
        for spec in sorted(specs, key=lambda s: s.name)
    ]
    available = sum(1 for r in rows if r["available"])
    typer.echo(
        json.dumps(
            {"count": len(rows), "available_binaries": available, "scanners": rows},
            indent=2,
            sort_keys=True,
        )
    )


@aegis_app.command("matrix")
def aegis_matrix(
    check: bool = typer.Option(
        False,
        "--check",
        help="Exit non-zero if docs/scanner-matrix.md differs from the generated output.",
    ),
    write: bool = typer.Option(
        False,
        "--write",
        help="Rewrite docs/scanner-matrix.md in place instead of printing it.",
    ),
) -> None:
    """Render the scanner matrix from the registry, or check/rewrite the doc.

    The catalogue, its licences, the derived native-adapter and live-verified
    columns, and the totals are all generated from
    ``olympus.integrations.scanners`` and the maturity ledger, so the document
    can never drift from the code. ``--check`` is the CI gate: it exits ``2``
    when the committed ``docs/scanner-matrix.md`` no longer matches.
    """
    from pathlib import Path

    from olympus.integrations import matrix

    rendered = matrix.render()
    doc_path = Path(__file__).resolve().parents[3] / "docs" / "scanner-matrix.md"

    if check:
        try:
            current = doc_path.read_text(encoding="utf-8")
        except OSError as exc:
            typer.echo(f"olympus: cannot read {doc_path}: {exc}", err=True)
            raise typer.Exit(code=int(ExitCode.USAGE)) from exc
        if current != rendered:
            typer.echo(
                "olympus: docs/scanner-matrix.md is stale; run "
                "'olympus aegis matrix --write'",
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.USAGE))
        typer.echo("olympus: scanner matrix is up to date", err=True)
        return

    if write:
        doc_path.write_text(rendered, encoding="utf-8")
        typer.echo(f"olympus: wrote {doc_path}", err=True)
        return

    typer.echo(rendered, nl=False)


@aegis_app.command("capabilities")
def aegis_capabilities(
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Exit non-zero when no scanner integration is ready for a live job.",
    ),
    min_maturity: str | None = typer.Option(
        None,
        "--min-maturity",
        help=(
            "Exit non-zero unless at least --count integrations reach this stage: "
            + " | ".join(stage.value for stage in LADDER)
        ),
    ),
    count: int = typer.Option(
        1,
        "--count",
        min=1,
        help="How many integrations must reach --min-maturity.",
    ),
) -> None:
    """Report what AEGIS can actually execute, and how far each engine is proven.

    Unlike ``scanners``, which is a product catalogue, this command distinguishes
    registered adapters, installed engines, configured APIs and live readiness —
    and reports each integration's **maturity**, so the catalogue never promises
    more than it executes. It never contacts a target.

    ``--min-maturity`` turns that into a CI gate: it fails the build when the
    project claims less validation than a release requires.
    """
    document = inventory_document()
    typer.echo(json.dumps(document, indent=2, sort_keys=True))

    # A drifted ledger is a reporting bug, not a readiness result: say so on
    # stderr and fail with a usage code rather than a readiness one.
    drift = verify_declarations()
    if drift:
        for problem in drift:
            typer.echo(f"olympus: maturity declaration drift: {problem}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))

    if min_maturity is not None:
        try:
            minimum = Maturity(min_maturity)
        except ValueError as exc:
            typer.echo(
                f"olympus: unknown maturity stage {min_maturity!r}; expected one of "
                + ", ".join(stage.value for stage in LADDER),
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.USAGE)) from exc
        reached = count_at_least(minimum)
        if reached < count:
            typer.echo(
                f"olympus: {reached} integration(s) reach {minimum.value}, "
                f"{count} required",
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.NOT_AUTHORIZED))

    if strict and document["ready"] == 0:
        raise typer.Exit(code=int(ExitCode.NOT_AUTHORIZED))


def _emit_job(job: object) -> None:
    from pydantic import BaseModel

    if not isinstance(job, BaseModel):
        raise TypeError("AEGIS job output must be a validated contract")
    typer.echo(job.model_dump_json(indent=2))


@jobs_app.command("init")
def aegis_jobs_init(
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Initialize the private native job database."""
    from pathlib import Path

    from olympus.aegis.jobs import AegisJobStore

    store = AegisJobStore(Path(database))
    store.initialize()
    typer.echo(json.dumps({"database": str(store.path), "initialized": True}, indent=2))


@jobs_app.command("submit")
def aegis_jobs_submit(
    scanner: str = typer.Argument(...),
    target: str = typer.Option(..., "--target"),
    kind: str = typer.Option("host", "--kind"),
    scope: str = typer.Option(..., "--scope"),
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
    idempotency_key: str | None = typer.Option(
        None,
        "--idempotency-key",
        help="Resubmitting the same key returns the existing job instead of queueing a second.",
    ),
    max_attempts: int = typer.Option(
        1, "--max-attempts", min=1, max=10, help="Execution attempts before the job is failed."
    ),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized"),
) -> None:
    """Persist one authorized scan job without executing it."""
    from pathlib import Path

    from olympus.aegis.jobs import AegisJobStore

    if not i_am_authorized:
        typer.echo("olympus: queued live work requires --i-am-authorized", err=True)
        raise typer.Exit(code=4)
    try:
        job = AegisJobStore(Path(database)).submit(
            scanner=scanner,
            target=target,
            target_kind=kind,
            scope_path=Path(scope),
            authorized=True,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )
    except ValueError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    _emit_job(job)


@jobs_app.command("list")
def aegis_jobs_list(
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
    state: str | None = typer.Option(None, "--state"),
    limit: int = typer.Option(100, "--limit", min=1, max=1_000),
) -> None:
    """List durable jobs, optionally filtered by lifecycle state."""
    from pathlib import Path

    from olympus.aegis.jobs import AegisJobStore, JobState

    try:
        selected = JobState(state) if state else None
    except ValueError as exc:
        typer.echo(f"olympus: invalid job state {state!r}", err=True)
        raise typer.Exit(code=2) from exc
    jobs = AegisJobStore(Path(database)).list(limit=limit, state=selected)
    typer.echo(
        json.dumps(
            {
                "schema_name": "olympus.aegis-job-list",
                "schema_version": "2.0.0",
                "count": len(jobs),
                "jobs": [job.model_dump(mode="json") for job in jobs],
            },
            indent=2,
            sort_keys=True,
        )
    )


@jobs_app.command("status")
def aegis_jobs_status(
    job_id: str = typer.Argument(...),
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Return one durable job and its normalized result when complete."""
    from pathlib import Path

    from olympus.aegis.jobs import AegisJobStore

    try:
        _emit_job(AegisJobStore(Path(database)).get(job_id))
    except KeyError as exc:
        typer.echo(f"olympus: {exc.args[0]}", err=True)
        raise typer.Exit(code=2) from exc


@jobs_app.command("cancel")
def aegis_jobs_cancel(
    job_id: str = typer.Argument(...),
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Cancel queued work or request cooperative cancellation of running work."""
    from pathlib import Path

    from olympus.aegis.jobs import AegisJobStore

    try:
        _emit_job(AegisJobStore(Path(database)).cancel(job_id))
    except KeyError as exc:
        typer.echo(f"olympus: {exc.args[0]}", err=True)
        raise typer.Exit(code=2) from exc


@jobs_app.command("work")
def aegis_jobs_work(
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
    audit: str = typer.Option(".olympus/aegis-audit.ndjson", "--audit"),
    worker_id: str | None = typer.Option(
        None, "--worker-id", help="Stable identity for this worker's leases."
    ),
) -> None:
    """Claim and execute at most one job; safe for cron/systemd/container loops."""
    from pathlib import Path

    from olympus.aegis.jobs import AegisJobStore, AegisWorker, generate_worker_id

    store = AegisJobStore(Path(database))
    try:
        worker = AegisWorker(store, worker_id=worker_id or generate_worker_id())
    except ValueError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    job = worker.run_next(audit_path=Path(audit))
    if job is None:
        typer.echo(json.dumps({"claimed": False, "reason": "queue-empty"}, indent=2))
        return
    _emit_job(job)
    # A refused, broken or timed-out job is not a successful worker run.
    if job.state.value in {"failed", "timed_out", "policy_denied"}:
        raise typer.Exit(code=4)


@jobs_app.command("prune")
def aegis_jobs_prune(
    older_than_days: int = typer.Option(
        30, "--older-than-days", min=0, max=3_650, help="Keep finished jobs for this long."
    ),
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report what would be deleted."),
) -> None:
    """Delete finished jobs past the retention window; queued/running work is kept."""
    from pathlib import Path

    from olympus.aegis.jobs import AegisJobStore

    count, job_ids = AegisJobStore(Path(database)).prune(
        older_than_days=older_than_days, dry_run=dry_run
    )
    typer.echo(
        json.dumps(
            {
                "pruned": count,
                "job_ids": list(job_ids),
                "older_than_days": older_than_days,
                "dry_run": dry_run,
            },
            indent=2,
            sort_keys=True,
        )
    )


@jobs_app.command("recover")
def aegis_jobs_recover(
    database: str = typer.Option(".olympus/aegis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Requeue (or fail) jobs whose worker stopped renewing its lease."""
    from pathlib import Path

    from olympus.aegis.jobs import AegisJobStore

    recovered = AegisJobStore(Path(database)).recover_expired_leases()
    typer.echo(
        json.dumps(
            {
                "recovered": len(recovered),
                "jobs": [job.model_dump(mode="json") for job in recovered],
            },
            indent=2,
            sort_keys=True,
            default=str,
        )
    )


def _identity_register(path: str, *, create: bool = False) -> object:
    from pathlib import Path

    from olympus.aegis.identity import IdentityRegister, load_register

    location = Path(path)
    if not location.exists():
        if create:
            return IdentityRegister()
        typer.echo(f"olympus: identity register not found: {location}", err=True)
        raise typer.Exit(code=2)
    return load_register(location)


@identities_app.command("init")
def aegis_identities_init(
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
) -> None:
    """Create an empty identity register (owner-only)."""
    from pathlib import Path

    from olympus.aegis.identity import IdentityRegister, save_register

    location = Path(register_path)
    if location.exists():
        typer.echo(f"olympus: identity register already exists: {location}", err=True)
        raise typer.Exit(code=2)
    save_register(location, IdentityRegister())
    typer.echo(json.dumps({"register": str(location), "identities": 0}, indent=2))


@identities_app.command("add")
def aegis_identities_add(
    identity_id: str = typer.Argument(..., help="Identity name, e.g. 'ops-console'."),
    scopes: str = typer.Option(
        "jobs:read", "--scopes", help="Comma-separated scopes granted to this identity."
    ),
    rate_limit: int = typer.Option(120, "--rate-limit", min=1, max=100_000),
    expires_in_days: int = typer.Option(
        0, "--expires-in-days", min=0, max=3_650, help="0 keeps the credential open-ended."
    ),
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
) -> None:
    """Add one scoped identity and print its secret exactly once."""
    from pathlib import Path

    from olympus.aegis.identity import IdentityError, add_identity, save_register

    register = _identity_register(register_path, create=True)
    try:
        updated, secret = add_identity(
            register,  # type: ignore[arg-type]
            identity_id=identity_id,
            scopes=[item.strip() for item in scopes.split(",") if item.strip()],
            rate_limit_per_minute=rate_limit,
            expires_in_days=expires_in_days or None,
        )
    except IdentityError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    save_register(Path(register_path), updated)
    _emit_secret(identity_id, secret, "created")


@identities_app.command("rotate")
def aegis_identities_rotate(
    identity_id: str = typer.Argument(...),
    overlap_seconds: int = typer.Option(
        300,
        "--overlap-seconds",
        min=0,
        max=604_800,
        help="How long the previous secret keeps working; 0 revokes it immediately.",
    ),
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
) -> None:
    """Issue a new secret, keeping the old one valid for a bounded overlap."""
    from pathlib import Path

    from olympus.aegis.identity import IdentityError, rotate_identity, save_register

    try:
        updated, secret = rotate_identity(
            _identity_register(register_path),  # type: ignore[arg-type]
            identity_id,
            overlap_seconds=overlap_seconds,
        )
    except IdentityError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    save_register(Path(register_path), updated)
    _emit_secret(identity_id, secret, "rotated")


@identities_app.command("revoke")
def aegis_identities_revoke(
    identity_id: str = typer.Argument(...),
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
) -> None:
    """Revoke an identity immediately, including any secret still rotating."""
    from pathlib import Path

    from olympus.aegis.identity import IdentityError, revoke_identity, save_register

    try:
        updated = revoke_identity(
            _identity_register(register_path), identity_id  # type: ignore[arg-type]
        )
    except IdentityError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    save_register(Path(register_path), updated)
    typer.echo(json.dumps({"identity_id": identity_id, "revoked": True}, indent=2))


@identities_app.command("list")
def aegis_identities_list(
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
) -> None:
    """List identities, their scopes and status. Secrets are never stored."""
    register = _identity_register(register_path)
    identities = register.public_view()  # type: ignore[attr-defined]
    typer.echo(
        json.dumps({"count": len(identities), "identities": identities}, indent=2, sort_keys=True)
    )


def _emit_secret(identity_id: str, secret: str, action: str) -> None:
    """Print a credential once; only its SHA-256 is written to the register."""
    typer.echo(
        json.dumps(
            {
                "identity_id": identity_id,
                "action": action,
                "secret": secret,
                "notice": "store this secret now: only its hash is kept on disk",
            },
            indent=2,
        )
    )


@retention_app.command("prune")
def aegis_retention_prune(
    directory: str = typer.Argument(..., help="Directory of artefacts to bound."),
    pattern: str = typer.Option("*", "--pattern", help="Filename glob within that directory."),
    older_than_days: int | None = typer.Option(
        None, "--older-than-days", min=0, max=3_650, help="Delete artefacts older than this."
    ),
    max_files: int | None = typer.Option(
        None, "--max-files", min=0, max=10_000, help="Keep at most this many, oldest deleted."
    ),
    max_bytes: int | None = typer.Option(
        None, "--max-bytes", min=0, help="Keep at most this many bytes, oldest deleted."
    ),
    insecure: bool = typer.Option(
        False, "--no-overwrite", help="Unlink without overwriting the contents first."
    ),
    dry_run: bool = typer.Option(False, "--dry-run"),
) -> None:
    """Enforce an age/count/size budget over an artefact directory."""
    from pathlib import Path

    from olympus.core.retention import RetentionError, RetentionPolicy, prune_paths

    try:
        report = prune_paths(
            Path(directory),
            policy=RetentionPolicy(
                max_age_days=older_than_days,
                max_files=max_files,
                max_total_bytes=max_bytes,
                secure=not insecure,
            ),
            pattern=pattern,
            dry_run=dry_run,
        )
    except RetentionError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))


@retention_app.command("rotate-log")
def aegis_retention_rotate_log(
    path: str = typer.Argument(..., help="Append-only log to roll over."),
    max_bytes: int = typer.Option(50_000_000, "--max-bytes", min=1),
    keep: int = typer.Option(5, "--keep", min=0, max=100, help="Generations to retain."),
    insecure: bool = typer.Option(False, "--no-overwrite"),
) -> None:
    """Roll an audit log once it passes a size budget, securely dropping the oldest."""
    from pathlib import Path

    from olympus.core.retention import RetentionError, rotate_log

    try:
        report = rotate_log(
            Path(path), max_bytes=max_bytes, keep=keep, secure=not insecure
        )
    except RetentionError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))


@aegis_app.command("deps")
def aegis_deps() -> None:
    """Report AEGIS runtime dependencies: web stack, services, and scanner binaries."""
    report = Report("aegis deps")
    report.add(_vendor_check())
    for module in ("fastapi", "uvicorn", "sqlalchemy", "alembic", "celery", "redis"):
        report.add(check_python_module(module, optional=True))
    for spec in scanner_registry.REGISTRY:
        if spec.binary:
            report.add(check_binary(spec.binary, optional=True))
    _emit_report(report)


@aegis_app.command("info")
def aegis_info() -> None:
    """Show where AEGIS lives and whether its stack is importable."""
    import importlib.util

    path = optional_tool_path(VAP_DIR)
    if path is not None:
        ensure_on_path(VAP_DIR)
    importable = importlib.util.find_spec("fastapi") is not None
    binaries = sum(1 for s in scanner_registry.REGISTRY if s.available())
    payload = {
        "name": "AEGIS (vendored Vulnerability Assessment Platform)",
        "path": str(path) if path is not None else None,
        "vendored_source_present": path is not None,
        "scanners": len(scanner_registry.REGISTRY),
        "scanner_binaries_available": binaries,
        "web_stack_importable": importable,
        "install_hint": 'pip install -e ".[aegis]"  (or vendor installer.sh / docker compose)',
        "docker_compose": "docker-compose.yml (services: redis, migrate, app, worker)",
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@aegis_app.command("scan")
def aegis_scan(
    target: str = typer.Option(..., "--target", help="Authorized target to scan."),
    scanner: str = typer.Option(..., "--scanner", help="Ready specialist engine."),
    scope_id: str = typer.Option(..., "--scope-id", help="Server-registered scope identifier."),
    kind: str = typer.Option("host", "--kind", help="Target kind: host, domain or url."),
    base_url: str = typer.Option(
        "http://127.0.0.1:8443", "--url", help="Base URL of the native AEGIS API."
    ),
    api_key_env: str = typer.Option("OLYMPUS_AEGIS_API_KEY", "--api-key-env"),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized"),
) -> None:
    """Submit authorized work to the native AEGIS API."""
    import ipaddress
    import os
    import urllib.error
    import urllib.request
    from urllib.parse import urlparse

    if not i_am_authorized:
        typer.echo("olympus: API scan submission requires --i-am-authorized", err=True)
        raise typer.Exit(code=4)
    api_key = os.environ.get(api_key_env, "")
    if not api_key:
        typer.echo(
            f"olympus: required API key environment variable is not set: {api_key_env}",
            err=True,
        )
        raise typer.Exit(code=2)
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        typer.echo("olympus: AEGIS API URL must be an absolute HTTP(S) URL", err=True)
        raise typer.Exit(code=2)
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname.lower() == "localhost"
    if parsed.scheme != "https" and not loopback:
        typer.echo("olympus: remote AEGIS API connections require HTTPS", err=True)
        raise typer.Exit(code=2)

    body: dict[str, object] = {
        "scanner": scanner,
        "target": target,
        "target_kind": kind,
        "scope_id": scope_id,
        "authorized": True,
    }
    request = urllib.request.Request(  # noqa: S310 - scheme is operator-provided base URL
        f"{base_url.rstrip('/')}/api/v1/jobs",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Olympus-API-Key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
            payload = response.read().decode("utf-8", "replace")
            typer.echo(payload)
    except urllib.error.HTTPError as exc:
        # The server rejected the request (e.g. auth/scope/schema) — surface it.
        detail = exc.read().decode("utf-8", "replace")
        typer.echo(f"olympus: AEGIS server returned {exc.code}: {detail}", err=True)
        raise typer.Exit(code=1) from exc
    except urllib.error.URLError as exc:
        typer.echo(
            f"olympus: could not reach an AEGIS server at {base_url} ({exc.reason}). "
            "Start it with: olympus aegis api",
            err=True,
        )
        raise typer.Exit(code=4) from exc


@aegis_app.command("doctor")
def aegis_doctor(
    scanner: str | None = typer.Option(
        None,
        "--scanner",
        help=(
            "Diagnose one scanner (binary/version/deps, adapter, maturity, readiness), "
            "or 'all' for every catalogued engine, instead of the runtime."
        ),
    ),
) -> None:
    """Diagnose the AEGIS runtime, or one scanner with ``--scanner``.

    Without ``--scanner`` this reports the whole runtime (web stack, DB dir,
    Redis, config). With ``--scanner <name>`` it reports that one engine: whether
    its binary is on PATH and at what version (or, for API engines, whether the
    endpoint and secret variables are set — names only), whether Olympus owns a
    native adapter, the project's maturity for it, and live-job readiness.
    ``--scanner all`` reports every catalogued engine. Exit code ``2`` for an
    unknown scanner name.
    """
    import os

    if scanner is not None:
        from olympus.integrations import scanner_doctor

        if scanner == "all":
            reports = scanner_doctor.all_scanner_reports()
            payload = {
                "title": "aegis doctor --scanner all",
                "ok": all(item.ok() for item in reports),
                "scanners": [item.to_dict() for item in reports],
            }
            typer.echo(json.dumps(payload, indent=2, sort_keys=True))
            return
        try:
            single = scanner_doctor.scanner_report(scanner)
        except KeyError:
            typer.echo(
                f"olympus: unknown scanner {scanner!r}; known: "
                + ", ".join(scanner_doctor.scanner_names()),
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.USAGE)) from None
        _emit_report(single)
        return

    report = Report("aegis doctor")
    report.add(_vendor_check())
    for module in ("fastapi", "uvicorn", "sqlalchemy", "alembic", "celery", "redis"):
        report.add(check_python_module(module, optional=True))
    # Redis reachability (parsed from the broker URL host/port, best effort).
    broker = os.environ.get("VAP_CELERY_BROKER_URL", "redis://localhost:6379/0")
    host, port = _redis_host_port(broker)
    report.add(check_tcp(host, port, name="service:redis", optional=True))
    report.add(check_writable_dir(os.environ.get("VAP_REPORTS_DIR", "reports"), optional=True))
    live = os.environ.get("VAP_ENABLE_LIVE_SCANS", "false").lower() == "true"
    live_detail = (
        "live scans ENABLED" if live else "live scans disabled (scanners run in simulated mode)"
    )
    report.add(report_flag("config:VAP_ENABLE_LIVE_SCANS", live, live_detail))
    for secret in ("VAP_API_KEY", "VAP_JWT_SECRET", "VAP_CSRF_SECRET"):
        report.add(check_env_set(secret, optional=True, secret=True))
    binaries = sum(1 for s in scanner_registry.REGISTRY if s.available())
    report.add(
        report_flag(
            "scanners:binaries_available",
            binaries > 0,
            f"{binaries}/{len(scanner_registry.REGISTRY)} scanner binaries on PATH",
        )
    )
    report.add(sandbox_check())
    _emit_report(report)


def sandbox_check() -> Check:
    """Report how confined scanner processes will be (see docs/aegis-sandbox.md)."""
    import os

    from olympus.aegis.sandbox import SandboxError, SandboxPolicy

    try:
        policy = SandboxPolicy.from_environment()
        identity = policy.resolve_identity()
    except SandboxError as exc:
        return Check("sandbox:isolation", False, str(exc), optional=True)
    privileged_parent = os.name == "posix" and os.geteuid() == 0
    if identity is not None:
        confined, detail = True, f"scanners drop to {identity.name} (uid {identity.uid})"
    elif privileged_parent:
        confined, detail = False, "AEGIS_SANDBOX_ALLOW_ROOT is set: scanners would run as ROOT"
    else:
        confined, detail = True, "parent process is already unprivileged"
    limits = ", ".join(f"{name}={value}" for name, value in sorted(policy.describe().items()))
    return Check("sandbox:isolation", confined, f"{detail}; limits {limits}", optional=True)


def _redis_host_port(url: str) -> tuple[str, int]:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return (parsed.hostname or "localhost", parsed.port or 6379)


def report_flag(name: str, ok: bool, detail: str) -> Check:
    """Build an optional diagnostics :class:`Check` for a boolean condition."""
    return Check(name, ok, detail, optional=True)


# --------------------------------------------------------------------------- #
# Deprecated ``olympus vap`` alias -> forwards to ``olympus aegis``
# --------------------------------------------------------------------------- #
def register_vap_shim(parent: typer.Typer) -> None:
    """Register a deprecated ``vap`` passthrough that forwards to ``aegis``.

    Planned removal: the ``vap`` alias will be removed in a future release. Use
    ``olympus aegis`` instead.
    """

    @parent.command(
        "vap",
        context_settings={
            "allow_extra_args": True,
            "ignore_unknown_options": True,
            "help_option_names": [],
        },
        help="[DEPRECATED] Alias for 'olympus aegis' — forwards all arguments.",
    )
    def _vap(ctx: typer.Context) -> None:
        from typer.main import get_command

        typer.echo(
            "olympus: 'olympus vap' is deprecated and will be removed in a future release; "
            "use 'olympus aegis' instead.",
            err=True,
        )
        command = get_command(aegis_app)
        try:
            command.main(args=list(ctx.args), prog_name="olympus aegis", standalone_mode=False)
        except SystemExit as exc:  # pragma: no cover - click may raise SystemExit
            raise typer.Exit(code=int(exc.code or 0)) from exc


# --------------------------------------------------------------------------- #
# Top-level ``olympus doctor``
# --------------------------------------------------------------------------- #
def register_doctor(parent: typer.Typer) -> None:
    """Register the ecosystem-wide ``olympus doctor`` diagnostic command."""

    @parent.command("doctor", help="Diagnose the Olympus environment (binaries, services, deps).")
    def _doctor() -> None:
        report = Report("olympus doctor")
        # Core Olympus deps.
        for module in ("pydantic", "typer", "rich", "dns", "phonenumbers"):
            report.add(check_python_module(module, optional=True))
        # Common external tooling.
        for binary in ("git", "docker", "redis-cli", "curl"):
            report.add(check_binary(binary, optional=True))
        # ARGUS + AEGIS stacks (importable?).
        report.add(check_python_module("requests", optional=True))
        report.add(check_python_module("fastapi", optional=True))
        # Scanner binary coverage.
        binaries = sum(1 for s in scanner_registry.REGISTRY if s.available())
        report.add(
            report_flag(
                "aegis:scanner_binaries",
                binaries > 0,
                f"{binaries}/{len(scanner_registry.REGISTRY)} scanner binaries on PATH",
            )
        )
        # Redis (default local).
        report.add(check_tcp("localhost", 6379, name="service:redis", optional=True))
        import tempfile

        report.add(check_writable_dir(tempfile.gettempdir(), optional=True))
        _emit_report(report)


@aegis_app.command("run")
def aegis_run(
    scanner: str = typer.Argument(..., help="Scanner name (see 'olympus aegis run --list')."),
    target: str = typer.Option("", "--target", help="Authorized target (host/url/domain)."),
    kind: str = typer.Option("host", "--kind", help="Target kind: host, url, or domain."),
    scope: str = typer.Option("", "--scope", help="Versioned AEGIS scope JSON file."),
    timeout: float = typer.Option(300.0, "--timeout", help="Per-process timeout in seconds."),
    deadline: float = typer.Option(600.0, "--deadline", help="Overall scan deadline in seconds."),
    max_scope_bytes: int = typer.Option(1_000_000, "--max-scope-bytes"),
    max_output_bytes: int = typer.Option(5_000_000, "--max-output-bytes"),
    max_findings: int = typer.Option(10_000, "--max-findings"),
    output: str = typer.Option("", "--output", help="Optional private versioned result JSON."),
    audit: str = typer.Option(
        DEFAULT_AEGIS_AUDIT_LOG, "--audit", help="Redacted structured audit log."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for a real scan."
    ),
    simulate: bool = typer.Option(
        False, "--simulate", help="Explicitly produce ILLUSTRATIVE output (never a real scan)."
    ),
    list_scanners: bool = typer.Option(
        False, "--list", help="List scanners with a native execution adapter and exit."
    ),
) -> None:
    """Run a real scanner with explicit execution states (never implicit simulation).

    States: live / unavailable / failed / disabled / simulation. Simulation is
    only ever produced with --simulate; a missing
    binary yields 'unavailable', and live-disabled yields 'disabled' — never
    fabricated findings.
    """
    from pathlib import Path

    from olympus.aegis import config as aegis_config
    from olympus.aegis.application import AegisApplicationService, AegisRunRequest
    from olympus.aegis.config import AegisConfigError
    from olympus.aegis.registry import UnknownScannerError, implemented
    from olympus.aegis.scope import (
        OutOfScopeError,
        SsrfBlockedError,
        TargetResolutionError,
        TargetValidationError,
    )
    from olympus.core.execution import AuthorizationRequiredError, CancellationRequested

    if list_scanners:
        typer.echo(json.dumps({"implemented": implemented()}, indent=2, sort_keys=True))
        return
    if not target:
        typer.echo("olympus: --target is required (or use --list)", err=True)
        raise typer.Exit(code=2)
    if not scope:
        typer.echo("olympus: --scope is required for every real or simulated target", err=True)
        raise typer.Exit(code=2)
    try:
        result = AegisApplicationService().run(
            AegisRunRequest(
                scanner=scanner,
                target=target,
                target_kind=kind,
                scope_path=Path(scope),
                authorized=i_am_authorized,
                live_enabled=aegis_config.live_enabled(),
                simulate=simulate,
                output_path=Path(output) if output else None,
                audit_path=Path(audit) if audit else None,
                timeout_seconds=timeout,
                deadline_seconds=deadline,
                max_scope_bytes=max_scope_bytes,
                max_output_bytes=max_output_bytes,
                max_findings=max_findings,
            )
        )
    except (OutOfScopeError, SsrfBlockedError) as exc:
        typer.echo(f"olympus: blocked, out of scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except (TargetResolutionError, TargetValidationError) as exc:
        typer.echo(f"olympus: invalid target: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except AuthorizationRequiredError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=4) from exc
    except UnknownScannerError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except (AegisConfigError, CancellationRequested, OSError, TimeoutError, ValueError) as exc:
        typer.echo(f"olympus: AEGIS execution error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    raise typer.Exit(code=_scan_exit_code(result))


def _scan_exit_code(result: object) -> int:
    from olympus.aegis.states import ExecutionState

    state = getattr(result, "state", None)
    findings = getattr(result, "findings", [])
    if state in {ExecutionState.FAILED, ExecutionState.UNAVAILABLE}:
        return 2
    if state is ExecutionState.DISABLED:
        return 4
    if state is ExecutionState.LIVE and findings:
        return 1
    return 0
