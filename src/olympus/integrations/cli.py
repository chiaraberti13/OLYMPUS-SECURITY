"""Olympus CLI surface for specialist-engine integrations.

* ``olympus themis`` owns native execution, capability readiness, durable jobs,
  authenticated API/web services, schema migrations and workers.
* ``olympus vap`` is a deprecated alias that forwards to ``olympus themis``.

Optional web dependencies are imported lazily; missing dependencies, services,
or external scanner binaries fail gracefully with actionable guidance and are
never reported as working.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from olympus.core.coverage import RunStatus, classify_run_status, exit_code_for
from olympus.core.enums import Severity
from olympus.core.execution import safe_terminal_text
from olympus.core.exit_codes import ExitCode, normalize_exit_code
from olympus.core.paths import audit_log_path, state_file_path
from olympus.integrations import scanners as scanner_registry
from olympus.integrations.capabilities import count_at_least, inventory_document
from olympus.integrations.diagnostics import (
    Check,
    Report,
    check_binary,
    check_python_module,
    check_writable_dir,
)
from olympus.integrations.maturity import LADDER, Maturity, verify_declarations

if TYPE_CHECKING:
    from olympus.themis.identity import IdentityRegister
    from olympus.themis.jobs import ThemisJob


def _read_api_key(api_key_env: str) -> str:
    """Read the API key, falling back from the canonical name to the legacy one.

    The default env var was renamed ``OLYMPUS_AEGIS_API_KEY`` ->
    ``OLYMPUS_THEMIS_API_KEY`` (ROADMAP ``DEV-I``). When the caller keeps the new
    default and only the legacy variable is set, the legacy value is still used.
    """
    import os

    value = os.environ.get(api_key_env, "")
    if not value and api_key_env == "OLYMPUS_THEMIS_API_KEY":
        value = os.environ.get("OLYMPUS_AEGIS_API_KEY", "")
    return value


# --------------------------------------------------------------------------- #
# Themis — native control plane
# --------------------------------------------------------------------------- #
themis_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Themis — Olympus vulnerability-assessment & scanner-orchestration platform.",
)
jobs_app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Durable native Themis job queue (SQLite, no Redis/Celery required).",
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
themis_app.add_typer(jobs_app, name="jobs")
themis_app.add_typer(identities_app, name="identities")
themis_app.add_typer(retention_app, name="retention")

#: Credential hashes are deployment state, not a report: they follow the
#: state directory rather than the working directory.
DEFAULT_IDENTITY_REGISTER = str(state_file_path("themis-api-identities.json"))

#: Themis writes this audit log whether or not the operator asked for it, so it
#: defaults to the per-user state directory rather than the working directory.
DEFAULT_THEMIS_AUDIT_LOG = str(audit_log_path("themis-audit.ndjson"))


def _authorize_direct_live_run(
    *,
    signed_manifest_path: Path,
    trusted_public_key_path: Path,
    engagement_storage: Path,
    scanner: str,
    target: str,
    audit_path: Path | None,
) -> tuple[str, str]:
    """Authorize and retain provenance for a direct live scanner invocation."""
    import sqlite3
    from datetime import UTC, datetime
    from uuid import uuid4

    from olympus.core.execution import StructuredAuditRecord, append_structured_audit
    from olympus.core.fileio import read_regular_text
    from olympus.engagements.manifest import SignedEngagementManifest
    from olympus.engagements.store import (
        ENGAGEMENTS_DB_NAME,
        MAX_DOCUMENT_BYTES,
        SqliteEngagementStore,
    )

    job_id = f"THEMIS-{uuid4().hex.upper()}"
    digest: str | None = None
    store: SqliteEngagementStore | None = None
    try:
        signed = SignedEngagementManifest.model_validate_json(
            read_regular_text(
                signed_manifest_path,
                max_bytes=MAX_DOCUMENT_BYTES,
                label="signed engagement manifest",
            )
        )
        digest = signed.manifest_sha256
        trusted_public_key = read_regular_text(
            trusted_public_key_path,
            max_bytes=64 * 1024,
            label="manifest public key",
        )
        store = SqliteEngagementStore(engagement_storage / ENGAGEMENTS_DB_NAME)
        store.authorize_and_save_manifest(
            signed,
            trusted_public_key_pem=trusted_public_key,
            target=target,
            technique=scanner,
            now=datetime.now(UTC),
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        if audit_path is not None:
            metadata: dict[str, object] = {
                "job_id": job_id,
                "scanner": scanner,
                "error_type": type(exc).__name__,
            }
            if digest is not None:
                metadata["manifest_sha256"] = digest
            append_structured_audit(
                audit_path,
                StructuredAuditRecord(
                    timestamp=datetime.now(UTC).isoformat(),
                    execution_id=job_id,
                    action="themis.manifest-authorization",
                    outcome="refused",
                    target=target,
                    metadata=metadata,
                ),
            )
        raise
    finally:
        if store is not None:
            store.close()

    if digest is None:  # defensive: successful parsing always assigns the digest
        raise RuntimeError("signed-manifest authorization completed without a digest")
    if audit_path is not None:
        append_structured_audit(
            audit_path,
            StructuredAuditRecord(
                timestamp=datetime.now(UTC).isoformat(),
                execution_id=job_id,
                action="themis.manifest-authorization",
                outcome="authorized",
                target=target,
                metadata={
                    "job_id": job_id,
                    "manifest_sha256": digest,
                    "scanner": scanner,
                },
            ),
        )
    return job_id, digest


def _emit_report(report: Report) -> None:
    typer.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))


def _job_exit_code(job: object) -> ExitCode:
    """Reduce a Themis job state to the canonical process contract."""
    state = getattr(getattr(job, "state", None), "value", None)
    if state == "partial":
        return exit_code_for(RunStatus.PARTIAL)
    if state in {"failed", "timed_out"}:
        return exit_code_for(RunStatus.FAILED)
    if state == "cancelled":
        return exit_code_for(RunStatus.CANCELLED)
    if state == "policy_denied":
        return ExitCode.NOT_AUTHORIZED
    if state == "succeeded":
        result = getattr(job, "result", None)
        findings = result.get("finding_count", 0) if isinstance(result, dict) else 0
        count = findings if isinstance(findings, int) and not isinstance(findings, bool) else 0
        return exit_code_for(classify_run_status(count))
    return ExitCode.OK


@themis_app.command("api")
def themis_api(
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
    scope_directory: str = typer.Option(".olympus/scopes", "--scope-directory"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8443, "--port", min=1, max=65_535),
    max_concurrent_requests: int = typer.Option(64, "--max-concurrent-requests", min=1, max=4_096),
    api_key_env: str = typer.Option("OLYMPUS_THEMIS_API_KEY", "--api-key-env"),
    api_key_scopes: str = typer.Option(
        "capabilities:read",
        "--api-key-scopes",
        help="Comma-separated permissions for the shared API key (default: capabilities:read).",
    ),
    identities: str = typer.Option(
        "", "--identities", help="Identity register with scoped, revocable credentials."
    ),
    oidc_issuer: str = typer.Option("", "--oidc-issuer", help="Pinned HTTPS OIDC issuer."),
    oidc_audience: str = typer.Option("", "--oidc-audience", help="Required OIDC audience."),
    oidc_jwks: str = typer.Option(
        "", "--oidc-jwks", help="Pinned local JWKS file; discovery is disabled."
    ),
    audit: str = typer.Option(
        DEFAULT_THEMIS_AUDIT_LOG, "--audit", help="Redacted per-request audit log."
    ),
    engagement_storage: str = typer.Option(
        "",
        "--engagement-storage",
        help="Directory holding the shared engagements database; enables the "
        "engagement read endpoints and engagement-derived scope enforcement.",
    ),
    manifest_public_key: str = typer.Option(
        "",
        "--manifest-public-key",
        help="Pinned Ed25519 approver public key; requires --engagement-storage and "
        "signed manifests on API job submissions.",
    ),
    ssl_certfile: str = typer.Option("", "--ssl-certfile"),
    ssl_keyfile: str = typer.Option("", "--ssl-keyfile"),
) -> None:
    """Serve the authenticated native Themis API.

    Non-loopback binds require both a TLS certificate and key. Credentials come
    from an identity register or a single environment variable, never from the
    command line.
    """
    import ipaddress
    from pathlib import Path

    from olympus.core.fileio import read_regular_text
    from olympus.engagements.store import ENGAGEMENTS_DB_NAME

    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not loopback and not (ssl_certfile and ssl_keyfile):
        typer.echo(
            "olympus: non-loopback Themis API binds require TLS certificate and key",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)
    api_key = _read_api_key(api_key_env)
    if not api_key and not identities:
        typer.echo(
            f"olympus: set {api_key_env} or pass --identities with a credential register",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)

    try:
        import uvicorn

        from olympus.themis.api import ApiSettings, create_app

        application = create_app(
            ApiSettings(
                database=Path(database),
                scope_directory=Path(scope_directory),
                api_key=api_key,
                api_key_scopes=tuple(
                    scope.strip() for scope in api_key_scopes.split(",") if scope.strip()
                ),
                identities_path=Path(identities) if identities else None,
                oidc_issuer=oidc_issuer or None,
                oidc_audience=oidc_audience or None,
                oidc_jwks_path=Path(oidc_jwks) if oidc_jwks else None,
                audit_path=Path(audit) if audit else None,
                engagements_database=(
                    Path(engagement_storage) / ENGAGEMENTS_DB_NAME if engagement_storage else None
                ),
                trusted_manifest_public_key_pem=(
                    read_regular_text(
                        Path(manifest_public_key),
                        max_bytes=64 * 1024,
                        label="manifest public key",
                    )
                    if manifest_public_key
                    else None
                ),
                max_concurrent_requests=max_concurrent_requests,
            )
        )
    except (ImportError, OSError, ValueError) as exc:
        typer.echo(
            f'olympus: native API unavailable: {exc}; install with pip install -e ".[api]"',
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE) from exc

    uvicorn.run(
        application,
        host=host,
        port=port,
        ssl_certfile=ssl_certfile or None,
        ssl_keyfile=ssl_keyfile or None,
        proxy_headers=False,
        server_header=False,
    )


@themis_app.command("serve")
@themis_app.command("web")
def themis_web(
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
    scope_directory: str = typer.Option(".olympus/scopes", "--scope-directory"),
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8600, "--port", min=1, max=65_535),
    max_concurrent_requests: int = typer.Option(64, "--max-concurrent-requests", min=1, max=4_096),
    api_key_env: str = typer.Option("OLYMPUS_THEMIS_API_KEY", "--api-key-env"),
    api_key_scopes: str = typer.Option(
        "capabilities:read",
        "--api-key-scopes",
        help="Comma-separated permissions for the shared API key (default: capabilities:read).",
    ),
    identities: str = typer.Option(
        "", "--identities", help="Identity register with scoped, revocable credentials."
    ),
    oidc_issuer: str = typer.Option("", "--oidc-issuer", help="Pinned HTTPS OIDC issuer."),
    oidc_audience: str = typer.Option("", "--oidc-audience", help="Required OIDC audience."),
    oidc_jwks: str = typer.Option(
        "", "--oidc-jwks", help="Pinned local JWKS file; discovery is disabled."
    ),
    audit: str = typer.Option(
        DEFAULT_THEMIS_AUDIT_LOG, "--audit", help="Redacted per-request audit log."
    ),
    engagement_storage: str = typer.Option(
        "",
        "--engagement-storage",
        help="Directory holding the shared engagements database; enables the "
        "engagement pages and engagement-derived scope enforcement.",
    ),
    manifest_public_key: str = typer.Option(
        "",
        "--manifest-public-key",
        help="Pinned Ed25519 approver public key; requires --engagement-storage and "
        "makes every Web job require a signed manifest.",
    ),
    findings_directory: str = typer.Option(
        "",
        "--findings-directory",
        help="Directory of core.Finding JSON bundles to review in the browser; "
        "enables the Findings pages (read-only producer artifacts).",
    ),
    findings_storage: str = typer.Option(
        "",
        "--findings-storage",
        help="Append-only SQLite finding-lifecycle store; enables recording "
        "triage decisions (status transitions) from the browser.",
    ),
    baseline_directory: str = typer.Option(
        "",
        "--baseline-directory",
        help="Directory of core.Finding JSON bundles from an earlier run; enables "
        "the Scan diff page (new/resolved/persistent vs the current findings).",
    ),
    incidents_directory: str = typer.Option(
        "",
        "--incidents-directory",
        help="Directory of core.Incident JSON documents (olympus minerva triage "
        "output); enables the dashboard incidents-by-status widget for an "
        "incidents:read identity (read-only producer artifacts).",
    ),
    ssl_certfile: str = typer.Option("", "--ssl-certfile"),
    ssl_keyfile: str = typer.Option("", "--ssl-keyfile"),
) -> None:
    """Serve the native Themis web control plane (browser UI over the same core).

    A browser-driven job is run through the identical scope gate, authorization
    check, sandbox and redacted audit trail as the CLI. Non-loopback binds
    require both a TLS certificate and key; credentials come from an identity
    register or a single environment variable, never from the command line.
    """
    import ipaddress
    from pathlib import Path

    from olympus.core.fileio import read_regular_text
    from olympus.engagements.store import ENGAGEMENTS_DB_NAME

    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == "localhost"
    if not loopback and not (ssl_certfile and ssl_keyfile):
        typer.echo(
            "olympus: non-loopback Themis web binds require TLS certificate and key",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)
    api_key = _read_api_key(api_key_env)
    if not api_key and not identities:
        typer.echo(
            f"olympus: set {api_key_env} or pass --identities with a credential register",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)

    try:
        import uvicorn

        from olympus.themis.api import ApiSettings
        from olympus.themis.web import create_web_app

        application = create_web_app(
            ApiSettings(
                database=Path(database),
                scope_directory=Path(scope_directory),
                api_key=api_key,
                api_key_scopes=tuple(
                    scope.strip() for scope in api_key_scopes.split(",") if scope.strip()
                ),
                identities_path=Path(identities) if identities else None,
                oidc_issuer=oidc_issuer or None,
                oidc_audience=oidc_audience or None,
                oidc_jwks_path=Path(oidc_jwks) if oidc_jwks else None,
                audit_path=Path(audit) if audit else None,
                engagements_database=(
                    Path(engagement_storage) / ENGAGEMENTS_DB_NAME if engagement_storage else None
                ),
                trusted_manifest_public_key_pem=(
                    read_regular_text(
                        Path(manifest_public_key),
                        max_bytes=64 * 1024,
                        label="manifest public key",
                    )
                    if manifest_public_key
                    else None
                ),
                findings_directory=Path(findings_directory) if findings_directory else None,
                findings_database=Path(findings_storage) if findings_storage else None,
                baseline_findings_directory=(
                    Path(baseline_directory) if baseline_directory else None
                ),
                incidents_directory=(Path(incidents_directory) if incidents_directory else None),
                max_concurrent_requests=max_concurrent_requests,
            )
        )
    except (ImportError, OSError, ValueError, RuntimeError) as exc:
        typer.echo(
            f'olympus: native web unavailable: {exc}; install with pip install -e ".[api]"',
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE) from exc

    uvicorn.run(
        application,
        host=host,
        port=port,
        ssl_certfile=ssl_certfile or None,
        ssl_keyfile=ssl_keyfile or None,
        proxy_headers=False,
        server_header=False,
    )


@themis_app.command("migrate")
def themis_migrate(
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Create or upgrade the native SQLite job schema without losing jobs."""
    import sqlite3

    from olympus.themis.jobs import JobStoreError
    from olympus.themis.runtime import migrate_jobs

    try:
        result = migrate_jobs(Path(database))
    except (OSError, sqlite3.Error, ValueError, JobStoreError) as exc:
        typer.echo(f"olympus: native migration refused: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))


@themis_app.command("legacy-snapshot")
def themis_legacy_snapshot(
    source: str = typer.Option(..., "--source", help="Read-only archived VAP SQLite database."),
    backup: str = typer.Option(..., "--backup", help="Create-only consistent SQLite backup."),
    output: str = typer.Option(..., "--output", "-o", help="Create-only migration manifest."),
) -> None:
    """Inventory a legacy VAP database without creating executable jobs."""
    import sqlite3

    from olympus.core.fileio import UnsafeWriteTarget
    from olympus.themis.legacy_vap import create_legacy_vap_snapshot

    try:
        snapshot = create_legacy_vap_snapshot(
            Path(source), backup=Path(backup), manifest=Path(output)
        )
    except (OSError, sqlite3.Error, UnsafeWriteTarget, ValueError) as exc:
        typer.echo(f"olympus: legacy snapshot refused: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    decisions: dict[str, int] = {}
    for scan in snapshot.scans:
        decisions[scan.conversion_decision] = decisions.get(scan.conversion_decision, 0) + 1
    typer.echo(
        json.dumps(
            {
                "schema_name": snapshot.schema_name,
                "schema_version": snapshot.schema_version,
                "source_sha256": snapshot.source_sha256,
                "backup_sha256": snapshot.backup_sha256,
                "scan_count": snapshot.scan_count,
                "conversion_decisions": decisions,
                "excluded_tables": [table.name for table in snapshot.excluded_tables],
            },
            indent=2,
            sort_keys=True,
        )
    )


@themis_app.command("legacy-verify")
def themis_legacy_verify(
    source: str = typer.Option(..., "--source", help="Archived VAP SQLite database."),
    backup: str = typer.Option(..., "--backup", help="Snapshot SQLite backup."),
    manifest: str = typer.Option(..., "--manifest", "-m", help="Snapshot manifest."),
) -> None:
    """Verify all legacy snapshot artifacts without modifying or importing them."""
    import sqlite3

    from olympus.themis.legacy_vap import verify_legacy_vap_snapshot

    try:
        snapshot = verify_legacy_vap_snapshot(
            Path(source), backup=Path(backup), manifest=Path(manifest)
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        typer.echo(f"olympus: legacy snapshot verification refused: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    typer.echo(
        json.dumps(
            {
                "schema_name": snapshot.schema_name,
                "schema_version": snapshot.schema_version,
                "verified": True,
                "source_sha256": snapshot.source_sha256,
                "backup_sha256": snapshot.backup_sha256,
                "scan_count": snapshot.scan_count,
            },
            indent=2,
            sort_keys=True,
        )
    )


@themis_app.command("legacy-plan")
def themis_legacy_plan(
    source: str = typer.Option(..., "--source", help="Archived VAP SQLite database."),
    backup: str = typer.Option(..., "--backup", help="Verified snapshot SQLite backup."),
    manifest: str = typer.Option(..., "--manifest", "-m", help="Verified snapshot manifest."),
    output: str = typer.Option(..., "--output", "-o", help="Create-only review plan."),
) -> None:
    """Plan a reviewed legacy conversion without creating executable jobs."""
    import sqlite3

    from olympus.themis.legacy_vap import create_legacy_vap_conversion_plan
    from olympus.themis.registry import implemented

    try:
        plan = create_legacy_vap_conversion_plan(
            Path(source),
            backup=Path(backup),
            manifest=Path(manifest),
            output=Path(output),
            native_scanners=frozenset(implemented()),
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        typer.echo(f"olympus: legacy conversion plan refused: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    dispositions: dict[str, int] = {}
    for entry in plan.entries:
        dispositions[entry.disposition] = dispositions.get(entry.disposition, 0) + 1
    typer.echo(
        json.dumps(
            {
                "schema_name": plan.schema_name,
                "schema_version": plan.schema_version,
                "entry_count": plan.entry_count,
                "dispositions": dispositions,
                "executable_jobs_created": plan.executable_jobs_created,
                "authorization_inherited": plan.authorization_inherited,
            },
            indent=2,
            sort_keys=True,
        )
    )


@themis_app.command("legacy-approve")
def themis_legacy_approve(
    source: str = typer.Option(..., "--source", help="Archived VAP SQLite database."),
    backup: str = typer.Option(..., "--backup", help="Verified snapshot SQLite backup."),
    manifest: str = typer.Option(..., "--manifest", "-m", help="Verified snapshot manifest."),
    plan: str = typer.Option(..., "--plan", help="Verified create-only conversion plan."),
    signed_manifest: str = typer.Option(
        ..., "--signed-manifest", help="Current signed engagement manifest."
    ),
    manifest_public_key: str = typer.Option(
        ..., "--manifest-public-key", help="Pinned Ed25519 approver public key."
    ),
    migration_key: list[str] = typer.Option(
        ..., "--migration-key", help="Reviewed terminal record to approve; repeat as needed."
    ),
    revoked: list[str] | None = typer.Option(
        None, "--revoked", help="Revoked manifest identifier; repeat as needed."
    ),
    output: str = typer.Option(..., "--output", "-o", help="Create-only approval receipt."),
) -> None:
    """Approve selected legacy records for later historical import; create no jobs."""
    import sqlite3

    from olympus.engagements.manifest import (
        ManifestAuthorizationError,
        ManifestVerificationError,
    )
    from olympus.themis.legacy_vap import approve_legacy_vap_import
    from olympus.themis.registry import implemented

    try:
        approval = approve_legacy_vap_import(
            Path(source),
            backup=Path(backup),
            manifest=Path(manifest),
            plan_path=Path(plan),
            signed_manifest_path=Path(signed_manifest),
            trusted_public_key_path=Path(manifest_public_key),
            output=Path(output),
            migration_keys=migration_key,
            native_scanners=frozenset(implemented()),
            revoked=revoked or (),
        )
    except (ManifestAuthorizationError, ManifestVerificationError) as exc:
        typer.echo(f"olympus: legacy import approval refused: {exc}", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    except (OSError, sqlite3.Error, ValueError) as exc:
        typer.echo(f"olympus: legacy import approval invalid: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    typer.echo(
        json.dumps(
            {
                "schema_name": approval.schema_name,
                "schema_version": approval.schema_version,
                "engagement_id": approval.engagement_id,
                "signed_manifest_sha256": approval.signed_manifest_sha256,
                "approved_count": approval.approved_count,
                "historical_execution_authorized": approval.historical_execution_authorized,
                "executable_jobs_created": approval.executable_jobs_created,
            },
            indent=2,
            sort_keys=True,
        )
    )


@themis_app.command("legacy-import")
def themis_legacy_import(
    source: str = typer.Option(..., "--source", help="Archived VAP SQLite database."),
    backup: str = typer.Option(..., "--backup", help="Verified snapshot SQLite backup."),
    manifest: str = typer.Option(..., "--manifest", "-m", help="Verified snapshot manifest."),
    plan: str = typer.Option(..., "--plan", help="Verified conversion plan."),
    approval: str = typer.Option(..., "--approval", help="Signed-scope import approval receipt."),
    signed_manifest: str = typer.Option(
        ..., "--signed-manifest", help="Current signed engagement manifest."
    ),
    manifest_public_key: str = typer.Option(
        ..., "--manifest-public-key", help="Pinned Ed25519 approver public key."
    ),
    database: str = typer.Option(
        ".olympus/themis-jobs.sqlite3", "--database", "-d", help="Native Themis job database."
    ),
    revoked: list[str] | None = typer.Option(
        None, "--revoked", help="Revoked manifest identifier; repeat as needed."
    ),
    output: str = typer.Option(..., "--output", "-o", help="Create-only import receipt."),
) -> None:
    """Import approved terminal history; never queue or execute a scanner."""
    import sqlite3

    from olympus.engagements.manifest import (
        ManifestAuthorizationError,
        ManifestVerificationError,
    )
    from olympus.themis.jobs import JobStoreError
    from olympus.themis.legacy_vap import import_legacy_vap_history
    from olympus.themis.registry import implemented

    try:
        receipt = import_legacy_vap_history(
            Path(source),
            backup=Path(backup),
            manifest=Path(manifest),
            plan_path=Path(plan),
            approval_path=Path(approval),
            signed_manifest_path=Path(signed_manifest),
            trusted_public_key_path=Path(manifest_public_key),
            database=Path(database),
            output=Path(output),
            native_scanners=frozenset(implemented()),
            revoked=revoked or (),
        )
    except (ManifestAuthorizationError, ManifestVerificationError) as exc:
        typer.echo(f"olympus: legacy historical import refused: {exc}", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    except (OSError, sqlite3.Error, ValueError, JobStoreError) as exc:
        typer.echo(f"olympus: legacy historical import invalid: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    typer.echo(
        json.dumps(
            {
                "schema_name": receipt.schema_name,
                "schema_version": receipt.schema_version,
                "engagement_id": receipt.engagement_id,
                "signed_manifest_sha256": receipt.signed_manifest_sha256,
                "imported_count": receipt.imported_count,
                "historical_execution_authorized": receipt.historical_execution_authorized,
                "executable_jobs_created": receipt.executable_jobs_created,
            },
            indent=2,
            sort_keys=True,
        )
    )


@themis_app.command("workers")
def themis_workers(
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
    audit: str = typer.Option(DEFAULT_THEMIS_AUDIT_LOG, "--audit"),
    engagement_storage: str = typer.Option(
        "",
        "--engagement-storage",
        help="Directory holding signed manifests and their revocation register.",
    ),
    manifest_public_key: str = typer.Option(
        "",
        "--manifest-public-key",
        help="Pinned Ed25519 approver public key used to revalidate bound manifests.",
    ),
    worker_id: str | None = typer.Option(None, "--worker-id", help="Stable lease owner."),
    max_concurrent_jobs: int = typer.Option(
        1,
        "--max-concurrent-jobs",
        min=1,
        max=4_096,
        help="Shared cap for running jobs across workers using this database.",
    ),
    poll_interval: float = typer.Option(1.0, "--poll-interval", min=0.05, max=30.0),
    once: bool = typer.Option(False, "--once", help="Process at most one job and exit."),
    notify_webhook: str | None = typer.Option(
        None,
        "--notify-webhook",
        help="Emit a redacted notification to this webhook (http/https) when a job "
        "finishes. Off by default — nothing leaves the host without it.",
    ),
    notify_email_to: list[str] = typer.Option(
        [], "--notify-email-to", help="Notification e-mail recipient(s) (repeatable)."
    ),
    notify_email_from: str | None = typer.Option(
        None, "--notify-email-from", help="Notification e-mail sender address."
    ),
    notify_smtp_host: str | None = typer.Option(
        None, "--notify-smtp-host", help="SMTP host for job notifications."
    ),
    notify_smtp_port: int = typer.Option(25, "--notify-smtp-port", help="SMTP port."),
    notify_finding_severity: Severity | None = typer.Option(
        None,
        "--notify-finding-severity",
        help="Also emit one notification per finding at or above this severity "
        "(bounded). Omit to notify only on job completion.",
    ),
) -> None:
    """Run the native worker; SIGINT/SIGTERM cancel the active scan and stop."""
    import sqlite3

    from olympus.core.notifications import (
        EmailChannel,
        NotificationChannel,
        NotificationDispatcher,
        PinnedWebhookPoster,
        SmtpEmailTransport,
        WebhookChannel,
    )
    from olympus.core.observability import observability_from_config
    from olympus.engagements.store import ENGAGEMENTS_DB_NAME, StoredManifestAuthorizer
    from olympus.themis.config import live_enabled
    from olympus.themis.jobs import JobStoreError, ThemisJobStore, ThemisWorker, generate_worker_id
    from olympus.themis.runtime import (
        WorkerStop,
        job_notifier,
        migrate_jobs,
        work_queue,
        worker_signals,
    )
    from olympus.themis.sandbox import SandboxError, require_scanner_isolation

    try:
        migrate_jobs(Path(database))
        live = live_enabled()
        if live and (not engagement_storage or not manifest_public_key):
            raise ValueError("live workers require --engagement-storage and --manifest-public-key")
        if bool(engagement_storage) != bool(manifest_public_key):
            raise ValueError(
                "--engagement-storage and --manifest-public-key must be configured together"
            )
        if live:
            require_scanner_isolation()
        telemetry = observability_from_config()
        manifest_authorizer = (
            StoredManifestAuthorizer(
                Path(engagement_storage) / ENGAGEMENTS_DB_NAME,
                trusted_public_key_pem=Path(manifest_public_key).read_text(encoding="utf-8"),
            )
            if manifest_public_key
            else None
        )
        notify_channels: list[NotificationChannel] = []
        if notify_webhook is not None:
            notify_channels.append(WebhookChannel(notify_webhook, PinnedWebhookPoster()))
        if notify_email_to:
            if notify_email_from is None or notify_smtp_host is None:
                raise ValueError(
                    "--notify-email-to requires --notify-email-from and --notify-smtp-host"
                )
            notify_channels.append(
                EmailChannel(
                    SmtpEmailTransport(notify_smtp_host, notify_smtp_port),
                    notify_email_from,
                    tuple(notify_email_to),
                )
            )
    except (OSError, sqlite3.Error, ValueError, JobStoreError, SandboxError) as exc:
        typer.echo(f"olympus: native worker unavailable: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    stop = WorkerStop()

    def emit_job(job: ThemisJob) -> None:
        typer.echo(json.dumps(job.model_dump(mode="json"), sort_keys=True))

    # Notifications are off unless a channel was configured: then each finished job
    # also dispatches a redacted notification, alongside the existing JSON output.
    on_job: Callable[[ThemisJob], None] = emit_job
    if notify_channels:
        on_job = job_notifier(
            NotificationDispatcher(tuple(notify_channels)),
            also=emit_job,
            finding_min_severity=notify_finding_severity,
        )

    try:
        worker = ThemisWorker(
            ThemisJobStore(Path(database)),
            live_scans=live,
            observability=telemetry,
            worker_id=generate_worker_id() if worker_id is None else worker_id,
            manifest_authorizer=manifest_authorizer,
            max_concurrent_jobs=max_concurrent_jobs,
        )
    except ValueError as exc:
        telemetry.shutdown()
        typer.echo(f"olympus: invalid worker settings: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    try:
        with worker_signals(stop):
            if not once:
                typer.echo(
                    json.dumps(
                        {
                            "ready": True,
                            "worker_id": worker.worker_id,
                            "live_scans": live,
                            "manifest_revalidation": manifest_authorizer is not None,
                            "max_concurrent_jobs": max_concurrent_jobs,
                        },
                        sort_keys=True,
                    )
                )
            result = work_queue(
                worker,
                stop,
                audit_path=Path(audit) if audit else None,
                poll_seconds=poll_interval,
                once=once,
                on_job=on_job,
            )
    except (OSError, sqlite3.Error, ValueError, JobStoreError) as exc:
        typer.echo(f"olympus: native worker failed: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    finally:
        telemetry.shutdown()
    if result.stopped:
        typer.echo(json.dumps({"stopped": True, "processed": result.processed}, sort_keys=True))
        raise typer.Exit(code=ExitCode.CANCELLED)
    if result.last_job is None:
        typer.echo(json.dumps({"claimed": False, "reason": "queue-empty"}, sort_keys=True))
        return
    code = _job_exit_code(result.last_job)
    if code is not ExitCode.OK:
        raise typer.Exit(code=code)


@themis_app.command("scanners")
def themis_scanners(
    check: bool = typer.Option(
        False, "--check", help="Also report whether each scanner's binary is available."
    ),
) -> None:
    """List the complete Themis scanner catalogue (all 24 integrations)."""
    from olympus.integrations.activity import classify

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
            # Reviewed risk class (SEC-G): surfaced here so the operator sees how
            # intrusive a scanner is from the catalogue, not only in a per-scan
            # preview. An unmapped scanner defaults to ``active``, never passive.
            "risk": classify(spec).risk.value,
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


@themis_app.command("matrix")
def themis_matrix(
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
                "olympus: docs/scanner-matrix.md is stale; run 'olympus themis matrix --write'",
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


@themis_app.command("maturity")
def themis_maturity(
    check: bool = typer.Option(
        False,
        "--check",
        help="Exit non-zero if the maturity status block in docs/scanner-maturity.md "
        "differs from the generated output.",
    ),
    write: bool = typer.Option(
        False,
        "--write",
        help="Rewrite the generated maturity status block in docs/scanner-maturity.md in place.",
    ),
) -> None:
    """Render the maturity status block from the ledger, or check/rewrite the doc.

    The per-stage counts and the scanner names at each stage are generated from
    ``olympus.integrations.maturity`` (the registry plus the declared ledger), so
    the "Lo stato oggi" table in ``docs/scanner-maturity.md`` can never drift from
    the code — exactly as ``olympus themis matrix`` keeps ``docs/scanner-matrix.md``
    honest. ``--check`` is the CI gate: it exits ``2`` when the committed block no
    longer matches. The surrounding prose is hand-written and left untouched.
    """
    from pathlib import Path

    from olympus.integrations.maturity import render_status_section

    doc_path = Path(__file__).resolve().parents[3] / "docs" / "scanner-maturity.md"
    section = render_status_section()
    try:
        current = doc_path.read_text(encoding="utf-8")
    except OSError as exc:
        typer.echo(f"olympus: cannot read {doc_path}: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    try:
        updated = _replace_generated_section(current, section)
    except ValueError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    if check:
        if current != updated:
            typer.echo(
                "olympus: docs/scanner-maturity.md status block is stale; "
                "run 'olympus themis maturity --write'",
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.USAGE))
        typer.echo("olympus: scanner maturity status block is up to date", err=True)
        return

    if write:
        doc_path.write_text(updated, encoding="utf-8")
        typer.echo(f"olympus: wrote {doc_path}", err=True)
        return

    typer.echo(section)


def _replace_generated_section(document: str, section: str) -> str:
    """Return ``document`` with the maturity-status markers' content set to ``section``.

    The markers must appear exactly once each and in order; anything else is a
    doc-authoring error rather than drift, so it is reported as a usage failure.
    """
    from olympus.integrations.maturity import STATUS_BLOCK_BEGIN, STATUS_BLOCK_END

    begin = document.count(STATUS_BLOCK_BEGIN)
    end = document.count(STATUS_BLOCK_END)
    if begin != 1 or end != 1:
        raise ValueError(
            "docs/scanner-maturity.md must contain exactly one maturity-status marker pair"
        )
    start_index = document.index(STATUS_BLOCK_BEGIN)
    end_index = document.index(STATUS_BLOCK_END) + len(STATUS_BLOCK_END)
    if end_index < start_index:
        raise ValueError("maturity-status END marker precedes its START marker")
    return document[:start_index] + section + document[end_index:]


@themis_app.command("capabilities")
def themis_capabilities(
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
    """Report what Themis can actually execute, and how far each engine is proven.

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
                f"olympus: {reached} integration(s) reach {minimum.value}, {count} required",
                err=True,
            )
            raise typer.Exit(code=int(ExitCode.NOT_AUTHORIZED))

    if strict and document["ready"] == 0:
        raise typer.Exit(code=int(ExitCode.NOT_AUTHORIZED))


@themis_app.command("preview")
def themis_preview(
    scanner: str = typer.Argument(..., help="Scanner to preview, e.g. nmap, nuclei, sqlmap."),
    target: str = typer.Option(..., "--target", help="The target the scanner would run against."),
    kind: str = typer.Option("host", "--kind", help="Target kind: host, domain or url."),
    scope: str = typer.Option(..., "--scope", help="Themis scope file authorizing the target."),
    simulate: bool = typer.Option(
        False, "--simulate", help="Preview a simulated run (no live traffic, no authorization)."
    ),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Reflect that live authorization would be asserted."
    ),
    timeout: float = typer.Option(300.0, "--timeout", min=0.05, max=3_600),
    deadline: float = typer.Option(600.0, "--deadline", min=0.05, max=7_200),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Where a result would be written."
    ),
    audit: str | None = typer.Option(
        None, "--audit", help="Where the redacted audit entry would go."
    ),
    output_format: str = typer.Option(
        "table", "--format", help="Output format: table (human) or json (machine)."
    ),
) -> None:
    """Show the safety preview of a single planned scan. Runs nothing, offline.

    This answers "what exactly am I about to do?" before a scan is queued or
    executed: the normalized target, whether it matches the authorized scope,
    how intrusive the scanner is, which authorization is in force, the resource
    budget, where output would be written and which external tool would launch.
    The scope check is static and performs no DNS resolution; a hostname cleared
    by name is reported as still re-checked against its resolved address at run
    time (ROADMAP ``UX-B``). No scanner is launched and no target is contacted.
    """
    from olympus.core.output import OutputFormat
    from olympus.themis.application import ThemisRunRequest, load_scope
    from olympus.themis.config import live_enabled
    from olympus.themis.preview import preview_run

    if kind not in {"host", "domain", "url"}:
        typer.echo("olympus: --kind must be host, domain or url", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    try:
        fmt = OutputFormat(output_format)
    except ValueError as exc:
        typer.echo("olympus: --format must be table or json", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    try:
        loaded_scope = load_scope(Path(scope))
    except (OSError, ValueError) as exc:
        typer.echo(safe_terminal_text(f"olympus: invalid scope: {exc}"), err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    try:
        request = ThemisRunRequest(
            scanner=scanner,
            target=target,
            target_kind=kind,
            scope_path=Path(scope),
            authorized=i_am_authorized,
            live_enabled=live_enabled(),
            simulate=simulate,
            timeout_seconds=timeout,
            deadline_seconds=deadline,
            output_path=Path(output) if output else None,
            audit_path=Path(audit) if audit else None,
        )
    except ValueError as exc:
        typer.echo(safe_terminal_text(f"olympus: {exc}"), err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    preview = preview_run(request, loaded_scope)

    if fmt is OutputFormat.JSON:
        typer.echo(json.dumps(preview.to_dict(), indent=2, sort_keys=True))
    else:
        # Target-derived fields are terminal-sanitized so a hostile hostname
        # cannot forge lines or inject escape sequences (ROADMAP ``SEC-H``).
        typer.echo("\n".join(safe_terminal_text(line) for line in preview.lines()))

    # A scope verdict that would block the run is an honest, non-error outcome,
    # but the exit code distinguishes it so a caller can branch without parsing
    # text (same discipline as smart-scan's out-of-scope exit).
    if preview.blocks_launch:
        raise typer.Exit(code=int(ExitCode.OUT_OF_SCOPE))


@themis_app.command("smart-scan")
def themis_smart_scan(
    objective: str = typer.Option(
        ...,
        "--objective",
        help=(
            "What to achieve: recon | web-app | network | full. Each expands to a "
            "reviewed, ordered pipeline of native activities."
        ),
    ),
    target: str = typer.Option(..., "--target", help="The target to plan against."),
    target_kind: str = typer.Option(
        "host", "--target-kind", help="Target kind: host, domain or url."
    ),
    max_risk: str = typer.Option(
        "active",
        "--max-risk",
        help=(
            "Risk ceiling: passive | active | intrusive. A scanner louder than the "
            "ceiling is dropped with a reason; intrusive is never planned unless "
            "selected here explicitly."
        ),
    ),
    engagement_storage: str | None = typer.Option(
        None,
        "--engagement-storage",
        help="Directory holding the shared engagements database; enables engagement "
        "scope enforcement on the proposal.",
    ),
    engagement: str | None = typer.Option(
        None,
        "--engagement",
        help="Engagement id (ENG-YYYY-NNNNN); the target must fall inside its scope "
        "or the plan proposes nothing.",
    ),
    output_format: str = typer.Option(
        "table", "--format", help="Output format: table (human) or json (machine)."
    ),
) -> None:
    """Propose a deterministic, scope- and policy-aware scan pipeline. Runs nothing.

    Smart Scan turns an objective and a target into an ordered pipeline the
    operator reads **before** anything executes. It only proposes: no scanner is
    launched and no target is contacted here. Execution stays on the audited
    path (``olympus themis jobs`` / the guided web flow), so every stage still
    passes the real scope, authorization and preview gates. The proposal is
    reproducible — the same inputs always yield the same plan and digest.
    """
    from olympus.core.output import OutputFormat
    from olympus.engagements.resolve import require_engagement
    from olympus.engagements.store import ENGAGEMENTS_DB_NAME, EngagementStoreError
    from olympus.integrations.activity import RiskClass
    from olympus.integrations.capabilities import inventory
    from olympus.integrations.smartscan import ScanObjective, propose_pipeline

    try:
        chosen_objective = ScanObjective(objective)
    except ValueError as exc:
        typer.echo(
            f"olympus: unknown objective {objective!r}; expected one of "
            + ", ".join(item.value for item in ScanObjective),
            err=True,
        )
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    try:
        ceiling = RiskClass(max_risk)
    except ValueError as exc:
        typer.echo(
            f"olympus: unknown risk ceiling {max_risk!r}; expected one of "
            + ", ".join(item.value for item in RiskClass),
            err=True,
        )
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc
    if target_kind not in {"host", "domain", "url"}:
        typer.echo("olympus: --target-kind must be host, domain or url", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE))
    try:
        fmt = OutputFormat(output_format)
    except ValueError as exc:
        typer.echo("olympus: --format must be table or json", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    resolved_engagement = None
    if engagement is not None:
        if engagement_storage is None:
            typer.echo("olympus: --engagement requires --engagement-storage", err=True)
            raise typer.Exit(code=int(ExitCode.USAGE))
        database = Path(engagement_storage) / ENGAGEMENTS_DB_NAME
        try:
            resolved_engagement = require_engagement(database, engagement)
        except EngagementStoreError as exc:
            typer.echo(f"olympus: {safe_terminal_text(str(exc))}", err=True)
            raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    ready = {item.name for item in inventory() if item.ready}
    plan = propose_pipeline(
        objective=chosen_objective,
        target=target,
        target_kind=target_kind,
        ready=ready,
        engagement=resolved_engagement,
        max_risk=ceiling,
    )

    if fmt is OutputFormat.JSON:
        typer.echo(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
    else:
        typer.echo(_format_smart_scan_table(plan))

    # A plan that cannot run anything is an honest, non-error outcome, but the
    # exit code still distinguishes it so a caller can branch on it without
    # parsing text: out-of-scope targets exit OUT_OF_SCOPE, an empty-but-in-scope
    # plan exits OK (nothing to run here is not a failure of the proposal).
    if not plan.in_scope:
        raise typer.Exit(code=int(ExitCode.OUT_OF_SCOPE))


def _format_smart_scan_table(plan: object) -> str:
    """Render a Smart Scan plan as a human-readable, terminal-safe summary.

    Target and other target-derived text pass through :func:`safe_terminal_text`
    so a hostile hostname cannot forge lines or inject escape sequences into the
    operator's terminal (ROADMAP ``SEC-H``).
    """
    from olympus.integrations.smartscan import OBJECTIVE_SUMMARY, SmartScanPlan

    assert isinstance(plan, SmartScanPlan)  # noqa: S101 - internal invariant, not input validation
    lines: list[str] = []
    lines.append(f"Smart Scan proposal ({plan.objective.value})")
    lines.append(OBJECTIVE_SUMMARY[plan.objective])
    lines.append(f"  target:      {safe_terminal_text(plan.target)} ({plan.target_kind})")
    lines.append(f"  engagement:  {plan.engagement_id or '—'}")
    lines.append(f"  risk ceiling:{plan.max_risk.value:>9}")
    lines.append(f"  digest:      {plan.digest}")
    lines.append(f"  authorization required: {'yes' if plan.requires_authorization else 'no'}")
    if not plan.in_scope:
        lines.append("")
        lines.append("  The target is outside the engagement's scope; nothing is proposed.")
        return "\n".join(lines)
    lines.append("")
    if plan.stages:
        lines.append("Proposed pipeline (nothing runs until you launch each step):")
        for stage in plan.stages:
            flag = "AUTH" if stage.needs_authorization else "    "
            lines.append(
                f"  {stage.order}. [{flag}] {stage.scanner:<12} "
                f"{stage.risk.value:<9} {safe_terminal_text(stage.rationale)}"
            )
    else:
        lines.append("No stage can run on this host for this objective.")
    if plan.excluded:
        lines.append("")
        lines.append("Not proposed:")
        for dropped in plan.excluded:
            lines.append(f"  - {dropped.activity.value}: {safe_terminal_text(dropped.reason)}")
    return "\n".join(lines)


def _emit_job(job: object) -> None:
    from pydantic import BaseModel

    if not isinstance(job, BaseModel):
        raise TypeError("Themis job output must be a validated contract")
    typer.echo(job.model_dump_json(indent=2))


@jobs_app.command("init")
def themis_jobs_init(
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Initialize the private native job database."""
    from pathlib import Path

    from olympus.themis.jobs import ThemisJobStore

    store = ThemisJobStore(Path(database))
    store.initialize()
    typer.echo(json.dumps({"database": str(store.path), "initialized": True}, indent=2))


@jobs_app.command("backup")
def themis_jobs_backup(
    destination: str = typer.Option(..., "--destination", help="Snapshot output path."),
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Create a verified snapshot of the Themis jobs database only."""
    from dataclasses import asdict

    from olympus.themis.jobs import ThemisJobStore

    info = ThemisJobStore(Path(database)).backup(Path(destination))
    typer.echo(json.dumps({"snapshot": str(Path(destination)), **asdict(info)}, indent=2))


@jobs_app.command("verify-backup")
def themis_jobs_verify_backup(
    backup: str = typer.Option(..., "--backup", help="Themis jobs snapshot to validate."),
) -> None:
    """Verify a Themis jobs snapshot's schema, SQLite integrity, and fingerprint."""
    from dataclasses import asdict

    from olympus.themis.jobs import ThemisJobStore

    info = ThemisJobStore.verify_backup(Path(backup))
    typer.echo(json.dumps({"verified": True, **asdict(info)}, indent=2))


@jobs_app.command("restore")
def themis_jobs_restore(
    backup: str = typer.Option(..., "--backup", help="Verified jobs snapshot to restore."),
    destination: str = typer.Option(..., "--destination", help="New, absent SQLite path."),
) -> None:
    """Restore a jobs snapshot to a new path; stop services before switching config."""
    from dataclasses import asdict

    from olympus.themis.jobs import ThemisJobStore

    destination_path = Path(destination)
    info = ThemisJobStore.restore_backup(Path(backup), destination_path)
    typer.echo(
        json.dumps(
            {
                "restored_to": str(destination_path),
                "services_must_be_stopped_before_switching_config": True,
                **asdict(info),
            },
            indent=2,
        )
    )


@jobs_app.command("submit")
def themis_jobs_submit(
    scanner: str = typer.Argument(...),
    target: str = typer.Option(..., "--target"),
    kind: str = typer.Option("host", "--kind"),
    scope: str = typer.Option(..., "--scope"),
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
    idempotency_key: str | None = typer.Option(
        None,
        "--idempotency-key",
        help="Resubmitting the same key returns the existing job instead of queueing a second.",
    ),
    max_attempts: int = typer.Option(
        1, "--max-attempts", min=1, max=10, help="Execution attempts before the job is failed."
    ),
    signed_manifest: str = typer.Option(
        "",
        "--signed-manifest",
        help="Signed engagement manifest authorizing this exact target and scanner.",
    ),
    manifest_public_key: str = typer.Option(
        "",
        "--manifest-public-key",
        help="Pinned Ed25519 approver public key used to verify the manifest.",
    ),
    engagement_storage: str = typer.Option(
        "",
        "--engagement-storage",
        help="Directory holding the durable signed-manifest and revocation store.",
    ),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized"),
) -> None:
    """Persist one manifest-authorized scan job without executing it."""
    import sqlite3
    from datetime import UTC, datetime
    from pathlib import Path

    from olympus.core.fileio import read_regular_text
    from olympus.engagements.manifest import SignedEngagementManifest
    from olympus.engagements.store import (
        ENGAGEMENTS_DB_NAME,
        MAX_DOCUMENT_BYTES,
        SqliteEngagementStore,
    )
    from olympus.themis.jobs import ThemisJobStore

    if not i_am_authorized:
        typer.echo("olympus: queued live work requires --i-am-authorized", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED)
    if not signed_manifest or not manifest_public_key or not engagement_storage:
        typer.echo(
            "olympus: queued work requires --signed-manifest, --manifest-public-key "
            "and --engagement-storage",
            err=True,
        )
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED)

    engagement_store: SqliteEngagementStore | None = None
    try:
        signed = SignedEngagementManifest.model_validate_json(
            read_regular_text(
                Path(signed_manifest),
                max_bytes=MAX_DOCUMENT_BYTES,
                label="signed engagement manifest",
            )
        )
        trusted_public_key = read_regular_text(
            Path(manifest_public_key),
            max_bytes=64 * 1024,
            label="manifest public key",
        )
        engagement_store = SqliteEngagementStore(Path(engagement_storage) / ENGAGEMENTS_DB_NAME)
        engagement_store.authorize_and_save_manifest(
            signed,
            trusted_public_key_pem=trusted_public_key,
            target=target,
            technique=scanner,
            now=datetime.now(UTC),
        )
    except (OSError, sqlite3.Error, ValueError) as exc:
        typer.echo(
            safe_terminal_text(f"olympus: signed authorization refused: {exc}"),
            err=True,
        )
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    finally:
        if engagement_store is not None:
            engagement_store.close()

    try:
        job = ThemisJobStore(Path(database)).submit(
            scanner=scanner,
            target=target,
            target_kind=kind,
            scope_path=Path(scope),
            authorized=True,
            manifest_sha256=signed.manifest_sha256,
            idempotency_key=idempotency_key,
            max_attempts=max_attempts,
        )
    except ValueError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    _emit_job(job)


@jobs_app.command("list")
def themis_jobs_list(
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
    state: str | None = typer.Option(None, "--state"),
    limit: int = typer.Option(100, "--limit", min=1, max=1_000),
) -> None:
    """List durable jobs, optionally filtered by lifecycle state."""
    from pathlib import Path

    from olympus.themis.jobs import JobState, ThemisJobStore

    try:
        selected = JobState(state) if state else None
    except ValueError as exc:
        typer.echo(f"olympus: invalid job state {state!r}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    jobs = ThemisJobStore(Path(database)).list(limit=limit, state=selected)
    typer.echo(
        json.dumps(
            {
                "schema_name": "olympus.themis-job-list",
                "schema_version": "3.0.0",
                "count": len(jobs),
                "jobs": [job.model_dump(mode="json") for job in jobs],
            },
            indent=2,
            sort_keys=True,
        )
    )


@jobs_app.command("status")
def themis_jobs_status(
    job_id: str = typer.Argument(...),
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
    output_format: str = typer.Option(
        "json",
        "--format",
        help="Output format: json (full contract) or table (human outcome summary).",
    ),
) -> None:
    """Return one durable job and its normalized result when complete.

    In ``table`` mode the job's result is rendered as an honest outcome summary
    (ROADMAP ``UX-B``) that keeps simulation, unavailable, failed, cancelled and
    partial outcomes distinct from a trustworthy empty, so a run that produced no
    findings for any of those reasons is never read as "no vulnerabilities".
    """
    from pathlib import Path

    from olympus.core.output import OutputFormat
    from olympus.themis.jobs import ThemisJobStore

    try:
        fmt = OutputFormat(output_format)
    except ValueError as exc:
        typer.echo("olympus: --format must be table or json", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE)) from exc

    try:
        job = ThemisJobStore(Path(database)).get(job_id)
    except KeyError as exc:
        typer.echo(f"olympus: {exc.args[0]}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    if fmt is OutputFormat.JSON:
        _emit_job(job)
        return

    from olympus.themis.outcome import from_mapping

    typer.echo(f"Job:       {safe_terminal_text(job.job_id)}")
    typer.echo(f"Scanner:   {safe_terminal_text(job.scanner)}")
    typer.echo(f"State:     {job.state.value}")
    if job.result is not None:
        summary = from_mapping(job.result)
        typer.echo("\n".join(safe_terminal_text(line) for line in summary.lines()))
    else:
        typer.echo("Outcome:   (job has not produced a result yet)")


@jobs_app.command("cancel")
def themis_jobs_cancel(
    job_id: str = typer.Argument(...),
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Cancel queued work or request cooperative cancellation of running work."""
    from pathlib import Path

    from olympus.themis.jobs import ThemisJobStore

    try:
        _emit_job(ThemisJobStore(Path(database)).cancel(job_id))
    except KeyError as exc:
        typer.echo(f"olympus: {exc.args[0]}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc


@jobs_app.command("work")
def themis_jobs_work(
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
    audit: str = typer.Option(".olympus/themis-audit.ndjson", "--audit"),
    worker_id: str | None = typer.Option(
        None, "--worker-id", help="Stable identity for this worker's leases."
    ),
) -> None:
    """Claim and execute at most one job; safe for cron/systemd/container loops."""
    from pathlib import Path

    from olympus.core.observability import (
        ObservabilityConfigurationError,
        observability_from_config,
    )
    from olympus.themis.config import live_enabled
    from olympus.themis.jobs import ThemisJobStore, ThemisWorker, generate_worker_id
    from olympus.themis.sandbox import SandboxError, require_scanner_isolation

    store = ThemisJobStore(Path(database))
    try:
        live = live_enabled()
        if live:
            require_scanner_isolation()
        observability = observability_from_config()
    except (ObservabilityConfigurationError, SandboxError, ValueError) as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    try:
        worker = ThemisWorker(
            store,
            live_scans=live,
            worker_id=worker_id or generate_worker_id(),
            observability=observability,
        )
    except ValueError as exc:
        observability.shutdown()
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    try:
        job = worker.run_next(audit_path=Path(audit))
    finally:
        observability.shutdown()
    if job is None:
        typer.echo(json.dumps({"claimed": False, "reason": "queue-empty"}, indent=2))
        return
    _emit_job(job)
    code = _job_exit_code(job)
    if code is not ExitCode.OK:
        raise typer.Exit(code=code)


@jobs_app.command("prune")
def themis_jobs_prune(
    older_than_days: int = typer.Option(
        30, "--older-than-days", min=0, max=3_650, help="Keep finished jobs for this long."
    ),
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Report what would be deleted."),
) -> None:
    """Delete finished jobs past the retention window; queued/running work is kept."""
    from pathlib import Path

    from olympus.themis.jobs import ThemisJobStore

    count, job_ids = ThemisJobStore(Path(database)).prune(
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
def themis_jobs_recover(
    database: str = typer.Option(".olympus/themis-jobs.sqlite3", "--database", "-d"),
) -> None:
    """Requeue (or fail) jobs whose worker stopped renewing its lease."""
    from pathlib import Path

    from olympus.themis.jobs import ThemisJobStore

    recovered = ThemisJobStore(Path(database)).recover_expired_leases()
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


def _identity_register(path: str, *, create: bool = False) -> IdentityRegister:
    from pathlib import Path

    from olympus.themis.identity import IdentityRegister, load_register

    location = Path(path)
    if not location.exists():
        if create:
            return IdentityRegister()
        typer.echo(f"olympus: identity register not found: {location}", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    return load_register(location)


def _audit_identity_change(
    audit_path: str,
    *,
    action: str,
    identity_id: str,
    metadata: dict[str, object] | None = None,
) -> None:
    """Audit credential administration by identity, never by credential value."""
    from datetime import UTC, datetime
    from pathlib import Path
    from uuid import uuid4

    from olympus.core.execution import StructuredAuditRecord, append_structured_audit

    append_structured_audit(
        Path(audit_path),
        StructuredAuditRecord(
            timestamp=datetime.now(UTC).isoformat(),
            execution_id=f"identity-{uuid4().hex}",
            action=f"themis.identity.{action}",
            outcome="requested",
            target=identity_id,
            metadata={"identity": identity_id, **(metadata or {})},
        ),
    )


@identities_app.command("init")
def themis_identities_init(
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
) -> None:
    """Create an empty identity register (owner-only)."""
    from pathlib import Path

    from olympus.themis.identity import IdentityRegister, save_register

    location = Path(register_path)
    if location.exists():
        typer.echo(f"olympus: identity register already exists: {location}", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    save_register(location, IdentityRegister())
    typer.echo(json.dumps({"register": str(location), "identities": 0}, indent=2))


@identities_app.command("add")
def themis_identities_add(
    identity_id: str = typer.Argument(..., help="Identity name, e.g. 'ops-console'."),
    scopes: str = typer.Option(
        "jobs:read", "--scopes", help="Comma-separated scopes granted to this identity."
    ),
    rate_limit: int = typer.Option(120, "--rate-limit", min=1, max=100_000),
    expires_in_days: int = typer.Option(
        90,
        "--expires-in-days",
        min=1,
        max=3_650,
        help="Mandatory lifetime of the newly issued credential.",
    ),
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
    audit_path: str = typer.Option(DEFAULT_THEMIS_AUDIT_LOG, "--audit"),
) -> None:
    """Add one scoped identity and print its secret exactly once."""
    from pathlib import Path

    from olympus.themis.identity import IdentityError, add_identity, save_register

    register = _identity_register(register_path, create=True)
    try:
        updated, secret = add_identity(
            register,
            identity_id=identity_id,
            scopes=[item.strip() for item in scopes.split(",") if item.strip()],
            rate_limit_per_minute=rate_limit,
            expires_in_days=expires_in_days,
        )
    except IdentityError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    identity = updated.find(identity_id)
    _audit_identity_change(
        audit_path,
        action="created",
        identity_id=identity_id,
        metadata={
            "not_after": identity.not_after.isoformat()
            if identity and identity.not_after
            else None,
            "scopes": sorted(identity.scopes) if identity else [],
        },
    )
    save_register(Path(register_path), updated)
    _emit_secret(identity_id, secret, "created")


@identities_app.command("rotate")
def themis_identities_rotate(
    identity_id: str = typer.Argument(...),
    overlap_seconds: int = typer.Option(
        300,
        "--overlap-seconds",
        min=0,
        max=3_600,
        help="How long the previous secret keeps working; 0 revokes it immediately.",
    ),
    expires_in_days: int = typer.Option(
        90,
        "--expires-in-days",
        min=1,
        max=3_650,
        help="Mandatory lifetime of the replacement credential.",
    ),
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
    audit_path: str = typer.Option(DEFAULT_THEMIS_AUDIT_LOG, "--audit"),
) -> None:
    """Issue a new secret, keeping the old one valid for a bounded overlap."""
    from pathlib import Path

    from olympus.themis.identity import IdentityError, rotate_identity, save_register

    try:
        updated, secret = rotate_identity(
            _identity_register(register_path),
            identity_id,
            overlap_seconds=overlap_seconds,
            expires_in_days=expires_in_days,
        )
    except IdentityError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    identity = updated.find(identity_id)
    _audit_identity_change(
        audit_path,
        action="rotated",
        identity_id=identity_id,
        metadata={
            "overlap_seconds": overlap_seconds,
            "not_after": identity.not_after.isoformat()
            if identity and identity.not_after
            else None,
        },
    )
    save_register(Path(register_path), updated)
    _emit_secret(identity_id, secret, "rotated")


@identities_app.command("revoke")
def themis_identities_revoke(
    identity_id: str = typer.Argument(...),
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
    audit_path: str = typer.Option(DEFAULT_THEMIS_AUDIT_LOG, "--audit"),
) -> None:
    """Revoke an identity immediately, including any secret still rotating."""
    from pathlib import Path

    from olympus.themis.identity import IdentityError, revoke_identity, save_register

    try:
        updated = revoke_identity(
            _identity_register(register_path),
            identity_id,
        )
    except IdentityError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    _audit_identity_change(audit_path, action="revoked", identity_id=identity_id)
    save_register(Path(register_path), updated)
    typer.echo(json.dumps({"identity_id": identity_id, "revoked": True}, indent=2))


@identities_app.command("list")
def themis_identities_list(
    register_path: str = typer.Option(DEFAULT_IDENTITY_REGISTER, "--file", "-f"),
) -> None:
    """List identities, their scopes and status. Secrets are never stored."""
    register = _identity_register(register_path)
    identities = register.public_view()
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
def themis_retention_prune(
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
        raise typer.Exit(code=ExitCode.USAGE) from exc
    typer.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))


@retention_app.command("rotate-log")
def themis_retention_rotate_log(
    path: str = typer.Argument(..., help="Append-only log to roll over."),
    max_bytes: int = typer.Option(50_000_000, "--max-bytes", min=1),
    keep: int = typer.Option(5, "--keep", min=0, max=100, help="Generations to retain."),
    insecure: bool = typer.Option(False, "--no-overwrite"),
) -> None:
    """Roll an audit log once it passes a size budget, securely dropping the oldest."""
    from pathlib import Path

    from olympus.core.retention import RetentionError, rotate_log

    try:
        report = rotate_log(Path(path), max_bytes=max_bytes, keep=keep, secure=not insecure)
    except RetentionError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    typer.echo(json.dumps(report.to_dict(), indent=2, sort_keys=True))


@themis_app.command("deps")
def themis_deps() -> None:
    """Report Themis runtime dependencies: web stack, services, and scanner binaries."""
    report = Report("themis deps")
    for module in ("fastapi", "uvicorn", "jinja2", "multipart"):
        report.add(check_python_module(module, optional=True))
    for spec in scanner_registry.REGISTRY:
        if spec.binary:
            report.add(check_binary(spec.binary, optional=True))
    _emit_report(report)


@themis_app.command("info")
def themis_info() -> None:
    """Show where Themis lives and whether its stack is importable."""
    import importlib.util

    from olympus.themis.jobs import SCHEMA_VERSION

    importable = importlib.util.find_spec("fastapi") is not None
    binaries = sum(1 for s in scanner_registry.REGISTRY if s.available())
    payload = {
        "name": "Themis (native Olympus control plane)",
        "runtime": "native",
        "vendor_required": False,
        "job_schema_version": SCHEMA_VERSION,
        "queue_backend": "sqlite",
        "scanners": len(scanner_registry.REGISTRY),
        "scanner_binaries_available": binaries,
        "web_stack_importable": importable,
        "install_hint": 'pip install "olympus-security[themis]"',
        "docker_compose": "docker-compose.yml (services: themis-migrate, themis-api, "
        "themis-app, themis-worker)",
    }
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@themis_app.command("scan")
def themis_scan(
    target: str = typer.Option(..., "--target", help="Authorized target to scan."),
    scanner: str = typer.Option(..., "--scanner", help="Ready specialist engine."),
    scope_id: str = typer.Option(..., "--scope-id", help="Server-registered scope identifier."),
    kind: str = typer.Option("host", "--kind", help="Target kind: host, domain or url."),
    base_url: str = typer.Option(
        "http://127.0.0.1:8443", "--url", help="Base URL of the native Themis API."
    ),
    api_key_env: str = typer.Option("OLYMPUS_THEMIS_API_KEY", "--api-key-env"),
    i_am_authorized: bool = typer.Option(False, "--i-am-authorized"),
) -> None:
    """Submit authorized work to the native Themis API."""
    import ipaddress
    import urllib.error
    import urllib.request
    from urllib.parse import urlparse

    if not i_am_authorized:
        typer.echo("olympus: API scan submission requires --i-am-authorized", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED)
    api_key = _read_api_key(api_key_env)
    if not api_key:
        typer.echo(
            f"olympus: required API key environment variable is not set: {api_key_env}",
            err=True,
        )
        raise typer.Exit(code=ExitCode.USAGE)
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        typer.echo("olympus: Themis API URL must be an absolute HTTP(S) URL", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    try:
        loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        loopback = parsed.hostname.lower() == "localhost"
    if parsed.scheme != "https" and not loopback:
        typer.echo("olympus: remote Themis API connections require HTTPS", err=True)
        raise typer.Exit(code=ExitCode.USAGE)

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
        typer.echo(
            safe_terminal_text(f"olympus: Themis server returned {exc.code}: {detail}"),
            err=True,
        )
        raise typer.Exit(code=ExitCode.FINDINGS) from exc
    except urllib.error.URLError as exc:
        typer.echo(
            f"olympus: could not reach a Themis server at {base_url} ({exc.reason}). "
            "Start it with: olympus themis api",
            err=True,
        )
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc


@themis_app.command("doctor")
def themis_doctor(
    scanner: str | None = typer.Option(
        None,
        "--scanner",
        help=(
            "Diagnose one scanner (binary/version/deps, adapter, maturity, readiness), "
            "or 'all' for every catalogued engine, instead of the runtime."
        ),
    ),
) -> None:
    """Diagnose the Themis runtime, or one scanner with ``--scanner``.

    Without ``--scanner`` this reports the whole runtime (web stack, DB dir,
    Redis, config). With ``--scanner <name>`` it reports that one engine: whether
    its binary is on PATH and at what version (or, for API engines, whether the
    endpoint and secret variables are set — names only), whether Olympus owns a
    native adapter, the project's maturity for it, and live-job readiness.
    ``--scanner all`` reports every catalogued engine. Exit code ``2`` for an
    unknown scanner name.
    """
    if scanner is not None:
        from olympus.integrations import scanner_doctor

        if scanner == "all":
            reports = scanner_doctor.all_scanner_reports()
            payload = {
                "title": "themis doctor --scanner all",
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

    report = Report("themis doctor")
    for module in ("fastapi", "uvicorn", "jinja2", "multipart"):
        report.add(check_python_module(module, optional=True))
    from olympus.themis.config import ThemisConfigError, live_enabled

    report.add(Check("runtime:native", True, "SQLite jobs; no vendor, Redis or Celery"))
    try:
        live = live_enabled()
        report.add(
            report_flag(
                "config:THEMIS_ENABLE_LIVE_SCANS",
                live,
                "live scans ENABLED" if live else "live scans disabled (no live traffic)",
            )
        )
    except ThemisConfigError as exc:
        report.add(Check("config:THEMIS_ENABLE_LIVE_SCANS", False, str(exc)))
    credential_set = bool(_read_api_key("OLYMPUS_THEMIS_API_KEY"))
    report.add(
        report_flag(
            "config:api-credential",
            credential_set,
            "credential is set" if credential_set else "set a credential or pass --identities",
        )
    )
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
    """Report how confined scanner processes will be (see docs/themis-sandbox.md)."""
    import os

    from olympus.themis.sandbox import SandboxError, SandboxPolicy

    try:
        policy = SandboxPolicy.from_environment()
        identity = policy.resolve_identity()
    except SandboxError as exc:
        return Check("sandbox:isolation", False, str(exc), optional=True)
    privileged_parent = os.name == "posix" and os.geteuid() == 0
    if identity is not None:
        confined, detail = True, f"scanners drop to {identity.name} (uid {identity.uid})"
    elif privileged_parent:
        confined, detail = False, "THEMIS_SANDBOX_ALLOW_ROOT is set: scanners would run as ROOT"
    else:
        confined, detail = True, "parent process is already unprivileged"
    limits = ", ".join(f"{name}={value}" for name, value in sorted(policy.describe().items()))
    return Check("sandbox:isolation", confined, f"{detail}; limits {limits}", optional=True)


def report_flag(name: str, ok: bool, detail: str) -> Check:
    """Build an optional diagnostics :class:`Check` for a boolean condition."""
    return Check(name, ok, detail, optional=True)


# --------------------------------------------------------------------------- #
# Deprecated ``olympus vap`` alias -> forwards to ``olympus themis``
# --------------------------------------------------------------------------- #
def register_vap_shim(parent: typer.Typer) -> None:
    """Register a deprecated ``vap`` passthrough that forwards to ``themis``.

    Planned removal: the ``vap`` alias will be removed in a future release. Use
    ``olympus themis`` instead.
    """

    @parent.command(
        "vap",
        context_settings={
            "allow_extra_args": True,
            "ignore_unknown_options": True,
            "help_option_names": [],
        },
        help="[DEPRECATED] Alias for 'olympus themis' — forwards all arguments.",
    )
    def _vap(ctx: typer.Context) -> None:
        from typer.main import get_command

        typer.echo(
            "olympus: 'olympus vap' is deprecated and will be removed in a future release; "
            "use 'olympus themis' instead.",
            err=True,
        )
        command = get_command(themis_app)
        try:
            command.main(args=list(ctx.args), prog_name="olympus themis", standalone_mode=False)
        except SystemExit as exc:  # pragma: no cover - click may raise SystemExit
            raw_code = exc.code if isinstance(exc.code, int) else None
            raise typer.Exit(code=normalize_exit_code(raw_code)) from exc


# --------------------------------------------------------------------------- #
# Deprecated ``olympus aegis`` alias -> forwards to ``olympus themis``
# --------------------------------------------------------------------------- #
def register_aegis_shim(parent: typer.Typer) -> None:
    """Register a deprecated ``aegis`` passthrough that forwards to ``themis``.

    The AEGIS subsystem was renamed to Themis (ROADMAP ``DEV-I``). The old
    command keeps working for at least one release, printing a deprecation
    warning and forwarding every argument to ``olympus themis`` — one
    implementation, no duplicated logic.
    """

    @parent.command(
        "aegis",
        context_settings={
            "allow_extra_args": True,
            "ignore_unknown_options": True,
            "help_option_names": [],
        },
        help="[DEPRECATED] Alias for 'olympus themis' — forwards all arguments.",
    )
    def _aegis(ctx: typer.Context) -> None:
        from typer.main import get_command

        typer.echo(
            "olympus: 'olympus aegis' is deprecated and will be removed in a future release; "
            "use 'olympus themis' instead.",
            err=True,
        )
        command = get_command(themis_app)
        try:
            command.main(args=list(ctx.args), prog_name="olympus themis", standalone_mode=False)
        except SystemExit as exc:  # pragma: no cover - click may raise SystemExit
            raw_code = exc.code if isinstance(exc.code, int) else None
            raise typer.Exit(code=normalize_exit_code(raw_code)) from exc


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
        # Argus + Themis stacks (importable?).
        report.add(check_python_module("requests", optional=True))
        report.add(check_python_module("fastapi", optional=True))
        # Scanner binary coverage.
        binaries = sum(1 for s in scanner_registry.REGISTRY if s.available())
        report.add(
            report_flag(
                "themis:scanner_binaries",
                binaries > 0,
                f"{binaries}/{len(scanner_registry.REGISTRY)} scanner binaries on PATH",
            )
        )
        import tempfile

        report.add(check_writable_dir(tempfile.gettempdir(), optional=True))
        _emit_report(report)


@themis_app.command("run")
def themis_run(
    scanner: str = typer.Argument(..., help="Scanner name (see 'olympus themis run --list')."),
    target: str = typer.Option("", "--target", help="Authorized target (host/url/domain)."),
    kind: str = typer.Option("host", "--kind", help="Target kind: host, url, or domain."),
    scope: str = typer.Option("", "--scope", help="Versioned Themis scope JSON file."),
    timeout: float = typer.Option(300.0, "--timeout", help="Per-process timeout in seconds."),
    deadline: float = typer.Option(600.0, "--deadline", help="Overall scan deadline in seconds."),
    max_scope_bytes: int = typer.Option(1_000_000, "--max-scope-bytes"),
    max_output_bytes: int = typer.Option(5_000_000, "--max-output-bytes"),
    max_findings: int = typer.Option(10_000, "--max-findings"),
    output: str = typer.Option("", "--output", help="Optional private versioned result JSON."),
    audit: str = typer.Option(
        DEFAULT_THEMIS_AUDIT_LOG, "--audit", help="Redacted structured audit log."
    ),
    signed_manifest: str = typer.Option(
        "",
        "--signed-manifest",
        help="Signed engagement manifest required for direct live execution.",
    ),
    manifest_public_key: str = typer.Option(
        "",
        "--manifest-public-key",
        help="Pinned Ed25519 approver public key required for direct live execution.",
    ),
    engagement_storage: str = typer.Option(
        "",
        "--engagement-storage",
        help="Directory holding the durable signed-manifest and revocation store.",
    ),
    lab_policy: str = typer.Option(
        "",
        "--lab-policy",
        help="Explicit signed policy file for a direct live scan limited to declared lab CIDRs.",
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
    import sqlite3
    from pathlib import Path

    from olympus.core.execution import AuthorizationRequiredError, CancellationRequested
    from olympus.themis import config as themis_config
    from olympus.themis.application import ThemisApplicationService, ThemisRunRequest
    from olympus.themis.config import ThemisConfigError
    from olympus.themis.registry import UnknownScannerError, implemented
    from olympus.themis.sandbox import SandboxError
    from olympus.themis.scope import (
        OutOfScopeError,
        SsrfBlockedError,
        TargetResolutionError,
        TargetValidationError,
    )

    if list_scanners:
        typer.echo(json.dumps({"implemented": implemented()}, indent=2, sort_keys=True))
        return
    if not target:
        typer.echo("olympus: --target is required (or use --list)", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    if not scope:
        typer.echo("olympus: --scope is required for every real or simulated target", err=True)
        raise typer.Exit(code=ExitCode.USAGE)
    try:
        live_scans = themis_config.live_enabled()
    except ThemisConfigError as exc:
        typer.echo(f"olympus: Themis execution error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc

    job_id: str | None = None
    manifest_sha256: str | None = None
    lab_policy_sha256: str | None = None
    lab_activation_signature: str | None = None
    lab_allowed_cidrs: tuple[str, ...] = ()
    if live_scans and not simulate:
        if not i_am_authorized:
            typer.echo("olympus: direct live execution requires --i-am-authorized", err=True)
            raise typer.Exit(code=ExitCode.NOT_AUTHORIZED)
        manifest_options = bool(signed_manifest or manifest_public_key or engagement_storage)
        if lab_policy and manifest_options:
            typer.echo(
                "olympus: --lab-policy and signed-manifest authorization are mutually exclusive",
                err=True,
            )
            raise typer.Exit(code=ExitCode.NOT_AUTHORIZED)
        if lab_policy:
            from olympus.core.policy import PolicyError
            from olympus.themis.lab import load_lab_execution_profile

            try:
                lab_profile = load_lab_execution_profile(Path(lab_policy))
            except (OSError, PolicyError, ValueError) as exc:
                typer.echo(
                    safe_terminal_text(f"olympus: lab authorization refused: {exc}"), err=True
                )
                raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
            lab_policy_sha256 = lab_profile.policy_sha256
            lab_activation_signature = lab_profile.activation_signature
            lab_allowed_cidrs = lab_profile.allowed_networks
        elif not signed_manifest or not manifest_public_key or not engagement_storage:
            typer.echo(
                "olympus: direct live execution requires --signed-manifest, "
                "--manifest-public-key and --engagement-storage, or an explicit --lab-policy",
                err=True,
            )
            raise typer.Exit(code=ExitCode.NOT_AUTHORIZED)
        try:
            if not lab_policy:
                job_id, manifest_sha256 = _authorize_direct_live_run(
                    signed_manifest_path=Path(signed_manifest),
                    trusted_public_key_path=Path(manifest_public_key),
                    engagement_storage=Path(engagement_storage),
                    scanner=scanner,
                    target=target,
                    audit_path=Path(audit) if audit else None,
                )
        except (OSError, sqlite3.Error, ValueError) as exc:
            typer.echo(
                safe_terminal_text(f"olympus: signed authorization refused: {exc}"),
                err=True,
            )
            raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    try:
        result = ThemisApplicationService().run(
            ThemisRunRequest(
                scanner=scanner,
                target=target,
                target_kind=kind,
                scope_path=Path(scope),
                authorized=i_am_authorized,
                live_enabled=live_scans,
                job_id=job_id,
                manifest_sha256=manifest_sha256,
                lab_policy_sha256=lab_policy_sha256,
                lab_activation_signature=lab_activation_signature,
                lab_allowed_cidrs=lab_allowed_cidrs,
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
        raise typer.Exit(code=ExitCode.OUT_OF_SCOPE) from exc
    except (TargetResolutionError, TargetValidationError) as exc:
        typer.echo(f"olympus: invalid target: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    except AuthorizationRequiredError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.NOT_AUTHORIZED) from exc
    except UnknownScannerError as exc:
        typer.echo(f"olympus: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    except CancellationRequested as exc:
        typer.echo(f"olympus: Themis execution cancelled: {exc}", err=True)
        raise typer.Exit(code=ExitCode.CANCELLED) from exc
    except SandboxError as exc:
        typer.echo(f"olympus: scanner isolation refused: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc
    except (ThemisConfigError, OSError, TimeoutError, ValueError) as exc:
        typer.echo(f"olympus: Themis execution error: {exc}", err=True)
        raise typer.Exit(code=ExitCode.FAILED) from exc

    typer.echo(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    raise typer.Exit(code=_scan_exit_code(result))


def _scan_exit_code(result: object) -> ExitCode:
    from olympus.themis.states import ExecutionState

    state = getattr(result, "state", None)
    findings = getattr(result, "findings", [])
    if state in {ExecutionState.FAILED, ExecutionState.UNAVAILABLE}:
        return exit_code_for(RunStatus.FAILED)
    if state is ExecutionState.DISABLED:
        return ExitCode.NOT_AUTHORIZED
    if state is ExecutionState.LIVE:
        return exit_code_for(classify_run_status(len(findings)))
    return ExitCode.OK
