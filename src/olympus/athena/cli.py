"""Command-line interface for Athena — assessment orchestration.

The CLI contains no domain decisions: it validates input, wires real adapters
into the application use cases, and translates outcomes into the canonical
Olympus exit codes (:mod:`olympus.core.exit_codes`):

* ``0`` succeeded with no findings;
* ``1`` succeeded with findings to review;
* ``2`` invalid input or configuration;
* ``3`` authorization/scope denial;
* ``5`` partial — some jobs did not complete, so the findings are not exhaustive;
* ``6`` execution or infrastructure failure;
* ``7`` cancelled before finishing.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import typer

from olympus.athena.adapters.audit import SqliteAuditSink
from olympus.athena.adapters.report import VulcanReportRenderer
from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.athena.adapters.system import CoreIdProvider, SystemClock
from olympus.athena.application.coordinator import Coordinator, RunOutcome
from olympus.athena.application.planning import load_plan_file
from olympus.athena.application.registry import (
    SERVICE_HOSTS,
    UnknownAdapterError,
    available_adapters,
    resolve_adapters,
)
from olympus.athena.domain.assessment import AssessmentState
from olympus.athena.domain.contracts import AssessmentPlan, PlanValidationError
from olympus.athena.scope import ensure_web_target_allowed, scoped_address_policy
from olympus.core.coverage import RunStatus, classify_run_status, exit_code_for
from olympus.core.exit_codes import ExitCode
from olympus.core.fileio import read_regular_text
from olympus.core.http import UrllibHttpClient
from olympus.core.models import Finding
from olympus.vulcan.enrichment import (
    EnrichmentError,
    FindingEnrichment,
    LocalCatalogs,
    enrich_findings,
    parse_epss_response,
    parse_kev_catalog,
    prioritize,
)

app = typer.Typer(help="Athena — assessment orchestration.", no_args_is_help=True)
plan_app = typer.Typer(help="Plan validation utilities.", no_args_is_help=True)
app.add_typer(plan_app, name="plan")

_DB_NAME = "athena.db"

#: Upper bound for a local KEV/EPSS feed file read during offline enrichment.
_MAX_FEED_BYTES = 25_000_000


def _open_repository(storage: Path) -> SqliteAssessmentRepository:
    return SqliteAssessmentRepository(storage / _DB_NAME)


@plan_app.command("validate")
def plan_validate(
    path: Path = typer.Argument(..., help="Path to the assessment plan JSON file."),
) -> None:
    """Validate a plan file against the Athena contract and adapter registry."""
    try:
        plan = load_plan_file(path)
    except PlanValidationError as exc:
        typer.echo(f"athena: invalid plan: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc
    typer.echo(
        json.dumps(
            {
                "valid": True,
                "engagement_id": plan.engagement_id,
                "name": plan.name,
                "targets": len(plan.targets),
                "adapters": list(plan.adapters),
                "plan_digest": plan.digest(),
                "scope_digest": plan.scope_digest(),
            },
            indent=2,
            sort_keys=True,
        )
    )


def _exit_code_for(outcome: RunOutcome) -> int:
    """Map an assessment's terminal state onto the canonical Olympus exit codes.

    These are the same codes every other module uses (see
    :mod:`olympus.core.exit_codes`): a partial run is ``5`` rather than being
    reported as findings, and a failure is ``6`` rather than ``4``, which is
    reserved for a missing authorization flag.
    """
    if outcome.state is AssessmentState.SUCCEEDED:
        status = classify_run_status(len(outcome.findings))
        return int(exit_code_for(status))
    if outcome.state is AssessmentState.PARTIAL:
        return int(exit_code_for(RunStatus.PARTIAL))
    if outcome.state is AssessmentState.CANCELLED:
        return int(exit_code_for(RunStatus.CANCELLED))
    return int(exit_code_for(RunStatus.FAILED))


@app.command()
def run(
    path: Path = typer.Argument(..., help="Path to the assessment plan JSON file."),
    storage: Path = typer.Option(..., "--storage", help="Directory for the Athena database."),
    report: bool = typer.Option(
        False, "--report", help="Write a findings report into the storage directory."
    ),
    enrich_kev: Path | None = typer.Option(
        None,
        "--enrich-kev",
        help="Local CISA KEV catalogue JSON: overlay known-exploited status on findings (offline).",
    ),
    enrich_epss: Path | None = typer.Option(
        None,
        "--enrich-epss",
        help="Local FIRST EPSS response JSON: overlay exploit-probability on findings (offline).",
    ),
) -> None:
    """Execute an assessment plan end to end and persist its results.

    With ``--enrich-kev``/``--enrich-epss`` the findings are overlaid with CISA
    KEV and FIRST EPSS from **local** feed files (no network) and re-ordered by
    real-world risk (KEV -> EPSS -> CVSS -> severity), so the report leads with
    what an operator should fix first. The enrichment overlay is also written as
    a ``<assessment_id>.enriched.json`` sidecar next to the report.
    """
    try:
        plan = load_plan_file(path)
    except PlanValidationError as exc:
        typer.echo(f"athena: invalid plan: {exc}", err=True)
        raise typer.Exit(code=ExitCode.USAGE) from exc

    repository = _open_repository(storage)
    try:
        coordinator = _build_coordinator(plan, repository)
        try:
            outcome = coordinator.run(plan)
        except UnknownAdapterError as exc:
            typer.echo(f"athena: {exc}", err=True)
            raise typer.Exit(code=ExitCode.USAGE) from exc

        findings: list[Finding] = list(outcome.findings)
        enrichments: list[FindingEnrichment] | None = None
        if enrich_kev is not None or enrich_epss is not None:
            try:
                catalogs = _load_local_catalogs(enrich_kev, enrich_epss)
            except (EnrichmentError, OSError, ValueError) as exc:
                typer.echo(f"athena: enrichment feed error: {exc}", err=True)
                raise typer.Exit(code=ExitCode.USAGE) from exc
            enrichments = enrich_findings(findings, kev=catalogs.kev, epss=catalogs.epss)
            # Lead with real-world risk: KEV first, then EPSS, then CVSS/severity.
            findings = [finding for finding, _ in prioritize(findings, enrichments)]

        summary: dict[str, object] = {
            "assessment_id": outcome.assessment_id,
            "state": outcome.state.value,
            "findings": len(findings),
        }
        if enrichments is not None:
            summary["kev_hits"] = sum(1 for item in enrichments if item.in_kev)
        typer.echo(json.dumps(summary, indent=2, sort_keys=True))

        if report:
            _write_report(plan, outcome.assessment_id, findings, storage)
        if enrichments is not None:
            _write_enrichment(outcome.assessment_id, findings, enrichments, storage)
    finally:
        repository.close()
    raise typer.Exit(code=_exit_code_for(outcome))


def _load_local_catalogs(kev_path: Path | None, epss_path: Path | None) -> LocalCatalogs:
    """Load KEV/EPSS catalogues from local feed files for offline enrichment."""
    kev = {}
    epss = {}
    if kev_path is not None:
        kev = parse_kev_catalog(
            read_regular_text(kev_path, max_bytes=_MAX_FEED_BYTES, label="KEV catalogue")
        )
    if epss_path is not None:
        epss = parse_epss_response(
            read_regular_text(epss_path, max_bytes=_MAX_FEED_BYTES, label="EPSS feed")
        )
    return LocalCatalogs(kev=kev, epss=epss)


def _write_enrichment(
    assessment_id: str,
    findings: list[Finding],
    enrichments: list[FindingEnrichment],
    storage: Path,
) -> None:
    """Write the KEV/EPSS overlay as a risk-ordered sidecar next to the report."""
    by_id = {item.finding_id: item for item in enrichments}
    ordered = [by_id[finding.finding_id].to_dict() for finding in findings]
    target = storage / f"{assessment_id}.enriched.json"
    target.write_text(json.dumps(ordered, indent=2, sort_keys=True), encoding="utf-8")
    typer.echo(f"athena: wrote enrichment overlay to {target}", err=True)


def _build_coordinator(plan: AssessmentPlan, repository: SqliteAssessmentRepository) -> Coordinator:
    def _redirect_validator(allowed: tuple[str, ...]) -> Callable[[str], None]:
        def validate(url: str) -> None:
            # urllib invokes this before every redirect hop is followed. Re-run
            # both the scope and DNS-aware SSRF checks for the new location.
            ensure_web_target_allowed("url", url, allowed)

        return validate

    def _client(allowed: tuple[str, ...]) -> UrllibHttpClient:
        # The redirect validator authorizes each destination URL; the address
        # policy re-authorizes the host and pins the socket to the very address
        # it approved, so no DNS answer can change between check and connect.
        return UrllibHttpClient.from_config(
            redirect_validator=_redirect_validator(allowed),
            address_policy=scoped_address_policy(allowed),
        )

    # Target adapters may only reach the engagement's own hosts; the DoH/RDAP
    # adapters may only reach their fixed service hosts, which are never in the
    # engagement scope. One client each, so neither can reach the other's set.
    target_http = _client(plan.scope.allowed_domains)
    service_http = _client(SERVICE_HOSTS)
    return Coordinator(
        repository=repository,
        audit=SqliteAuditSink(repository),
        clock=SystemClock(),
        ids=CoreIdProvider(),
        resolver=lambda names: resolve_adapters(names, target_http, service_http=service_http),
    )


def _write_report(
    plan: AssessmentPlan, assessment_id: str, findings: list[Finding], storage: Path
) -> None:
    renderer = VulcanReportRenderer(plan.engagement_id)
    for fmt in plan.output.report_formats:
        content = renderer.render(findings, fmt)
        suffix = "md" if fmt == "markdown" else "json"
        target = storage / f"{assessment_id}.report.{suffix}"
        target.write_text(content, encoding="utf-8")
        typer.echo(f"athena: wrote {fmt} report to {target}", err=True)


@app.command()
def status(
    assessment_id: str = typer.Argument(..., help="Assessment ID to inspect."),
    storage: Path = typer.Option(..., "--storage", help="Directory for the Athena database."),
) -> None:
    """Print the persisted state of an assessment and its jobs."""
    repository = _open_repository(storage)
    try:
        assessment = repository.load_assessment(assessment_id)
        if assessment is None:
            typer.echo(f"athena: assessment not found: {assessment_id}", err=True)
            raise typer.Exit(code=ExitCode.USAGE)
        payload = {
            "assessment_id": assessment.assessment_id,
            "plan_id": assessment.plan_id,
            "state": assessment.state.value,
            "jobs": [
                {
                    "job_id": job.job_id,
                    "adapter": job.adapter,
                    "target": job.target_value,
                    "state": job.state.value,
                    "error_code": job.error_code,
                }
                for job in assessment.jobs
            ],
        }
    finally:
        repository.close()
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@app.command()
def cancel(
    assessment_id: str = typer.Argument(..., help="Assessment ID to cancel."),
    storage: Path = typer.Option(..., "--storage", help="Directory for the Athena database."),
) -> None:
    """Cancel a persisted, non-terminal assessment and its open jobs."""
    repository = _open_repository(storage)
    try:
        coordinator = Coordinator(
            repository=repository,
            audit=SqliteAuditSink(repository),
            clock=SystemClock(),
            ids=CoreIdProvider(),
            resolver=lambda names: {},
        )
        try:
            state = coordinator.cancel(assessment_id)
        except LookupError as exc:
            typer.echo(f"athena: {exc}", err=True)
            raise typer.Exit(code=ExitCode.USAGE) from exc
    finally:
        repository.close()
    typer.echo(json.dumps({"assessment_id": assessment_id, "state": state.value}, sort_keys=True))


@app.command()
def recover(
    storage: Path = typer.Option(..., "--storage", help="Directory for the Athena database."),
) -> None:
    """Settle assessments left running after a crash (interrupted jobs fail closed)."""
    repository = _open_repository(storage)
    try:
        coordinator = Coordinator(
            repository=repository,
            audit=SqliteAuditSink(repository),
            clock=SystemClock(),
            ids=CoreIdProvider(),
            resolver=lambda names: {},
        )
        settled = coordinator.recover()
    finally:
        repository.close()
    typer.echo(json.dumps({"recovered": settled}, sort_keys=True))


@app.command()
def adapters() -> None:
    """List the assessment adapters available in the closed registry."""
    typer.echo(json.dumps({"adapters": list(available_adapters())}, sort_keys=True))
