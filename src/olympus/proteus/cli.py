"""Command-line interface for the Proteus module."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from olympus.core.contracts import ContractCompatibilityError
from olympus.core.execution import AuthorizationRequiredError, CancellationRequested
from olympus.core.paths import audit_log_path, output_path
from olympus.proteus.application import (
    CampaignApplicationService,
    CampaignBuildRequest,
    CampaignTokenNotFoundError,
)
from olympus.proteus.campaign import (
    export_campaign,
)
from olympus.proteus.scope import (
    ProteusOutOfScopeError,
    ProteusScopeError,
)

app = typer.Typer(
    help="Proteus — Authorized phishing simulation (training only).",
    no_args_is_help=True,
)

DEFAULT_CAMPAIGN_OUTPUT = output_path("proteus-campaign.json")
DEFAULT_TRAINING_OUTPUT = output_path("proteus-training.html")
DEFAULT_SCOPE = Path("examples/input/proteus-scope.json")
DEFAULT_LOG = audit_log_path("proteus-blocked.log")

_DISCLAIMER = (
    "AUTHORIZED USE ONLY — a phishing simulation targets real people's inboxes. Run it only "
    "with documented authorization for the engagement. Proteus never collects credentials: "
    "clickers land on a training page. Re-run with --i-am-authorized to confirm."
)


@app.command()
def campaign(
    engagement: str = typer.Option(..., "--engagement", help="Engagement name."),
    targets: Path = typer.Option(..., "--targets", help="File with one recipient email per line."),
    landing_url: str = typer.Option(..., "--landing-url", help="Base URL of the training page."),
    subject: str = typer.Option(
        "Action required: confirm your account", "--subject", help="Lure email subject."
    ),
    sender: str = typer.Option("it-support@example.com", "--sender", help="Lure sender address."),
    scope: Path = typer.Option(DEFAULT_SCOPE, "--scope", help="Authorized email-domain allowlist."),
    log: Path = typer.Option(DEFAULT_LOG, "--log", help="Out-of-scope audit log."),
    i_am_authorized: bool = typer.Option(
        False, "--i-am-authorized", help="Confirm documented authorization for the engagement."
    ),
    output: Path = typer.Option(DEFAULT_CAMPAIGN_OUTPUT, "--output", help="Campaign JSON output."),
) -> None:
    """Build an authorized simulation campaign (unique token per in-scope target)."""
    service = CampaignApplicationService()
    try:
        outcome = service.build(
            CampaignBuildRequest(
                engagement=engagement,
                targets_path=targets,
                landing_url=landing_url,
                subject=subject,
                sender=sender,
                scope_path=scope,
                audit_log_path=log,
                authorized=i_am_authorized,
            )
        )
        export_campaign(outcome.campaign, output)
    except AuthorizationRequiredError as exc:
        typer.echo(f"proteus: {_DISCLAIMER}", err=True)
        raise typer.Exit(code=4) from exc
    except ProteusOutOfScopeError as exc:
        typer.echo(f"proteus: blocked by scope: {exc}", err=True)
        raise typer.Exit(code=3) from exc
    except (ProteusScopeError, CancellationRequested, OSError, UnicodeError, ValueError) as exc:
        typer.echo(f"proteus: campaign error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    for skipped in outcome.skipped_targets:
        typer.echo(f"proteus: skipping out-of-scope target {skipped!r} (logged)", err=True)
    typer.echo(
        json.dumps(
            {
                "schema_name": outcome.campaign.SCHEMA_NAME,
                "schema_version": outcome.campaign.SCHEMA_VERSION,
                "engagement": outcome.campaign.engagement,
                "targets": len(outcome.campaign.targets),
                "skipped_targets": len(outcome.skipped_targets),
                "output": str(output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    typer.echo(
        f"proteus: campaign '{engagement}' built for "
        f"{len(outcome.campaign.targets)} target(s); {output}",
        err=True,
    )


@app.command()
def page(
    engagement: str = typer.Option(..., "--engagement", help="Engagement name for the page."),
    output: Path = typer.Option(
        DEFAULT_TRAINING_OUTPUT, "--output", help="Training-page HTML output."
    ),
) -> None:
    """Render the training/awareness page a clicker lands on (captures nothing)."""
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(CampaignApplicationService().render_page(engagement), encoding="utf-8")
    except (OSError, ValueError) as exc:
        typer.echo(f"proteus: page error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"proteus: wrote training page to {output}")


@app.command()
def email(
    campaign_file: Path = typer.Option(
        ..., "--campaign", help="Campaign JSON from `proteus campaign`."
    ),
    token: str = typer.Option(..., "--token", help="Target token to render the lure email for."),
) -> None:
    """Render the simulated lure email for one target token."""
    try:
        rendered = CampaignApplicationService().render_campaign_email(campaign_file, token)
    except (
        CampaignTokenNotFoundError,
        ContractCompatibilityError,
        OSError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        typer.echo(f"proteus: email error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(rendered)


@app.command()
def report(
    campaign_file: Path = typer.Option(
        ..., "--campaign", help="Campaign JSON from `proteus campaign`."
    ),
    clicked: list[str] = typer.Option(
        [], "--clicked", help="Token(s) recorded as clicked (repeatable)."
    ),
) -> None:
    """Summarize campaign click-through (a training metric, never secrets)."""
    try:
        summary = CampaignApplicationService().report(campaign_file, set(clicked))
    except (ContractCompatibilityError, OSError, json.JSONDecodeError, ValueError) as exc:
        typer.echo(f"proteus: report error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(json.dumps(summary, indent=2, sort_keys=True))
