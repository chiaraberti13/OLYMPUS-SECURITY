"""Command-line presentation for bounded Apollo application use cases."""

from __future__ import annotations

from pathlib import Path

import typer

from olympus.apollo.application import (
    DEFAULT_MAX_ALERTS,
    DEFAULT_MAX_EVALUATIONS,
    DEFAULT_MAX_EVENT_BYTES,
    DEFAULT_MAX_EVENTS,
    DEFAULT_MAX_STREAM_BYTES,
    ApolloApplicationService,
    ApolloRunRequest,
    ApolloTestRequest,
)
from olympus.apollo.export import export_alerts, export_alerts_ecs
from olympus.apollo.rules import DEFAULT_MAX_RULE_BYTES, DEFAULT_MAX_RULES
from olympus.core.contracts import ContractCompatibilityError
from olympus.core.execution import CancellationRequested, ExecutionPolicyError
from olympus.core.output import OutputFormat, render
from olympus.core.paths import output_path

app = typer.Typer(help="Apollo — detection engineering and testing.", no_args_is_help=True)
DEFAULT_OUTPUT = output_path("apollo-alerts.json")
DEFAULT_RULES_DIR = Path("examples/input/apollo-ad")


@app.command()
def test(
    rule: Path,
    event: Path,
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output"),
    ecs: Path | None = typer.Option(
        None, "--ecs", help="Also write alerts as newline-delimited ECS JSON for a SIEM."
    ),
    max_rule_bytes: int = typer.Option(DEFAULT_MAX_RULE_BYTES, "--max-rule-bytes"),
    max_event_bytes: int = typer.Option(DEFAULT_MAX_EVENT_BYTES, "--max-event-bytes"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Evaluate one rule against one strict, normalized Event fixture."""
    try:
        outcome = ApolloApplicationService().test(
            ApolloTestRequest(
                rule_path=rule,
                event_path=event,
                max_rule_bytes=max_rule_bytes,
                max_event_bytes=max_event_bytes,
                deadline_seconds=deadline,
                excluded_paths=(output, ecs) if ecs is not None else (output,),
            )
        )
        export_alerts(outcome.alerts, output)
        if ecs is not None:
            export_alerts_ecs(outcome.alerts, ecs)
    except (
        CancellationRequested,
        ContractCompatibilityError,
        ExecutionPolicyError,
        OSError,
        TimeoutError,
        ValueError,
    ) as exc:
        typer.echo(f"apollo: invalid input or execution limit: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"apollo: {len(outcome.alerts)} alert(s); output: {output}")


@app.command()
def run(
    rules: Path = typer.Option(DEFAULT_RULES_DIR, "--rules", help="Directory of YAML rules."),
    events: Path = typer.Option(..., "--events", help="NDJSON file: one core.Event per line."),
    output: Path = typer.Option(DEFAULT_OUTPUT, "--output", help="Alerts JSON output."),
    ecs: Path | None = typer.Option(
        None, "--ecs", help="Also write alerts as newline-delimited ECS JSON for a SIEM."
    ),
    max_rules: int = typer.Option(DEFAULT_MAX_RULES, "--max-rules"),
    max_rule_bytes: int = typer.Option(DEFAULT_MAX_RULE_BYTES, "--max-rule-bytes"),
    max_event_bytes: int = typer.Option(DEFAULT_MAX_EVENT_BYTES, "--max-event-bytes"),
    max_events: int = typer.Option(DEFAULT_MAX_EVENTS, "--max-events"),
    max_stream_bytes: int = typer.Option(DEFAULT_MAX_STREAM_BYTES, "--max-stream-bytes"),
    max_evaluations: int = typer.Option(DEFAULT_MAX_EVALUATIONS, "--max-evaluations"),
    max_alerts: int = typer.Option(DEFAULT_MAX_ALERTS, "--max-alerts"),
    deadline: float = typer.Option(600.0, "--deadline"),
) -> None:
    """Evaluate a bounded rule set against a strict streaming NDJSON event source."""
    try:
        outcome = ApolloApplicationService().run(
            ApolloRunRequest(
                rules_path=rules,
                events_path=events,
                excluded_paths=(output, ecs) if ecs is not None else (output,),
                max_rules=max_rules,
                max_rule_bytes=max_rule_bytes,
                max_event_bytes=max_event_bytes,
                max_events=max_events,
                max_stream_bytes=max_stream_bytes,
                max_evaluations=max_evaluations,
                max_alerts=max_alerts,
                deadline_seconds=deadline,
            )
        )
        export_alerts(outcome.alerts, output)
        if ecs is not None:
            export_alerts_ecs(outcome.alerts, ecs)
    except (
        CancellationRequested,
        ContractCompatibilityError,
        ExecutionPolicyError,
        OSError,
        TimeoutError,
        ValueError,
    ) as exc:
        typer.echo(f"apollo: input or execution error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    for error in outcome.input_errors:
        typer.echo(f"apollo: malformed event on line {error.line}: {error.message}", err=True)
    typer.echo(
        f"apollo: {len(outcome.rules)} rule(s) x {outcome.events} event(s) -> "
        f"{len(outcome.alerts)} alert(s); duplicates={outcome.duplicates}; {output}"
    )
    if outcome.input_errors:
        raise typer.Exit(code=2)
    if outcome.alerts:
        raise typer.Exit(code=1)


@app.command()
def rules(
    directory: Path = typer.Option(DEFAULT_RULES_DIR, "--rules", help="Directory of YAML rules."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.TABLE, "--format", help="Render as table (human) or json (machine)."
    ),
    max_rules: int = typer.Option(DEFAULT_MAX_RULES, "--max-rules"),
    max_rule_bytes: int = typer.Option(DEFAULT_MAX_RULE_BYTES, "--max-rule-bytes"),
    deadline: float = typer.Option(60.0, "--deadline"),
) -> None:
    """Load, bound and validate a non-empty rule directory."""
    try:
        rule_set = ApolloApplicationService().list_rules(
            directory,
            max_rules=max_rules,
            max_rule_bytes=max_rule_bytes,
            deadline_seconds=deadline,
        )
    except (ContractCompatibilityError, OSError, TimeoutError, ValueError) as exc:
        typer.echo(f"apollo: rule error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    records: list[dict[str, object]] = [
        {
            "rule_id": rule.rule_id,
            "event_type": rule.event_type,
            "severity": rule.severity.value,
            "mitre": ",".join(rule.mitre_attack),
            "title": rule.title,
        }
        for rule in rule_set
    ]
    columns = ["rule_id", "event_type", "severity", "mitre", "title"]
    typer.echo(render(records, columns, output_format, title=f"Apollo rules ({len(rule_set)})"))
