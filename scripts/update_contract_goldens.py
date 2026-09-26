"""Generate deterministic golden files for Olympus public interfaces."""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from typer.testing import CliRunner

from olympus.aegis.api import ApiSettings, create_app
from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.athena.domain.assessment import Assessment, Job
from olympus.athena.domain.contracts import AssessmentResult, load_plan
from olympus.cli import app
from olympus.core import models as core_models
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.models import Alert, Asset, Finding
from olympus.vulcan.report import build_report_model, render_report_markdown

GOLDEN_NAMES = (
    "cli-json.json",
    "cli-ndjson.ndjson",
    "openapi.json",
    "sqlite.json",
    "report.json",
    "report.md",
)

_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_TABLE_INFO_QUERIES = {
    "assessments": "PRAGMA table_info(assessments)",
    "audit": "PRAGMA table_info(audit)",
    "jobs": "PRAGMA table_info(jobs)",
    "plans": "PRAGMA table_info(plans)",
    "results": "PRAGMA table_info(results)",
}
_TABLE_ROWS_QUERIES = {
    "assessments": "SELECT * FROM assessments ORDER BY rowid",
    "audit": "SELECT * FROM audit ORDER BY rowid",
    "jobs": "SELECT * FROM jobs ORDER BY rowid",
    "plans": "SELECT * FROM plans ORDER BY rowid",
    "results": "SELECT * FROM results ORDER BY rowid",
}


def _json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _finding() -> Finding:
    return Finding(
        finding_id="FND-GOLDEN-1",
        asset_id="AST-GOLDEN-1",
        source=Source.ARTEMIS,
        title="Reflected script injection",
        description="Untrusted input is reflected into an HTML response.",
        severity=Severity.HIGH,
        cvss=8.2,
        evidence=["EVD-GOLDEN-1"],
        remediation="Apply contextual output encoding.",
        first_seen=_NOW,
        last_seen=_NOW,
        references=["https://owasp.org/www-community/attacks/xss/"],
    )


def _cli_json(root: Path) -> str:
    source = root / "findings.json"
    atomic_write_text(source, _json([_finding().model_dump(mode="json")]))
    result = CliRunner().invoke(
        app, ["vulcan", "rank", "--findings", str(source), "--format", "json"]
    )
    if result.exit_code != 0:
        raise RuntimeError(f"JSON CLI golden failed: {result.output}")
    return _json(json.loads(result.stdout))


def _cli_ndjson(root: Path) -> str:
    source = root / "access.log"
    output = root / "events.ndjson"
    atomic_write_text(
        source,
        '192.0.2.10 - - [02/Jan/2026:03:04:05 +0000] "GET /login?next=%2F HTTP/1.1" '
        '401 123 "-" "GoldenClient/1.0"\n',
    )
    original_new_id: Callable[[str], str] = core_models.new_id
    core_models.new_id = lambda _prefix: "EVT-GOLDEN-1"
    try:
        result = CliRunner().invoke(
            app,
            [
                "apollo",
                "ingest",
                "--input",
                str(source),
                "--output",
                str(output),
                "--format",
                "access-log",
                "--source",
                "manual",
            ],
        )
    finally:
        core_models.new_id = original_new_id
    if result.exit_code != 0:
        raise RuntimeError(f"NDJSON CLI golden failed: {result.output}")
    return output.read_text(encoding="utf-8")


def _openapi(root: Path) -> str:
    scope_directory = root / "scopes"
    scope_directory.mkdir()
    api = create_app(
        ApiSettings(
            database=root / "aegis.sqlite3",
            scope_directory=scope_directory,
            api_key="golden-contract-key-32-characters",
        )
    )
    return _json(api.openapi())


def _sqlite(root: Path) -> str:
    database = root / "athena.sqlite3"
    repository = SqliteAssessmentRepository(database)
    plan = load_plan(
        {
            "engagement_id": "ENG-GOLDEN",
            "name": "Golden assessment",
            "targets": [{"kind": "domain", "value": "example.test"}],
            "adapters": ["dns"],
            "scope": {"allowed_domains": ["example.test"]},
            "authorization": {
                "engagement_id": "ENG-GOLDEN",
                "approval_reference": "AUTH-GOLDEN",
                "confirmed": True,
            },
        }
    )
    plan_id = repository.save_plan(plan)
    job = Job(
        job_id="JOB-GOLDEN-1",
        adapter="dns",
        target_kind="domain",
        target_value="example.test",
    )
    repository.save_assessment(
        Assessment(assessment_id="ASM-GOLDEN-1", plan_id=plan_id, jobs=(job,))
    )
    result = AssessmentResult(
        assessment_id="ASM-GOLDEN-1",
        job=job.to_contract("ASM-GOLDEN-1").model_copy(update={"state": "succeeded"}),
    )
    repository.save_result("ASM-GOLDEN-1", "JOB-GOLDEN-1", result.canonical_json())
    repository.append_audit(
        "ASM-GOLDEN-1",
        0,
        _NOW.isoformat(),
        "assessment.created",
        "planned",
        None,
        '{"actor":"golden-test"}',
    )
    repository.close()

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        tables: dict[str, object] = {}
        definitions = connection.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        for definition in definitions:
            name = str(definition["name"])
            if name not in _TABLE_INFO_QUERIES:
                raise RuntimeError(f"unexpected Athena table: {name}")
            columns = [dict(row) for row in connection.execute(_TABLE_INFO_QUERIES[name])]
            rows = [dict(row) for row in connection.execute(_TABLE_ROWS_QUERIES[name])]
            for row in rows:
                for field in ("document", "metadata"):
                    if field in row:
                        row[field] = json.loads(str(row[field]))
            tables[name] = {
                "columns": columns,
                "create_sql": definition["sql"],
                "rows": rows,
            }
    finally:
        connection.close()
    return _json(
        {"schema_name": "olympus.athena-sqlite", "schema_version": "1.0.0", "tables": tables}
    )


def _report() -> tuple[str, str]:
    asset = Asset(
        asset_id="AST-GOLDEN-1",
        asset_type=AssetType.DOMAIN,
        hostname="example.test",
        source=Source.ARGUS,
        first_seen=_NOW,
        last_seen=_NOW,
    )
    alert = Alert(
        alert_id="ALT-GOLDEN-1",
        event_id="EVT-GOLDEN-1",
        title="Suspicious login sequence",
        source=Source.APOLLO,
        severity=Severity.MEDIUM,
        rule_id="APL-GOLDEN-1",
        mitre_attack=["T1110"],
        created_at=_NOW,
    )
    report = build_report_model("ENG-GOLDEN", [asset], [_finding()], [alert], generated_at=_NOW)
    return _json(report.model_dump(mode="json")), render_report_markdown(report)


def generate_goldens(root: Path) -> dict[str, str]:
    """Return every public-interface golden using isolated temporary state."""
    root.mkdir(parents=True, exist_ok=True)
    report_json, report_markdown = _report()
    generated = {
        "cli-json.json": _cli_json(root),
        "cli-ndjson.ndjson": _cli_ndjson(root),
        "openapi.json": _openapi(root),
        "sqlite.json": _sqlite(root),
        "report.json": report_json,
        "report.md": report_markdown,
    }
    if tuple(sorted(generated)) != tuple(sorted(GOLDEN_NAMES)):
        raise RuntimeError("golden generator and declared names differ")
    return generated


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("tests/fixtures/contracts"))
    args = parser.parse_args()
    with TemporaryDirectory(prefix="olympus-goldens-") as temporary:
        generated = generate_goldens(Path(temporary))
    for name, content in generated.items():
        atomic_write_text(args.output / name, content)
    print(f"Wrote {len(generated)} contract goldens to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
