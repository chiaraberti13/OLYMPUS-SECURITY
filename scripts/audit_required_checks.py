"""Audit workflow checks, effective GitHub rules and runs for one exact SHA."""

from __future__ import annotations

import argparse
import itertools
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REQUIRED_WORKFLOW_JOBS = {
    ".github/workflows/ci.yml": (
        "quality",
        "tests",
        "coverage",
        "mutation",
        "posix-sandbox",
        "portable-smoke",
        "package-smoke",
        "native-container",
        "dependency-audit",
        "secret-scan",
    ),
    ".github/workflows/codeql.yml": ("analyze",),
    ".github/workflows/docker-build.yml": ("gate",),
}
MATRIX_EXPRESSION = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")


class AuditInputError(ValueError):
    """Raised when an input cannot support a fail-closed audit."""


@dataclass(frozen=True)
class CheckRow:
    """One expected or configured merge check and its effective state."""

    name: str
    source: str | None
    defined: bool
    executed: bool
    successful: bool
    required: bool
    terminal_failure: bool


@dataclass(frozen=True)
class AuditResult:
    """Complete merge-gate verdict for one immutable commit."""

    sha: str
    strict: bool
    rows: tuple[CheckRow, ...]

    @property
    def success(self) -> bool:
        return self.strict and all(
            row.defined and row.executed and row.successful and row.required for row in self.rows
        )

    @property
    def terminal_failure(self) -> bool:
        """Whether a required check has already reached a failing terminal state."""

        return any(row.terminal_failure for row in self.rows)


def _matrix_rows(matrix: object, *, source: str) -> list[dict[str, object]]:
    if matrix is None:
        return [{}]
    if not isinstance(matrix, dict):
        raise AuditInputError(f"{source}: strategy.matrix must be a mapping")

    axes: dict[str, list[object]] = {}
    for key, values in matrix.items():
        if key in {"include", "exclude"}:
            continue
        if not isinstance(key, str) or not isinstance(values, list) or not values:
            raise AuditInputError(f"{source}: matrix axis {key!r} must be a non-empty list")
        axes[key] = values

    rows = [
        dict(zip(axes, values, strict=True))
        for values in itertools.product(*(axes[key] for key in axes))
    ]
    include = matrix.get("include", [])
    if not isinstance(include, list) or not all(isinstance(row, dict) for row in include):
        raise AuditInputError(f"{source}: matrix.include must contain mappings")
    if not axes:
        rows = [dict(row) for row in include]
    else:
        rows.extend(dict(row) for row in include)

    exclude = matrix.get("exclude", [])
    if not isinstance(exclude, list) or not all(isinstance(row, dict) for row in exclude):
        raise AuditInputError(f"{source}: matrix.exclude must contain mappings")
    for excluded in exclude:
        rows = [
            row for row in rows if not all(row.get(key) == value for key, value in excluded.items())
        ]
    return rows or [{}]


def _render_job_name(template: str, matrix: dict[str, object], *, source: str) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in matrix:
            raise AuditInputError(f"{source}: job name references missing matrix axis {key!r}")
        return str(matrix[key])

    rendered = MATRIX_EXPRESSION.sub(replace, template)
    if "${{" in rendered:
        raise AuditInputError(f"{source}: required job name contains an unsupported expression")
    return rendered


def expected_checks(repository_root: Path) -> dict[str, str]:
    """Derive check contexts from the job names and matrices in real workflows."""

    checks: dict[str, str] = {}
    for relative_path, job_ids in REQUIRED_WORKFLOW_JOBS.items():
        workflow_path = repository_root / relative_path
        try:
            workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise AuditInputError(f"cannot read workflow {relative_path}: {exc}") from exc
        jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
        if not isinstance(jobs, dict):
            raise AuditInputError(f"{relative_path}: jobs must be a mapping")
        for job_id in job_ids:
            source = f"{relative_path}#{job_id}"
            job = jobs.get(job_id)
            if not isinstance(job, dict):
                raise AuditInputError(f"{source}: required job is missing")
            template = job.get("name")
            if not isinstance(template, str) or not template.strip():
                raise AuditInputError(f"{source}: required job needs an explicit name")
            strategy = job.get("strategy", {})
            if not isinstance(strategy, dict):
                raise AuditInputError(f"{source}: strategy must be a mapping")
            for matrix in _matrix_rows(strategy.get("matrix"), source=source):
                name = _render_job_name(template, matrix, source=source)
                previous = checks.setdefault(name, source)
                if previous != source:
                    raise AuditInputError(
                        f"duplicate required check name {name!r}: {previous} and {source}"
                    )
    return checks


def _effective_rules(document: object) -> list[dict[str, Any]]:
    if isinstance(document, list) and all(isinstance(rule, dict) for rule in document):
        return document
    if isinstance(document, dict) and isinstance(document.get("rules"), list):
        rules = document["rules"]
        if all(isinstance(rule, dict) for rule in rules):
            return rules
    raise AuditInputError("rules JSON must be an effective-rules list or a ruleset object")


def _required_checks(document: object) -> tuple[bool, dict[str, set[int | None]]]:
    strict = False
    required: dict[str, set[int | None]] = {}
    for rule in _effective_rules(document):
        if rule.get("type") != "required_status_checks":
            continue
        parameters = rule.get("parameters")
        if not isinstance(parameters, dict):
            raise AuditInputError("required_status_checks.parameters must be a mapping")
        strict |= parameters.get("strict_required_status_checks_policy") is True
        configured = parameters.get("required_status_checks")
        if not isinstance(configured, list):
            raise AuditInputError("required_status_checks must be a list")
        for check in configured:
            if not isinstance(check, dict) or not isinstance(check.get("context"), str):
                raise AuditInputError("every required check needs a string context")
            integration_id = check.get("integration_id")
            if integration_id is not None and not isinstance(integration_id, int):
                raise AuditInputError("integration_id must be an integer or null")
            required.setdefault(check["context"], set()).add(integration_id)
    return strict, required


def audit(
    *,
    sha: str,
    rules_document: object,
    checks_document: object,
    repository_root: Path,
) -> AuditResult:
    """Return a fail-closed verdict for workflow definition, rules and check runs."""

    sources = expected_checks(repository_root)
    strict, required = _required_checks(rules_document)
    if not isinstance(checks_document, dict):
        raise AuditInputError("check-runs JSON must be a mapping")
    runs = checks_document.get("check_runs")
    total = checks_document.get("total_count")
    if not isinstance(runs, list) or not isinstance(total, int):
        raise AuditInputError("check-runs JSON needs total_count and check_runs")
    if len(runs) != total:
        raise AuditInputError("incomplete check-runs response; retrieve all pages")

    sha_runs = [run for run in runs if isinstance(run, dict) and run.get("head_sha") == sha]
    rows: list[CheckRow] = []
    for name in sorted(sources.keys() | required.keys()):
        matching = [run for run in sha_runs if run.get("name") == name]
        required_sources = required.get(name, set())
        source_success = {
            source_id: any(
                run.get("conclusion") == "success"
                and (
                    source_id is None
                    or (isinstance(run.get("app"), dict) and run["app"].get("id") == source_id)
                )
                for run in matching
            )
            for source_id in required_sources
        }
        successful = bool(required_sources) and all(source_success.values())
        terminal_failure = any(
            not source_success[source_id]
            and any(
                run.get("status") == "completed"
                and run.get("conclusion") not in {None, "success"}
                and (
                    source_id is None
                    or (isinstance(run.get("app"), dict) and run["app"].get("id") == source_id)
                )
                for run in matching
            )
            for source_id in required_sources
        )
        rows.append(
            CheckRow(
                name=name,
                source=sources.get(name),
                defined=name in sources,
                executed=bool(matching),
                successful=successful,
                required=bool(required_sources),
                terminal_failure=terminal_failure,
            )
        )
    return AuditResult(sha=sha, strict=strict, rows=tuple(rows))


def render_markdown(result: AuditResult) -> str:
    """Render the canonical present/executed/required evidence table."""

    lines = [
        f"Audited SHA: `{result.sha}`",
        "",
        "| Check | Workflow source | Defined | Executed on this SHA | "
        "Successful | Required | Terminal failure |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in result.rows:
        source = f"`{row.source}`" if row.source else "—"
        values = (row.defined, row.executed, row.successful, row.required)
        states = ["yes" if value else "**no**" for value in values]
        states.append("**yes**" if row.terminal_failure else "no")
        lines.append(f"| {row.name} | {source} | {' | '.join(states)} |")
    verdict = "PASS" if result.success else "FAIL"
    lines.extend(
        (
            "",
            f"Strict branch freshness: `{str(result.strict).lower()}`",
            "",
            f"Verdict: **{verdict}**",
            "",
        )
    )
    return "\n".join(lines)


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditInputError(f"cannot read {path}: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sha", nargs="?", help="Full commit SHA")
    parser.add_argument("rules", nargs="?", type=Path, help="Effective rules or ruleset JSON")
    parser.add_argument("checks", nargs="?", type=Path, help="Check-runs JSON for the SHA")
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Repository checkout containing .github/workflows",
    )
    parser.add_argument("--output", type=Path, help="Also write the Markdown table here")
    parser.add_argument(
        "--verify-workflows",
        action="store_true",
        help="Validate and print the required contexts derived from workflows",
    )
    args = parser.parse_args()

    try:
        if args.verify_workflows:
            if any(value is not None for value in (args.sha, args.rules, args.checks)):
                parser.error("--verify-workflows does not accept SHA/rules/checks")
            for name, source in sorted(expected_checks(args.repository_root).items()):
                print(f"{name}\t{source}")
            return 0
        if args.sha is None or args.rules is None or args.checks is None:
            parser.error("SHA, rules and checks are required unless --verify-workflows is used")
        result = audit(
            sha=args.sha,
            rules_document=_read_json(args.rules),
            checks_document=_read_json(args.checks),
            repository_root=args.repository_root,
        )
        rendered = render_markdown(result)
        print(rendered, end="")
        if args.output is not None:
            args.output.write_text(rendered, encoding="utf-8")
        if result.success:
            return 0
        return 3 if result.terminal_failure else 1
    except AuditInputError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
