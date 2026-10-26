"""CLI surface for the human outcome summary of a durable job (UX-B).

``olympus themis jobs status --format table`` must render a finished job's
result as an honest outcome summary that never lets a non-clean empty result
look like "no vulnerabilities". The default ``json`` format stays the full,
machine-readable contract.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.themis.jobs import JobState, ThemisJob

runner = CliRunner()


def _job(state: JobState, result: dict[str, object] | None) -> ThemisJob:
    return ThemisJob(
        job_id="THEMIS-" + "A" * 32,
        scanner="nmap",
        target="scanme.nmap.org",
        target_kind="host",
        scope_name="engagement",
        state=state,
        authorized=True,
        attempts=1,
        max_attempts=1,
        created_at="2026-01-01T00:00:00+00:00",
        updated_at="2026-01-01T00:00:00+00:00",
        available_at="2026-01-01T00:00:00+00:00",
        result=result,
    )


def _patch_get(monkeypatch, job: ThemisJob) -> None:
    monkeypatch.setattr("olympus.themis.jobs.ThemisJobStore.get", lambda self, job_id: job)


def test_status_table_marks_unavailable_as_not_clean(monkeypatch) -> None:
    _patch_get(monkeypatch, _job(JobState.PARTIAL, {"state": "unavailable", "finding_count": 0}))
    result = runner.invoke(
        app, ["themis", "jobs", "status", "THEMIS-" + "A" * 32, "--format", "table"]
    )
    assert result.exit_code == int(ExitCode.OK)
    assert "UNAVAILABLE" in result.stdout
    assert "Empty = no vulnerabilities? NO" in result.stdout


def test_status_table_marks_clean_as_trustworthy(monkeypatch) -> None:
    _patch_get(
        monkeypatch,
        _job(
            JobState.SUCCEEDED,
            {"state": "live", "finding_count": 0, "termination": {"cause": "completed"}},
        ),
    )
    result = runner.invoke(
        app, ["themis", "jobs", "status", "THEMIS-" + "A" * 32, "--format", "table"]
    )
    assert result.exit_code == int(ExitCode.OK)
    assert "CLEAN" in result.stdout
    assert "Empty = no vulnerabilities? yes" in result.stdout


def test_status_table_without_result_says_so(monkeypatch) -> None:
    _patch_get(monkeypatch, _job(JobState.QUEUED, None))
    result = runner.invoke(
        app, ["themis", "jobs", "status", "THEMIS-" + "A" * 32, "--format", "table"]
    )
    assert result.exit_code == int(ExitCode.OK)
    assert "not produced a result yet" in result.stdout


def test_status_json_is_unchanged_default(monkeypatch) -> None:
    _patch_get(monkeypatch, _job(JobState.SUCCEEDED, {"state": "live", "finding_count": 0}))
    result = runner.invoke(app, ["themis", "jobs", "status", "THEMIS-" + "A" * 32])
    assert result.exit_code == int(ExitCode.OK)
    payload = json.loads(result.stdout)
    assert payload["job_id"] == "THEMIS-" + "A" * 32
    assert payload["state"] == "succeeded"


def test_status_rejects_bad_format(monkeypatch) -> None:
    _patch_get(monkeypatch, _job(JobState.SUCCEEDED, None))
    result = runner.invoke(
        app, ["themis", "jobs", "status", "THEMIS-" + "A" * 32, "--format", "xml"]
    )
    assert result.exit_code == int(ExitCode.USAGE)
