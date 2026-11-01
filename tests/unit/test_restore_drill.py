"""WEB-J-01: offline restore drill on synthetic data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.restore_drill import run_drill

runner = CliRunner()


def test_drill_restores_snapshot_state_and_reports_loss_window(tmp_path: Path) -> None:
    report = run_drill(tmp_path / "d", engagements=7, ledger_entries=4, post_snapshot=3)
    assert report["dataset"] == {
        "synthetic": True,
        "engagements": 7,
        "ledger_entries": 4,
        "identities": 10,
        "audit_records": 50,
        "jobs": 20,
        "athena_assessments": 5,
        "finding_transitions": 20,
        "post_snapshot_writes": 3,
    }
    recovery = report["recovery_point"]
    assert isinstance(recovery, dict)
    assert recovery["restored_engagements"] == 7
    assert recovery["engagements_lost_after_snapshot"] == 3
    assert float(str(report["rto_seconds"])) >= 0
    assert "not a production" in str(report["disclaimer"])
    assert "athena" in report["stores_covered"]  # type: ignore[operator]
    assert "athena" not in report["stores_not_covered"]  # type: ignore[operator]
    assert "findings-transitions" in report["stores_covered"]  # type: ignore[operator]
    assert "findings-transitions" not in report["stores_not_covered"]  # type: ignore[operator]
    assert recovery["restored_finding_transitions"] == 20
    assert recovery["finding_transitions_lost_after_snapshot"] == 3
    assert recovery["restored_athena_assessments"] == 5
    assert recovery["athena_assessments_lost_after_snapshot"] == 3
    assert {"identity", "audit"} <= set(report["stores_covered"])  # type: ignore[call-overload]
    assert "identity" not in report["stores_not_covered"]  # type: ignore[operator]
    assert "themis-jobs" in report["stores_covered"]  # type: ignore[operator]
    assert "themis-jobs" not in report["stores_not_covered"]  # type: ignore[operator]
    assert "themis-scope" in report["stores_covered"]  # type: ignore[operator]
    assert "scope" not in report["stores_not_covered"]  # type: ignore[operator]
    assert recovery["restored_jobs"] == 20
    assert recovery["jobs_lost_after_snapshot"] == 3


def test_drill_refuses_existing_workdir_and_bad_bounds(tmp_path: Path) -> None:
    existing = tmp_path / "x"
    existing.mkdir()
    with pytest.raises(FileExistsError):
        run_drill(existing)
    with pytest.raises(ValueError):
        run_drill(tmp_path / "y", engagements=0)
    with pytest.raises(ValueError):
        run_drill(tmp_path / "z", ledger_entries=10_000)
    with pytest.raises(ValueError):
        run_drill(tmp_path / "i", identities=0)
    with pytest.raises(ValueError):
        run_drill(tmp_path / "k", jobs=0)
    with pytest.raises(ValueError):
        run_drill(tmp_path / "j", audit_records=10_000)
    with pytest.raises(ValueError):
        run_drill(tmp_path / "a", assessments=0)
    with pytest.raises(ValueError):
        run_drill(tmp_path / "t", transitions=0)
    assert not (tmp_path / "y").exists()


def test_cli_prints_report_and_fails_on_existing_dir(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "core",
            "restore-drill",
            "--workdir",
            str(tmp_path / "w"),
            "--engagements",
            "3",
            "--ledger-entries",
            "2",
            "--post-snapshot",
            "1",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["recovery_point"]["restored_engagements"] == 3
    again = runner.invoke(app, ["core", "restore-drill", "--workdir", str(tmp_path / "w")])
    assert again.exit_code != 0
