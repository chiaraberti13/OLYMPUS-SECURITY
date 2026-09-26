"""Tests for the branch-coverage CI gate."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "check_branch_coverage.py"


def _run_checker(tmp_path: Path, percentage: float) -> subprocess.CompletedProcess[str]:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"totals": {"percent_branches_covered": percentage}}))
    return subprocess.run(
        [sys.executable, str(CHECKER), str(report)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_branch_coverage_gate_accepts_the_configured_floor(tmp_path: Path) -> None:
    result = _run_checker(tmp_path, 75.0)
    assert result.returncode == 0
    assert "75.00%" in result.stdout


def test_branch_coverage_gate_rejects_a_result_below_the_floor(tmp_path: Path) -> None:
    result = _run_checker(tmp_path, 74.99)
    assert result.returncode == 1
    assert "below the configured threshold" in result.stderr


def test_branch_coverage_gate_requires_branch_data(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"totals": {"percent_covered": 90.0}}))
    result = subprocess.run(
        [sys.executable, str(CHECKER), str(report)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "Could not read branch coverage" in result.stderr
