"""Metis IOC sweep: match a local artifact against a case's known indicators (DFIR).

The sweep extracts observables from an artifact with the SAME normalization used
to ingest indicators, so a hit is a true type+value match against stored
intelligence, not a substring coincidence. Exit 1 signals "IOC found".
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app

runner = CliRunner()


def _case_with_iocs(tmp_path: Path) -> tuple[Path, str]:
    database = tmp_path / "cases.db"
    created = runner.invoke(app, ["metis", "case", "create", str(database), "sweep case"])
    assert created.exit_code == 0, created.output
    case_id = created.stdout.strip()
    intel = tmp_path / "intel.txt"
    intel.write_text("Known bad: evil.example and 203.0.113.7", encoding="utf-8")
    ingested = runner.invoke(
        app,
        [
            "metis",
            "case",
            "ingest",
            str(database),
            case_id,
            str(intel),
            "--source",
            "threatfeed",
            "--confidence",
            "80",
        ],
    )
    assert ingested.exit_code == 0, ingested.output
    return database, case_id


def test_sweep_flags_a_known_ioc_and_exits_one(tmp_path: Path) -> None:
    database, case_id = _case_with_iocs(tmp_path)
    artifact = tmp_path / "artifact.log"
    artifact.write_text(
        "GET / from good.example\nreferrer evil.example seen in payload\n", encoding="utf-8"
    )
    result = runner.invoke(app, ["metis", "case", "sweep", str(database), case_id, str(artifact)])
    assert result.exit_code == 1, result.output  # a hit is something to act on
    report = json.loads(result.stdout)
    assert report["matched"] == 1
    hit = report["hits"][0]
    assert hit["indicator_type"] == "domain"
    assert hit["value"] == "evil.example"
    assert hit["source"] == "threatfeed"
    assert hit["confidence"] == 80


def test_sweep_of_a_clean_artifact_exits_zero(tmp_path: Path) -> None:
    database, case_id = _case_with_iocs(tmp_path)
    clean = tmp_path / "clean.log"
    clean.write_text("only good.example and 198.51.100.9 here\n", encoding="utf-8")
    result = runner.invoke(app, ["metis", "case", "sweep", str(database), case_id, str(clean)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["matched"] == 0


def test_sweep_matches_on_value_not_substring(tmp_path: Path) -> None:
    database, case_id = _case_with_iocs(tmp_path)
    # "notevil.example" contains "evil.example" as a substring but is a different
    # domain: normalization makes it its own observable, so it must NOT match.
    artifact = tmp_path / "artifact.log"
    artifact.write_text("visit notevil.example today\n", encoding="utf-8")
    result = runner.invoke(app, ["metis", "case", "sweep", str(database), case_id, str(artifact)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["matched"] == 0
