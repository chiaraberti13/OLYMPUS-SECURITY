"""Executable documentation examples over the synthetic ``examples/`` dataset (DEV-G).

``examples/`` ships a synthetic "Olympus Demo Corp" dataset so a reader can run
real commands without an external target. DEV-G asks for those examples to be
*executable* in CI, not just printed in a README, so the documented commands
cannot rot silently.

These tests drive the **real CLI** (``olympus.cli.app``) against the committed
``examples/input/`` fixtures, exactly as ``examples/README.md`` documents. Every
command here is **offline**: none contacts a target, resolves DNS or opens a
socket (so no authorized lab is needed). Outputs are written under ``tmp_path``
so the repository is never polluted. Assertions pin the documented outcome —
the canonical exit code and a contract-valid result — rather than a byte-exact
match, because producer artifacts carry per-run ids and timestamps.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode

runner = CliRunner()

# Repository-relative example inputs, as documented in examples/README.md.
ROOT = Path(__file__).resolve().parents[2]
INPUT = ROOT / "examples" / "input"
OUTPUT = ROOT / "examples" / "output"


def test_apollo_test_matches_the_demo_rule_against_the_demo_event(tmp_path: Path) -> None:
    """`olympus apollo test` evaluates one rule against one event (Blue team)."""
    out = tmp_path / "alerts.json"
    result = runner.invoke(
        app,
        [
            "apollo",
            "test",
            str(INPUT / "apollo-rule.yaml"),
            str(INPUT / "apollo-event.json"),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == int(ExitCode.OK), result.output
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["schema_name"] == "olympus.apollo-alerts"
    # The encoded-PowerShell demo rule matches the demo event: exactly one alert.
    assert len(bundle["alerts"]) == 1


def test_apollo_test_metabase_example_runs(tmp_path: Path) -> None:
    out = tmp_path / "alerts.json"
    result = runner.invoke(
        app,
        [
            "apollo",
            "test",
            str(INPUT / "apollo-metabase-rule.yaml"),
            str(INPUT / "apollo-metabase-event.json"),
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == int(ExitCode.OK), result.output
    assert json.loads(out.read_text(encoding="utf-8"))["alerts"]


def test_apollo_rules_load_each_shipped_pack() -> None:
    """Every detection pack under examples/input loads and validates."""
    for pack in ("apollo-redteam", "apollo-blueteam", "apollo-ad"):
        result = runner.invoke(app, ["apollo", "rules", "--rules", str(INPUT / pack)])
        assert result.exit_code == int(ExitCode.OK), f"{pack}: {result.output}"


def test_hermes_scan_finds_the_demo_secret(tmp_path: Path) -> None:
    """`olympus hermes scan` flags the synthetic demo key (exit 1 = findings)."""
    sarif = tmp_path / "hermes.sarif"
    result = runner.invoke(
        app,
        ["hermes", "scan", str(INPUT / "hermes-demo.txt"), "--output", str(sarif)],
    )
    # A found secret is the FINDINGS outcome, not success and not an error.
    assert result.exit_code == int(ExitCode.FINDINGS), result.output
    report = json.loads(sarif.read_text(encoding="utf-8"))
    assert report["version"] == "2.1.0"
    runs = report["runs"]
    assert runs and runs[0]["results"], "expected at least one masked finding"


def test_blue_team_chain_apollo_to_minerva_triage(tmp_path: Path) -> None:
    """Chain the Blue-team flow: detect (apollo) then open an incident (minerva)."""
    alerts = tmp_path / "alerts.json"
    detect = runner.invoke(
        app,
        [
            "apollo",
            "test",
            str(INPUT / "apollo-rule.yaml"),
            str(INPUT / "apollo-event.json"),
            "--output",
            str(alerts),
        ],
    )
    assert detect.exit_code == int(ExitCode.OK), detect.output

    incident = tmp_path / "incident.json"
    triage = runner.invoke(
        app,
        [
            "minerva",
            "triage",
            str(alerts),
            "--title",
            "Olympus Demo encoded PowerShell",
            "--output",
            str(incident),
        ],
    )
    assert triage.exit_code == int(ExitCode.OK), triage.output
    doc = json.loads(incident.read_text(encoding="utf-8"))
    assert doc["schema_name"] == "olympus.incident"


def test_minerva_verify_accepts_the_committed_custody_ledger() -> None:
    """The shipped custody example verifies cleanly (chain-of-custody integrity)."""
    result = runner.invoke(app, ["minerva", "verify", str(OUTPUT / "minerva-custody.json")])
    assert result.exit_code == int(ExitCode.OK), result.output


def test_core_export_schemas_writes_the_catalogue(tmp_path: Path) -> None:
    """`olympus core export-schemas` emits the shared JSON Schemas offline."""
    out = tmp_path / "schemas"
    result = runner.invoke(app, ["core", "export-schemas", str(out)])
    assert result.exit_code == int(ExitCode.OK), result.output
    assert (out / "catalog.json").is_file()
    assert (out / "contracts").is_dir()
