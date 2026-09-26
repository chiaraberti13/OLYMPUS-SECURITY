"""Smoke tests for the unified CLI wiring."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from olympus import __version__
from olympus.cli import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_export_schemas_outputs_valid_json() -> None:
    result = runner.invoke(app, ["core", "export-schemas"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "olympus.athena.plan" in payload
    assert "olympus.athena.result" in payload
    assert "olympus.asset" in payload
    assert "olympus.finding" in payload
    assert "olympus.event" in payload
    assert "olympus.evidence" in payload
    assert "olympus.alert" in payload
    assert "olympus.incident" in payload
    assert "olympus.observation" in payload
    assert "olympus.scan-job" in payload
    assert "olympus.security-report" in payload


def test_no_module_exposes_a_demo_command() -> None:
    # Every module ships real, working tools — no demo scaffolding anywhere.
    for tool in ("argus", "helios", "artemis", "proteus", "hermes", "apollo", "minerva", "vulcan"):
        result = runner.invoke(app, [tool, "--help"])
        assert result.exit_code == 0, tool
        assert "demo" not in result.stdout, f"{tool} still exposes a demo command"


def test_proteus_and_vulcan_are_real_tools() -> None:
    # Both were scaffolds ("not implemented"); they now expose real commands.
    assert "campaign" in runner.invoke(app, ["proteus", "--help"]).stdout
    assert "report" in runner.invoke(app, ["vulcan", "--help"]).stdout


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_exit_codes_are_canonical() -> None:
    from olympus.core.exit_codes import ExitCode

    assert (ExitCode.OK, ExitCode.USAGE, ExitCode.OUT_OF_SCOPE, ExitCode.NOT_AUTHORIZED) == (
        0,
        2,
        3,
        4,
    )


def test_export_schemas_writes_directory(tmp_path) -> None:  # type: ignore[no-untyped-def]
    out = tmp_path / "schemas-dir"
    result = runner.invoke(app, ["core", "export-schemas", str(out)])
    assert result.exit_code == 0
    payload = json.loads((out / "schemas.json").read_text())
    assert "olympus.asset" in payload
    catalog = json.loads((out / "catalog.json").read_text())
    asset = next(entry for entry in catalog["contracts"] if entry["name"] == "olympus.asset")
    assert asset["schema_version"] == "1.0.0"
    assert (out / asset["path"]).is_file()


def test_config_validate_reports_redacted_effective_values(tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = tmp_path / "olympus.toml"
    cfg.write_text(
        '[http]\ntimeout = 12.0\n[service]\napi_token = "must-not-leak"\n',
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["config", "validate", "--file", str(cfg)],
        env={"OLYMPUS_HTTP_RETRIES": "4"},
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "valid"
    assert payload["effective"]["http"]["timeout"] == 12.0
    assert payload["effective"]["http"]["retries"] == 4
    assert payload["effective"]["service"]["api_token"] == "[REDACTED]"  # noqa: S105
    assert "must-not-leak" not in result.stdout


def test_config_validate_fails_closed_without_traceback(tmp_path) -> None:  # type: ignore[no-untyped-def]
    cfg = tmp_path / "invalid.toml"
    cfg.write_text("[http]\nretries = 999\n", encoding="utf-8")

    result = runner.invoke(app, ["config", "validate", "--file", str(cfg)])

    assert result.exit_code == 2
    assert "invalid configuration" in result.output
    assert "Traceback" not in result.output
