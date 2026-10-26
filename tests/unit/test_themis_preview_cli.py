"""CLI surface for the single-run safety preview (ROADMAP ``UX-B``).

``olympus themis preview`` only *describes* a planned scan: it must run nothing,
work offline, be machine-readable in JSON, and carry an honest exit code when
the scope would block the launch. These tests pin that behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode

runner = CliRunner()

_SCOPE = json.dumps(
    {
        "schema_name": "olympus.themis-scope",
        "schema_version": "1.0.0",
        "allowed_hosts": ["scanme.nmap.org"],
        "allowed_domains": ["example.com"],
        "allowed_cidrs": ["10.0.0.0/24"],
    }
)


def _scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(_SCOPE, encoding="utf-8")
    return path


def test_preview_in_scope_ip_exits_ok_as_json(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)
    result = runner.invoke(
        app,
        [
            "themis",
            "preview",
            "nmap",
            "--target",
            "10.0.0.5",
            "--scope",
            str(scope),
            "--i-am-authorized",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == int(ExitCode.OK)
    data = json.loads(result.stdout)
    assert data["scope_decision"] == "in_scope"
    assert data["risk"] == "active"
    assert data["requires_confirmation"] is True
    assert data["external_tool"] == "nmap"
    assert data["blocks_launch"] is False


def test_preview_out_of_scope_exits_out_of_scope(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)
    result = runner.invoke(
        app,
        [
            "themis",
            "preview",
            "sqlmap",
            "--target",
            "not-authorized.test",
            "--scope",
            str(scope),
            "--i-am-authorized",
        ],
    )
    assert result.exit_code == int(ExitCode.OUT_OF_SCOPE)
    assert "OUT_OF_SCOPE" in result.stdout
    assert "INTRUSIVE" in result.stdout


def test_preview_simulation_needs_no_authorization(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)
    result = runner.invoke(
        app,
        [
            "themis",
            "preview",
            "sqlmap",
            "--target",
            "10.0.0.5",
            "--scope",
            str(scope),
            "--simulate",
            "--format",
            "json",
        ],
    )
    assert result.exit_code == int(ExitCode.OK)
    data = json.loads(result.stdout)
    assert data["simulate"] is True
    assert data["requires_confirmation"] is False
    assert "Simulation mode" in data["authorization_detail"]


def test_preview_rejects_bad_kind(tmp_path: Path) -> None:
    scope = _scope_file(tmp_path)
    result = runner.invoke(
        app,
        [
            "themis",
            "preview",
            "nmap",
            "--target",
            "10.0.0.5",
            "--kind",
            "bogus",
            "--scope",
            str(scope),
        ],
    )
    assert result.exit_code == int(ExitCode.USAGE)


def test_preview_rejects_missing_scope_file(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "themis",
            "preview",
            "nmap",
            "--target",
            "10.0.0.5",
            "--scope",
            str(tmp_path / "does-not-exist.json"),
        ],
    )
    assert result.exit_code == int(ExitCode.USAGE)
