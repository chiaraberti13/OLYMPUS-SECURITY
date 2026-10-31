"""Contract proving the native Argus surface replaces the vendored CLI."""

from __future__ import annotations

from typer.main import get_command
from typer.testing import CliRunner

from olympus.cli import app

runner = CliRunner()


def test_argus_native_surface_covers_professional_osint_workflows() -> None:
    root = get_command(app)
    argus = root.commands["argus"]
    expected = {
        "accounts",
        "diff",
        "dns",
        "doctor",
        "email",
        "fronting",
        "investigate",
        "ip",
        "mac",
        "myip",
        "phone",
        "pipeline",
        "scan",
        "web",
        "whois",
    }
    assert expected <= set(argus.commands)


def test_legacy_argus_passthrough_is_removed() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "argus-native" not in result.output


def test_native_argus_offline_phone_path_runs() -> None:
    result = runner.invoke(app, ["argus", "phone", "--number", "+390212345678"])
    assert result.exit_code == 0, result.output
    assert "phone" in result.output.casefold()
