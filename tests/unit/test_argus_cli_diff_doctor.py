"""CLI parity tests for the offline Argus diff and diagnostic services."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.argus.assets import export_assets
from olympus.cli import app
from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset

runner = CliRunner()


def _snapshot(path: Path, *hostnames: str) -> Path:
    export_assets(
        [
            Asset(asset_type=AssetType.HOST, hostname=hostname, source=Source.ARGUS)
            for hostname in hostnames
        ],
        path,
    )
    return path


def test_diff_cli_returns_validated_changes(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "diff",
            str(_snapshot(tmp_path / "before.json", "old.example")),
            str(_snapshot(tmp_path / "after.json", "new.example")),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["added"] == ["new.example"]
    assert payload["removed"] == ["old.example"]


def test_diff_cli_rejects_non_snapshot_json(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{}", encoding="utf-8")

    result = runner.invoke(app, ["argus", "diff", str(invalid), str(invalid)])

    assert result.exit_code == 2
    assert "diff error" in result.output


def test_doctor_cli_is_json_and_secret_safe(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OLYMPUS_NUMVERIFY_KEY", "never-echo-this")

    result = runner.invoke(app, ["argus", "doctor"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["title"] == "argus doctor"
    assert "never-echo-this" not in result.output
