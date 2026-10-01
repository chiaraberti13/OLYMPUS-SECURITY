"""Integration test: the engagement CLI round-trips through the shared store."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app

runner = CliRunner()


def test_engagement_create_list_show_roundtrip(tmp_path: Path) -> None:
    storage = str(tmp_path)
    created = runner.invoke(
        app,
        [
            "engagement",
            "create",
            "--name",
            "ACME Oct",
            "--client",
            "ACME",
            "--include",
            "example.com",
            "--include",
            "api.example.com",
            "--exclude",
            "db.example.com",
            "--authorization-reference",
            "CONTRACT-9",
            "--storage",
            storage,
        ],
    )
    assert created.exit_code == 0, created.output
    summary = json.loads(created.stdout)
    engagement_id = summary["engagement_id"]
    assert summary["included"] == ["example.com", "api.example.com"]
    assert summary["excluded"] == ["db.example.com"]

    listed = runner.invoke(app, ["engagement", "list", "--storage", storage])
    assert listed.exit_code == 0
    assert engagement_id in listed.stdout

    shown = runner.invoke(app, ["engagement", "show", engagement_id, "--storage", storage])
    assert shown.exit_code == 0
    document = json.loads(shown.stdout)
    assert document["schema_name"] == "olympus.engagement"
    assert document["authorization_reference"] == "CONTRACT-9"

    missing = runner.invoke(app, ["engagement", "show", "ENG-NOPE", "--storage", storage])
    assert missing.exit_code == 2


def test_engagement_create_rejects_empty_scope(tmp_path: Path) -> None:
    result = runner.invoke(app, ["engagement", "create", "--name", "x", "--storage", str(tmp_path)])
    assert result.exit_code == 2
