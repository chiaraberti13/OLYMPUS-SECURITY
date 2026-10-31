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


def test_engagement_create_twice_does_not_lose_the_first(tmp_path: Path) -> None:
    """Regression: a per-process new_id() restart must not overwrite an engagement."""
    import olympus.core.ids as ids

    storage = str(tmp_path)

    def create(name: str, target: str) -> str:
        result = runner.invoke(
            app,
            ["engagement", "create", "--name", name, "--include", target, "--storage", storage],
        )
        assert result.exit_code == 0, result.output
        return str(json.loads(result.stdout)["engagement_id"])

    first_id = create("First Client", "127.0.0.1")
    # Simulate a brand-new process: the id counter restarts at 1 (the real bug).
    ids._default_generator = ids.IdGenerator()
    second_id = create("Second Client", "10.0.0.1")

    assert first_id != second_id  # the second create was allocated a fresh id
    listed = runner.invoke(app, ["engagement", "list", "--storage", storage])
    names = {item["name"] for item in json.loads(listed.stdout)}
    assert names == {"First Client", "Second Client"}  # neither was lost


def test_engagement_create_rejects_empty_scope(tmp_path: Path) -> None:
    result = runner.invoke(app, ["engagement", "create", "--name", "x", "--storage", str(tmp_path)])
    assert result.exit_code == 2
