"""CLI surface for Smart Scan proposals (ROADMAP ``WEB-F``).

``olympus themis smart-scan`` only *proposes* a pipeline: it must be
machine-readable, deterministic and never execute a scanner. These tests pin
that, plus the honest exit code when a target is out of an engagement's scope.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode

runner = CliRunner()


@dataclass(frozen=True)
class _FakeCapability:
    name: str
    ready: bool


def _force_ready(monkeypatch, names: set[str]) -> None:
    """Make the capability inventory report exactly ``names`` as ready."""
    from olympus.integrations import scanners

    inventory = [_FakeCapability(spec.name, spec.name in names) for spec in scanners.REGISTRY]
    monkeypatch.setattr("olympus.integrations.capabilities.inventory", lambda *a, **k: inventory)


def test_smart_scan_json_is_machine_readable_and_deterministic(monkeypatch) -> None:
    _force_ready(monkeypatch, {"subfinder", "nmap", "nuclei"})
    args = [
        "themis",
        "smart-scan",
        "--objective",
        "full",
        "--target",
        "example.com",
        "--format",
        "json",
    ]
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    document = json.loads(first.output)
    assert document["objective"] == "full"
    assert len(document["digest"]) == 64
    assert document["in_scope"] is True
    # Reproducible: the same inputs yield the same digest.
    second = runner.invoke(app, args)
    assert json.loads(second.output)["digest"] == document["digest"]


def test_smart_scan_table_is_the_default(monkeypatch) -> None:
    _force_ready(monkeypatch, {"subfinder"})
    result = runner.invoke(
        app, ["themis", "smart-scan", "--objective", "recon", "--target", "example.com"]
    )
    assert result.exit_code == 0, result.output
    assert "Smart Scan proposal" in result.output
    assert "subfinder" in result.output
    assert "nothing runs until you launch" in result.output.lower()


def test_smart_scan_rejects_an_unknown_objective() -> None:
    result = runner.invoke(
        app, ["themis", "smart-scan", "--objective", "bogus", "--target", "example.com"]
    )
    assert result.exit_code == int(ExitCode.USAGE)
    assert "unknown objective" in result.output


def test_smart_scan_rejects_an_unknown_risk_ceiling() -> None:
    result = runner.invoke(
        app,
        ["themis", "smart-scan", "--objective", "recon", "--target", "x", "--max-risk", "nuclear"],
    )
    assert result.exit_code == int(ExitCode.USAGE)
    assert "risk ceiling" in result.output


def test_smart_scan_engagement_requires_storage() -> None:
    result = runner.invoke(
        app,
        [
            "themis",
            "smart-scan",
            "--objective",
            "recon",
            "--target",
            "x",
            "--engagement",
            "ENG-2026-00001",
        ],
    )
    assert result.exit_code == int(ExitCode.USAGE)
    assert "--engagement-storage" in result.output


def test_smart_scan_out_of_scope_target_exits_out_of_scope(monkeypatch, tmp_path: Path) -> None:
    from olympus.core.models import Engagement, EngagementScope
    from olympus.engagements.store import ENGAGEMENTS_DB_NAME, SqliteEngagementStore

    _force_ready(monkeypatch, {"subfinder", "nmap"})
    engagement = Engagement(
        name="Acme",
        client="Acme",
        scope=EngagementScope(included=("acme.test",), excluded=()),
    )
    store = SqliteEngagementStore(tmp_path / ENGAGEMENTS_DB_NAME)
    try:
        store.save(engagement)
    finally:
        store.close()

    result = runner.invoke(
        app,
        [
            "themis",
            "smart-scan",
            "--objective",
            "full",
            "--target",
            "evil.example",
            "--target-kind",
            "domain",
            "--engagement-storage",
            str(tmp_path),
            "--engagement",
            engagement.engagement_id,
        ],
    )
    assert result.exit_code == int(ExitCode.OUT_OF_SCOPE), result.output
    assert "outside the engagement" in result.output


def test_smart_scan_intrusive_ceiling_is_opt_in(monkeypatch) -> None:
    _force_ready(monkeypatch, {"subfinder", "sqlmap"})
    # Default (active) ceiling: the intrusive web tool is not proposed.
    active = runner.invoke(
        app,
        [
            "themis",
            "smart-scan",
            "--objective",
            "web-app",
            "--target",
            "example.com",
            "--format",
            "json",
        ],
    )
    assert active.exit_code == 0, active.output
    assert all(stage["scanner"] != "sqlmap" for stage in json.loads(active.output)["stages"])
    # Explicit intrusive ceiling: sqlmap is now eligible.
    intrusive = runner.invoke(
        app,
        [
            "themis",
            "smart-scan",
            "--objective",
            "web-app",
            "--target",
            "example.com",
            "--max-risk",
            "intrusive",
            "--format",
            "json",
        ],
    )
    assert intrusive.exit_code == 0, intrusive.output
    assert any(stage["scanner"] == "sqlmap" for stage in json.loads(intrusive.output)["stages"])
