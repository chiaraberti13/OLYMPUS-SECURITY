"""CLI-level tests for `olympus argus investigate`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.cli import app
from olympus.core.http import HttpResponse

runner = CliRunner()


class _Resolver:
    def resolve(self, name: str, record_type: str) -> list[str]:
        return ["203.0.113.10"] if record_type == "A" else []


class _CtClient:
    def discover(self, domain: str) -> list[str]:
        return [f"mail.{domain}"]


class _Http:
    @classmethod
    def from_config(
        cls,
        *,
        min_interval: object = None,
        redirect_validator: object = None,
        address_policy: object = None,
    ) -> _Http:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        return HttpResponse(status_code=404, headers={}, body="")


def _patch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "DnspythonResolver", _Resolver)
    monkeypatch.setattr(argus_cli, "CrtShClient", _CtClient)
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _Http)


def _domain_scope(tmp_path: Path, *domains: str) -> Path:
    path = tmp_path / "domain-scope.json"
    path.write_text(
        json.dumps({"engagement": "test", "allowed_domains": list(domains)}),
        encoding="utf-8",
    )
    return path


def test_investigate_requires_authorization() -> None:
    result = runner.invoke(
        app, ["argus", "investigate", "--seed-type", "email", "--seed-value", "a@b.example"]
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_investigate_domain_builds_graph(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch)
    out = tmp_path / "graph.json"
    mmd = tmp_path / "graph.mmd"
    result = runner.invoke(
        app,
        [
            "argus",
            "investigate",
            "--seed-type",
            "domain",
            "--seed-value",
            "x.example",
            "--i-am-authorized",
            "--depth",
            "1",
            "--output",
            str(out),
            "--mermaid",
            str(mmd),
            "--domain-scope",
            str(_domain_scope(tmp_path, "x.example")),
            "--log",
            str(tmp_path / "log"),
        ],
    )
    assert result.exit_code == 0, result.output
    graph = json.loads(out.read_text(encoding="utf-8"))
    values = {e["value"] for e in graph["entities"]}
    assert "x.example" in values
    assert "203.0.113.10" in values  # DNS transform
    assert "mail.x.example" in values  # CT transform
    assert mmd.exists()
    assert (tmp_path / "log").exists()  # audit log written


def test_investigate_blocks_out_of_scope_seed_before_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch(monkeypatch)
    log = tmp_path / "audit.log"

    result = runner.invoke(
        app,
        [
            "argus",
            "investigate",
            "--seed-type",
            "domain",
            "--seed-value",
            "outside.example",
            "--i-am-authorized",
            "--domain-scope",
            str(_domain_scope(tmp_path, "inside.example")),
            "--log",
            str(log),
        ],
    )

    assert result.exit_code == 3
    assert "blocked, out of scope" in result.output
    assert "blocked_out_of_scope" in log.read_text(encoding="utf-8")


def test_investigate_writes_audit_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch)
    log = tmp_path / "audit.log"
    runner.invoke(
        app,
        [
            "argus",
            "investigate",
            "--seed-type",
            "phone",
            "--seed-value",
            "+16505550123",
            "--i-am-authorized",
            "--output",
            str(tmp_path / "g.json"),
            "--log",
            str(log),
        ],
    )
    entry = json.loads(log.read_text(encoding="utf-8").strip())
    assert entry["seed_type"] == "phone"
    assert entry["action"] == "investigation_started"
