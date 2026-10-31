"""CLI-level tests for `olympus argus accounts` and `accounts-demo`."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from olympus.argus import cli as argus_cli
from olympus.cli import app
from olympus.core.http import HttpResponse

runner = CliRunner()


class _FakeClient:
    """Offline HttpClient double: first configured host is 'present', rest 404."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        # Accept the same construction kwargs as UrllibHttpClient (e.g. min_interval).
        pass

    @classmethod
    def from_config(
        cls,
        *,
        min_interval: object = None,
        redirect_validator: object = None,
        address_policy: object = None,
    ) -> _FakeClient:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if "github.com" in url:
            return HttpResponse(status_code=200, headers={}, body="<html>profile</html>")
        return HttpResponse(status_code=404, headers={}, body="not found")


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps({"engagement": "t", "allowed_handles": ["olympus_demo"]}), encoding="utf-8"
    )
    return path


def _sites(tmp_path: Path) -> Path:
    path = tmp_path / "sites.json"
    path.write_text(
        json.dumps(
            [
                {"name": "GitHub", "url_template": "https://github.com/{username}"},
                {"name": "GitLab", "url_template": "https://gitlab.com/{username}"},
            ]
        ),
        encoding="utf-8",
    )
    return path


def test_accounts_real_with_fake_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _FakeClient)
    result = runner.invoke(
        app,
        [
            "argus",
            "accounts",
            "--username",
            "olympus_demo",
            "--scope",
            str(_scope(tmp_path)),
            "--sites",
            str(_sites(tmp_path)),
        ],
    )
    assert result.exit_code == 0, result.output
    # output combines stderr progress lines with the JSON bundle; slice out the JSON object.
    json_text = result.output[result.output.find("{") : result.output.rfind("}") + 1]
    payload = json.loads(json_text)
    assert len(payload["assets"]) == 1
    assert payload["assets"][0]["metadata"]["site"] == "GitHub"


def test_accounts_out_of_scope_blocks(tmp_path: Path) -> None:
    log = tmp_path / "blocked.log"
    result = runner.invoke(
        app,
        [
            "argus",
            "accounts",
            "--username",
            "intruder",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(log),
            "--sites",
            str(_sites(tmp_path)),
        ],
    )
    assert result.exit_code == 3
    assert log.exists()


def test_accounts_metadata_requires_authorization(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "argus",
            "accounts",
            "--username",
            "olympus_demo",
            "--scope",
            str(_scope(tmp_path)),
            "--sites",
            str(_sites(tmp_path)),
            "--metadata",
        ],
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_accounts_bad_registry(tmp_path: Path) -> None:
    bad = tmp_path / "sites.json"
    bad.write_text("{not a list", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "argus",
            "accounts",
            "--username",
            "olympus_demo",
            "--scope",
            str(_scope(tmp_path)),
            "--sites",
            str(bad),
        ],
    )
    assert result.exit_code == 2


def test_accounts_requires_username_or_input(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["argus", "accounts", "--scope", str(_scope(tmp_path)), "--sites", str(_sites(tmp_path))],
    )
    assert result.exit_code == 2
    assert "exactly one" in result.output


def test_accounts_batch_skips_out_of_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(argus_cli, "UrllibHttpClient", _FakeClient)
    handles = tmp_path / "handles.txt"
    handles.write_text("olympus_demo\nintruder\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "argus",
            "accounts",
            "--input",
            str(handles),
            "--scope",
            str(_scope(tmp_path)),
            "--sites",
            str(_sites(tmp_path)),
            "--log",
            str(tmp_path / "blocked.log"),
        ],
    )
    assert result.exit_code == 0, result.output
    json_text = result.output[result.output.find("[") : result.output.rfind("]") + 1]
    payload = json.loads(json_text)
    assert len(payload) == 1  # only the in-scope handle
    assert "skipping out-of-scope" in result.output


def test_accounts_sanitizes_provider_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _WarningService:
        def __init__(self, *args: object) -> None:
            pass

        def run_many(self, requests: tuple[object, ...]) -> SimpleNamespace:
            return SimpleNamespace(
                intels=(), warnings=("provider\x1b[2J warning\nforged terminal line",)
            )

    monkeypatch.setattr(argus_cli, "AccountEnumerationService", _WarningService)
    handles = tmp_path / "handles.txt"
    handles.write_text("olympus_demo\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "argus",
            "accounts",
            "--input",
            str(handles),
            "--scope",
            str(_scope(tmp_path)),
            "--sites",
            str(_sites(tmp_path)),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "argus: provider[2J warning forged terminal line" in result.output
    assert "\x1b" not in result.output
    assert "\nforged terminal line" not in result.output
