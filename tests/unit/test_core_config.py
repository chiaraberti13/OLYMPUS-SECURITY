"""Unit tests for optional TOML configuration."""

import os
from pathlib import Path

import pytest

from olympus.core import config
from olympus.core.http import UrllibHttpClient


def test_no_file_returns_empty(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OLYMPUS_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)  # no ./olympus.toml here
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)  # no ~/.olympus.toml
    assert config.load_config() == {}


def test_loads_from_env_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("[http]\ntimeout = 15.0\nretries = 3\nrate = 0.25\n", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    data = config.load_config()
    assert config.get("http", "timeout", 10.0, data) == 15.0
    assert config.get("http", "retries", 2, data) == 3


def test_get_rejects_type_mismatch() -> None:
    data = {"http": {"timeout": "not-a-number"}}
    with pytest.raises(config.ConfigError, match="invalid type"):
        config.get("http", "timeout", 10.0, data)


def test_get_missing_section_returns_default() -> None:
    assert config.get("http", "timeout", 10.0, {}) == 10.0


def test_malformed_toml_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("this is = = not toml", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    with pytest.raises(config.ConfigError, match="invalid TOML"):
        config.load_config()


def test_missing_explicit_config_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    missing = tmp_path / "missing.toml"
    monkeypatch.setenv("OLYMPUS_CONFIG", str(missing))
    with pytest.raises(config.ConfigError, match="does not exist"):
        config.load_config()


@pytest.mark.parametrize(
    "body",
    [
        "[http]\ntimeout = 0\n",
        "[http]\nretries = 99\n",
        "[http]\nmax_response_bytes = 0\n",
        "[http]\nunknown = 1\n",
    ],
)
def test_invalid_http_config_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, body: str
) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text(body, encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    with pytest.raises(config.ConfigError):
        config.load_config()


def test_http_from_config_uses_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("[http]\ntimeout = 20.0\nrate = 0.5\n", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    client = UrllibHttpClient.from_config()
    assert client._timeout == 20.0
    assert client._min_interval == 0.5


def test_http_from_config_caller_rate_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("[http]\nrate = 0.5\n", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    client = UrllibHttpClient.from_config(min_interval=2.0)
    assert client._min_interval == 2.0


def test_precedence_is_caller_then_environment_then_file_then_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = tmp_path / "olympus.toml"
    cfg.write_text("[http]\nrate = 0.5\ntimeout = 20.0\n", encoding="utf-8")
    monkeypatch.setenv("OLYMPUS_CONFIG", str(cfg))
    monkeypatch.setenv("OLYMPUS_HTTP_RATE", "1.25")
    data = config.load_config()

    assert config.get("http", "rate", 0.0, data) == 1.25
    assert config.get("http", "timeout", 10.0, data) == 20.0
    assert config.get("http", "retries", 2, data) == 2
    assert UrllibHttpClient.from_config(min_interval=2.0)._min_interval == 2.0


def test_invalid_environment_override_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_HTTP_RETRIES", "1.5")
    with pytest.raises(config.ConfigError, match="OLYMPUS_HTTP_RETRIES"):
        config.get("http", "retries", 2, {})

    monkeypatch.setenv("OLYMPUS_HTTP_RETRIES", "99")
    with pytest.raises(config.ConfigError, match=r"invalid.*retries"):
        config.get("http", "retries", 2, {})


def test_load_config_with_explicit_source_does_not_mutate_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cfg = tmp_path / "selected.toml"
    cfg.write_text("[http]\ntimeout = 12.0\n", encoding="utf-8")
    monkeypatch.delenv("OLYMPUS_CONFIG", raising=False)

    data, source = config.load_config_with_source(cfg)

    assert data["http"]["timeout"] == 12.0
    assert source == cfg.resolve()
    assert "OLYMPUS_CONFIG" not in os.environ


def test_effective_config_lists_override_names_not_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OLYMPUS_HTTP_TIMEOUT", "13.5")
    effective = config.effective_config({"service": {"api_token": "super-secret"}})

    assert effective["http"]["timeout"] == 13.5
    assert config.active_environment_overrides() == ["OLYMPUS_HTTP_TIMEOUT"]


def test_effective_deadline_tracks_timeout_when_not_overridden() -> None:
    effective = config.effective_config({"http": {"timeout": 900.0}})
    assert effective["http"]["deadline"] == 900.0
