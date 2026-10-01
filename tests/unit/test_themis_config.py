"""Unit tests for Themis configuration resolution (THEMIS_* -> AEGIS_* -> VAP_*)."""

from __future__ import annotations

import pytest

from olympus.themis import config


def test_canonical_themis_variable_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THEMIS_HOST", "canonical")
    monkeypatch.setenv("AEGIS_HOST", "canonical")  # same value, not ambiguous
    assert config.get("THEMIS_HOST") == "canonical"


def test_falls_back_to_legacy_aegis_then_vap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THEMIS_HOST", raising=False)
    monkeypatch.setenv("AEGIS_HOST", "from-aegis")
    assert config.get("THEMIS_HOST") == "from-aegis"
    monkeypatch.delenv("AEGIS_HOST", raising=False)
    monkeypatch.setenv("VAP_HOST", "from-vap")
    assert config.get("THEMIS_HOST") == "from-vap"


def test_resolution_is_bidirectional(monkeypatch: pytest.MonkeyPatch) -> None:
    # A caller still passing the legacy AEGIS_* name resolves THEMIS_* too.
    monkeypatch.delenv("AEGIS_HOST", raising=False)
    monkeypatch.setenv("THEMIS_HOST", "new")
    assert config.get("AEGIS_HOST") == "new"


def test_ambiguous_values_are_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THEMIS_HOST", "a")
    monkeypatch.setenv("AEGIS_HOST", "b")
    with pytest.raises(config.ThemisConfigError):
        config.get("THEMIS_HOST")


def test_default_when_nothing_set(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("THEMIS_HOST", "AEGIS_HOST", "VAP_HOST"):
        monkeypatch.delenv(name, raising=False)
    assert config.get("THEMIS_HOST", "fallback-default") == "fallback-default"
