"""Fail-closed contract tests for the explicit Themis live-lab profile."""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.core.policy import PolicyError
from olympus.themis.lab import load_lab_execution_profile

LAB = """schema_version = "1.0.0"
engagement = "LAB-SYNTHETIC-01"
[lab]
enabled = true
allowed_networks = ["10.20.1.7/24"]
activated_by = "synthetic-operator"
activated_at = 2026-10-25T12:00:00Z
"""


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def test_live_lab_profile_requires_explicit_signed_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _write(tmp_path / "lab.toml", LAB)
    monkeypatch.delenv("OLYMPUS_POLICY_LAB_KEY", raising=False)
    with pytest.raises(PolicyError, match="OLYMPUS_POLICY_LAB_KEY"):
        load_lab_execution_profile(policy)

    monkeypatch.setenv("OLYMPUS_POLICY_LAB_KEY", "too-short")
    with pytest.raises(PolicyError, match="at least 32"):
        load_lab_execution_profile(policy)

    monkeypatch.setenv("OLYMPUS_POLICY_LAB_KEY", "synthetic-test-key-at-least-32-bytes")
    profile = load_lab_execution_profile(policy)
    assert profile.engagement == "LAB-SYNTHETIC-01"
    assert profile.allowed_networks == ("10.20.1.0/24",)
    assert len(profile.policy_sha256) == len(profile.activation_signature) == 64


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('schema_version = "1.0.0"\n', "enabled"),
        (LAB.replace('engagement = "LAB-SYNTHETIC-01"\n', ""), "engagement"),
        (
            LAB.replace(
                'allowed_networks = ["10.20.1.7/24"]',
                'allowed_networks = ["0.0.0.0/0"]',
            ),
            "eligible lab range",
        ),
    ],
)
def test_live_lab_profile_rejects_implicit_unattributed_or_global_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str, message: str
) -> None:
    monkeypatch.setenv("OLYMPUS_POLICY_LAB_KEY", "synthetic-test-key-at-least-32-bytes")
    with pytest.raises(PolicyError, match=message):
        load_lab_execution_profile(_write(tmp_path / "lab.toml", body))


def test_live_lab_profile_rejects_symlinks(tmp_path: Path) -> None:
    policy = _write(tmp_path / "lab.toml", LAB)
    alias = tmp_path / "alias.toml"
    alias.symlink_to(policy)
    with pytest.raises(OSError, match="symlink"):
        load_lab_execution_profile(alias)
