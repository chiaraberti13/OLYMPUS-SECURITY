from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from scripts import manage_scanner_apparmor as apparmor


def _policy(tmp_path: Path) -> Path:
    policy = tmp_path / "scanner.apparmor"
    policy.write_bytes(apparmor.DEFAULT_POLICY.read_bytes())
    return policy


def test_inspect_reports_trusted_identity_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy(tmp_path)
    monkeypatch.setattr(apparmor, "_apparmor_available", lambda: True)
    monkeypatch.setattr(apparmor, "_loaded_mode", lambda: "enforce")
    monkeypatch.setattr(apparmor, "_find_parser", lambda: "/usr/sbin/apparmor_parser")
    status = apparmor.inspect(policy)
    assert status.available is True
    assert status.loaded_mode == "enforce"
    assert status.profile == "olympus-themis-scanner"
    assert len(status.policy_sha256) == 64


@pytest.mark.parametrize(
    "source",
    [
        "# Policy version: 2.0.0\nprofile olympus-themis-scanner {\n}\n",
        "# Policy version: 1.0.0\nprofile attacker {\n}\n",
        "# Policy version: 1.0.0\nprofile olympus-themis-scanner {\n}\n",
    ],
)
def test_policy_identity_mismatch_fails_closed(tmp_path: Path, source: str) -> None:
    policy = tmp_path / "scanner.apparmor"
    policy.write_text(source, encoding="utf-8")
    with pytest.raises(apparmor.ProvisioningError, match="identity or version"):
        apparmor.inspect(policy)


def test_symlink_policy_is_rejected(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    alias = tmp_path / "alias.apparmor"
    alias.symlink_to(policy)
    with pytest.raises(apparmor.ProvisioningError, match="not a symlink"):
        apparmor.inspect(alias)


def test_modified_policy_with_valid_identity_is_rejected(tmp_path: Path) -> None:
    policy = _policy(tmp_path)
    policy.write_text(policy.read_text() + "# altered\n", encoding="utf-8")
    with pytest.raises(apparmor.ProvisioningError, match="digest"):
        apparmor.inspect(policy)


def test_install_uses_fixed_argv_without_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy(tmp_path)
    calls: list[tuple[list[str], bool, object]] = []
    modes = iter((None, "enforce"))
    monkeypatch.setattr(apparmor, "_apparmor_available", lambda: True)
    monkeypatch.setattr(apparmor, "_loaded_mode", lambda: next(modes))
    monkeypatch.setattr(apparmor, "_find_parser", lambda: "/usr/sbin/apparmor_parser")
    monkeypatch.setattr(apparmor.os, "geteuid", lambda: 0)

    def fake_run(argv: list[str], *, check: bool, stdin: object) -> None:
        calls.append((argv, check, stdin))

    monkeypatch.setattr(apparmor.subprocess, "run", fake_run)
    status = apparmor.install(policy)
    assert status.loaded_mode == "enforce"
    assert calls == [
        (
            ["/usr/sbin/apparmor_parser", "-r", "-W", str(policy.resolve())],
            True,
            subprocess.DEVNULL,
        )
    ]


def test_install_requires_enabled_lsm_before_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _policy(tmp_path)
    monkeypatch.setattr(apparmor, "_apparmor_available", lambda: False)
    monkeypatch.setattr(apparmor, "_loaded_mode", lambda: None)
    monkeypatch.setattr(apparmor, "_find_parser", lambda: "/usr/sbin/apparmor_parser")
    with pytest.raises(apparmor.ProvisioningError, match="not enabled"):
        apparmor.install(policy)


def test_install_requires_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy = _policy(tmp_path)
    monkeypatch.setattr(apparmor, "_apparmor_available", lambda: True)
    monkeypatch.setattr(apparmor, "_loaded_mode", lambda: None)
    monkeypatch.setattr(apparmor, "_find_parser", lambda: "/usr/sbin/apparmor_parser")
    monkeypatch.setattr(apparmor.os, "geteuid", lambda: 1000)
    with pytest.raises(apparmor.ProvisioningError, match="requires root"):
        apparmor.install(policy)
