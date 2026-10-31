"""Tests for the THEMIS scanner registry and environment diagnostics."""

from __future__ import annotations

from olympus.integrations import scanners
from olympus.integrations.diagnostics import (
    Report,
    check_binary,
    check_env_set,
    check_python_module,
    check_tcp,
    check_writable_dir,
)


def test_registry_has_all_24_scanners() -> None:
    assert len(scanners.REGISTRY) == 24
    assert len(scanners.names()) == 24
    # No duplicate names.
    assert len(set(scanners.names())) == 24


def test_registry_fields_are_populated() -> None:
    for spec in scanners.REGISTRY:
        assert spec.name and spec.purpose and spec.category
        assert spec.licence and spec.install
        # API/commercial engines have no binary; OSS CLI tools do.
        if spec.binary is None:
            assert spec.name in {"zap", "openvas", "nessus", "burp", "acunetix"}


def test_registry_by_name() -> None:
    nmap = scanners.by_name("nmap")
    assert nmap is not None
    assert nmap.binary == "nmap"
    assert scanners.by_name("does-not-exist") is None


def test_available_reflects_path(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import shutil

    spec = scanners.by_name("nmap")
    assert spec is not None
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/nmap")
    assert spec.available() is True
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert spec.available() is False


def test_commercial_scanners_not_redistributable() -> None:
    for name in ("nessus", "burp", "acunetix", "wpscan"):
        spec = scanners.by_name(name)
        assert spec is not None
        assert spec.redistributable is False


def test_diagnostics_binary_missing() -> None:
    check = check_binary("definitely-not-a-real-binary-xyz", optional=True)
    assert check.ok is False
    assert "not installed" in check.detail


def test_diagnostics_python_module() -> None:
    assert check_python_module("json").ok is True
    assert check_python_module("no_such_module_zzz", optional=True).ok is False


def test_diagnostics_tcp_unreachable() -> None:
    # Port 1 is not listening; connection fails quickly.
    check = check_tcp("127.0.0.1", 1, name="service:none", optional=True)
    assert check.ok is False


def test_diagnostics_writable_dir(tmp_path) -> None:  # type: ignore[no-untyped-def]
    missing = tmp_path / "sub"
    check = check_writable_dir(str(missing))
    assert check.ok is True
    # A diagnostic reports; it must not create the directory it asks about.
    assert not missing.exists()

    existing = check_writable_dir(str(tmp_path))
    assert existing.ok is True
    assert list(tmp_path.iterdir()) == []  # the write probe cleans up after itself

    a_file = tmp_path / "file"
    a_file.write_text("x", encoding="utf-8")
    assert check_writable_dir(str(a_file)).ok is False


def test_diagnostics_env_secret_never_prints_value(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("OLYMPUS_TEST_SECRET", "supersecretvalue")
    check = check_env_set("OLYMPUS_TEST_SECRET", secret=True)
    assert check.ok is True
    assert "supersecret" not in check.detail
    assert check.detail == "set"


def test_report_ok_ignores_optional_failures() -> None:
    report = Report("t")
    report.add(check_python_module("json"))
    report.add(check_binary("definitely-not-real-xyz", optional=True))
    assert report.ok() is True  # optional failure does not flip ok
    report.add(check_python_module("no_such_module_zzz", optional=False))
    assert report.ok() is False
