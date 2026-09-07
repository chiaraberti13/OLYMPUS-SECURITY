"""Per-scanner diagnostics and the ``olympus aegis doctor --scanner`` command."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.integrations import scanner_doctor
from olympus.integrations.scanners import REGISTRY

runner = CliRunner()


def _checks(report_dict: dict[str, object]) -> dict[str, dict[str, object]]:
    return {c["name"]: c for c in report_dict["checks"]}  # type: ignore[index,union-attr]


def test_scanner_names_cover_the_whole_catalogue() -> None:
    assert scanner_doctor.scanner_names() == sorted(s.name for s in REGISTRY)
    assert len(scanner_doctor.scanner_names()) == len(REGISTRY)


def test_report_for_an_unknown_scanner_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        scanner_doctor.scanner_report("definitely-not-a-scanner")


def test_binary_scanner_report_names_its_install_when_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scanner_doctor.shutil, "which", lambda _binary: None)
    checks = _checks(scanner_doctor.scanner_report("nmap").to_dict())
    binary = checks["scanner:nmap:binary"]
    assert binary["ok"] is False
    assert "not installed" in binary["detail"]
    assert "install:" in binary["detail"]  # tells the operator how to fix it


def test_binary_scanner_report_captures_a_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scanner_doctor.shutil, "which", lambda _binary: "/usr/bin/nmap")
    monkeypatch.setattr(
        scanner_doctor, "binary_version", lambda _b, _flag: "Nmap version 7.94"
    )
    binary = _checks(scanner_doctor.scanner_report("nmap").to_dict())["scanner:nmap:binary"]
    assert binary["ok"] is True
    assert "Nmap version 7.94" in binary["detail"]


def test_version_detection_strips_ansi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner_doctor.shutil, "which", lambda _binary: "/opt/nuclei")
    monkeypatch.setattr(
        scanner_doctor,
        "binary_version",
        lambda _b, _flag: "\x1b[34m[INF]\x1b[0m Nuclei Engine Version: v3.11.1",
    )
    assert scanner_doctor.detect_version("nuclei") == "[INF] Nuclei Engine Version: v3.11.1"


def test_api_scanner_reports_missing_configuration_by_name() -> None:
    """Secret-safe: name the unset variables, never a value, and never 'ready'."""
    checks = _checks(scanner_doctor.scanner_report("nessus").to_dict())
    api = checks["scanner:nessus:api"]
    assert api["ok"] is False
    assert "AEGIS_NESSUS_URL" in api["detail"] and "AEGIS_NESSUS_TOKEN" in api["detail"]
    assert checks["scanner:nessus:adapter"]["ok"] is False
    assert checks["scanner:nessus:ready"]["ok"] is False


def test_api_scanner_reports_configured_when_variables_are_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_NESSUS_URL", "https://nessus.example")
    monkeypatch.setenv("AEGIS_NESSUS_TOKEN", "s3cr3t")
    api = _checks(scanner_doctor.scanner_report("nessus").to_dict())["scanner:nessus:api"]
    assert api["ok"] is True
    # The variable names may appear; their values must never.
    assert "s3cr3t" not in api["detail"]


def test_report_exposes_maturity_and_adapter_for_a_live_tested_engine() -> None:
    checks = _checks(scanner_doctor.scanner_report("nmap").to_dict())
    assert checks["scanner:nmap:adapter"]["ok"] is True
    assert "live-tested" in checks["scanner:nmap:maturity"]["detail"]


def test_catalog_only_engine_reports_no_adapter() -> None:
    checks = _checks(scanner_doctor.scanner_report("wpscan").to_dict())
    assert checks["scanner:wpscan:adapter"]["ok"] is False
    assert "catalog-only" in checks["scanner:wpscan:maturity"]["detail"]


# --- CLI -------------------------------------------------------------------- #


def test_doctor_scanner_reports_one_engine() -> None:
    result = runner.invoke(app, ["aegis", "doctor", "--scanner", "nmap"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["title"] == "aegis doctor --scanner nmap"
    assert any(c["name"] == "scanner:nmap:maturity" for c in payload["checks"])


def test_doctor_scanner_all_reports_every_engine() -> None:
    result = runner.invoke(app, ["aegis", "doctor", "--scanner", "all"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert len(payload["scanners"]) == len(REGISTRY)
    titles = {item["title"] for item in payload["scanners"]}
    assert "aegis doctor --scanner nmap" in titles


def test_doctor_scanner_rejects_an_unknown_name() -> None:
    result = runner.invoke(app, ["aegis", "doctor", "--scanner", "ghost"])
    assert result.exit_code == int(ExitCode.USAGE)
    assert "unknown scanner" in result.output


def test_doctor_without_scanner_still_diagnoses_the_runtime() -> None:
    result = runner.invoke(app, ["aegis", "doctor"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["title"] == "aegis doctor"
