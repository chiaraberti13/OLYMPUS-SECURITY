"""End-to-end CLI tests for `olympus athena`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.athena import cli as athena_cli
from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.http import HttpResponse
from olympus.core.models import Finding
from olympus.vulcan.enrichment import enrich_findings, prioritize

runner = CliRunner()

# Representative local KEV / EPSS feed bodies (shape as published), not live captures.
_KEV_FEED = json.dumps(
    {
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "knownRansomwareCampaignUse": "Known",
            }
        ]
    }
)
_EPSS_FEED = json.dumps(
    {
        "data": [
            {"cve": "CVE-2021-44228", "epss": "0.975", "percentile": "0.999", "date": "2026-09-01"}
        ]
    }
)


class _Http:
    """Serves canned DNS / RDAP / web responses for every adapter."""

    @classmethod
    def from_config(
        cls,
        *,
        min_interval: float | None = None,
        redirect_validator: object = None,
        address_policy: object = None,
    ) -> _Http:
        return cls()

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if "cloudflare" in url or "dns.google" in url:
            return HttpResponse(
                status_code=200, headers={}, body=json.dumps({"Answer": [{"data": "203.0.113.9"}]})
            )
        if "rdap.org" in url:
            return HttpResponse(
                status_code=200, headers={}, body=json.dumps({"ldhName": "example.com"})
            )
        return HttpResponse(status_code=200, headers={"Server": "nginx"}, body="")


def _plan_file(tmp_path: Path, adapters: list[str]) -> Path:
    plan = {
        "engagement_id": "ENG-1",
        "name": "demo",
        "targets": [{"kind": "domain", "value": "example.com"}],
        "adapters": adapters,
        "scope": {"allowed_domains": ["example.com"]},
        "authorization": {"engagement_id": "ENG-1", "approval_reference": "T", "confirmed": True},
    }
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")
    return path


def test_plan_validate_ok(tmp_path: Path) -> None:
    result = runner.invoke(app, ["athena", "plan", "validate", str(_plan_file(tmp_path, ["dns"]))])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["valid"] is True


def test_plan_validate_invalid(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(app, ["athena", "plan", "validate", str(bad)])
    assert result.exit_code == 2


def test_plan_validate_unknown_adapter(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["athena", "plan", "validate", str(_plan_file(tmp_path, ["ghost"]))]
    )
    assert result.exit_code == 2


def test_adapters_command() -> None:
    result = runner.invoke(app, ["athena", "adapters"])
    assert result.exit_code == 0
    assert "web-headers" in json.loads(result.output)["adapters"]


def test_run_dns_clean_exit_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(athena_cli, "UrllibHttpClient", _Http)
    storage = tmp_path / "store"
    result = runner.invoke(
        app,
        ["athena", "run", str(_plan_file(tmp_path, ["dns"])), "--storage", str(storage)],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["state"] == "succeeded"


def test_run_web_findings_exit_one_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(athena_cli, "UrllibHttpClient", _Http)
    storage = tmp_path / "store"
    result = runner.invoke(
        app,
        ["athena", "run", str(_plan_file(tmp_path, ["web-headers"])),
         "--storage", str(storage), "--report"],
    )
    # Missing security headers produce findings -> exit 1.
    assert result.exit_code == 1, result.output
    # The run outcome is JSON on stdout; the report path notice goes to stderr.
    assessment_id = json.loads(result.output.split("\nathena:")[0])["assessment_id"]
    reports = list(storage.glob(f"{assessment_id}.report.*"))
    assert reports, "expected a report file to be written"


def test_run_offline_enrichment_writes_ranked_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(athena_cli, "UrllibHttpClient", _Http)
    storage = tmp_path / "store"
    kev = tmp_path / "kev.json"
    kev.write_text(_KEV_FEED, encoding="utf-8")
    epss = tmp_path / "epss.json"
    epss.write_text(_EPSS_FEED, encoding="utf-8")
    result = runner.invoke(
        app,
        ["athena", "run", str(_plan_file(tmp_path, ["web-headers"])),
         "--storage", str(storage), "--report",
         "--enrich-kev", str(kev), "--enrich-epss", str(epss)],
    )
    assert result.exit_code == 1, result.output  # missing-header findings
    summary = json.loads(result.output.split("\nathena:")[0])
    assert "kev_hits" in summary  # enrichment ran (these findings carry no CVE -> 0)
    sidecar = storage / f"{summary['assessment_id']}.enriched.json"
    assert sidecar.exists(), "expected an enrichment sidecar"
    overlay = json.loads(sidecar.read_text(encoding="utf-8"))
    assert isinstance(overlay, list) and len(overlay) == summary["findings"]


def test_run_enrichment_rejects_a_malformed_feed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(athena_cli, "UrllibHttpClient", _Http)
    bad = tmp_path / "kev.json"
    bad.write_text("{ not json", encoding="utf-8")
    result = runner.invoke(
        app,
        ["athena", "run", str(_plan_file(tmp_path, ["dns"])),
         "--storage", str(tmp_path / "s"), "--enrich-kev", str(bad)],
    )
    assert result.exit_code == 2
    assert "enrichment feed error" in result.output


def test_enrichment_ranks_kev_first_and_writes_overlay(tmp_path: Path) -> None:
    kev = tmp_path / "kev.json"
    kev.write_text(_KEV_FEED, encoding="utf-8")
    epss = tmp_path / "epss.json"
    epss.write_text(_EPSS_FEED, encoding="utf-8")
    catalogs = athena_cli._load_local_catalogs(kev, epss)
    assert "CVE-2021-44228" in catalogs.kev

    exploited = Finding(
        asset_id="AST-1", source=Source.AEGIS, severity=Severity.HIGH, cvss=10.0,
        title="Service vulnerable to CVE-2021-44228",
    )
    benign = Finding(
        asset_id="AST-1", source=Source.AEGIS, severity=Severity.MEDIUM,
        title="Missing security header",
    )
    findings = [benign, exploited]  # deliberately unordered
    enrichments = enrich_findings(findings, kev=catalogs.kev, epss=catalogs.epss)
    ordered = [finding for finding, _ in prioritize(findings, enrichments)]
    assert ordered[0].finding_id == exploited.finding_id  # KEV dominates ordering

    storage = tmp_path / "store"
    storage.mkdir()
    athena_cli._write_enrichment("A-1", ordered, enrichments, storage)
    overlay = json.loads((storage / "A-1.enriched.json").read_text(encoding="utf-8"))
    assert overlay[0]["finding_id"] == exploited.finding_id
    assert overlay[0]["in_kev"] is True
    assert overlay[0]["max_epss"] == 0.975


def test_run_invalid_plan(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    result = runner.invoke(app, ["athena", "run", str(bad), "--storage", str(tmp_path / "s")])
    assert result.exit_code == 2


def test_status_and_cancel_and_recover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(athena_cli, "UrllibHttpClient", _Http)
    storage = tmp_path / "store"
    run_result = runner.invoke(
        app, ["athena", "run", str(_plan_file(tmp_path, ["dns"])), "--storage", str(storage)]
    )
    assessment_id = json.loads(run_result.output)["assessment_id"]

    status = runner.invoke(app, ["athena", "status", assessment_id, "--storage", str(storage)])
    assert status.exit_code == 0
    assert json.loads(status.output)["state"] == "succeeded"

    # The assessment is already terminal; cancel is a no-op returning its state.
    cancel = runner.invoke(app, ["athena", "cancel", assessment_id, "--storage", str(storage)])
    assert cancel.exit_code == 0
    assert json.loads(cancel.output)["state"] == "succeeded"

    recover = runner.invoke(app, ["athena", "recover", "--storage", str(storage)])
    assert recover.exit_code == 0
    assert json.loads(recover.output)["recovered"] == []


def test_status_missing(tmp_path: Path) -> None:
    result = runner.invoke(app, ["athena", "status", "ASM-9999", "--storage", str(tmp_path / "s")])
    assert result.exit_code == 2


def test_cancel_missing(tmp_path: Path) -> None:
    result = runner.invoke(app, ["athena", "cancel", "ASM-9999", "--storage", str(tmp_path / "s")])
    assert result.exit_code == 2
