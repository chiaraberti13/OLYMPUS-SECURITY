"""Athena AEGIS scan stage: recon -> SCAN -> enrich -> report, scope-gated.

The adapter bridges AEGIS's scanner engine into an Athena plan. Offline it uses
AEGIS's own scope-gated simulation mode (real product path, clearly labelled, no
binary run); the live/failure mappings are covered by injecting a stub AEGIS
adapter so no real scan is triggered in the suite.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.aegis.model import ScanRequest, ScanResult
from olympus.aegis.states import ExecutionState
from olympus.athena.adapters.aegis_scan import AegisScanAdapter
from olympus.athena.application.registry import available_adapters, resolve_adapters
from olympus.athena.ports import ToolRequest
from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.models import Finding

runner = CliRunner()


class _NoCancel:
    def is_cancelled(self) -> bool:
        return False


def _req(target: str = "example.com", allowed: tuple[str, ...] = ("example.com",)) -> ToolRequest:
    return ToolRequest(
        target_kind="domain", target_value=target, allowed_domains=allowed, timeout_seconds=30
    )


def test_scan_uses_scope_gated_simulation_when_live_is_disabled() -> None:
    adapter = AegisScanAdapter("nmap", live_enabled=lambda: False)
    result = adapter.run(_req(), _NoCancel())
    assert result.ok is True
    assert result.findings, "simulation must still yield a labelled finding"
    assert "[SIMULATION]" in result.findings[0].title


def test_scan_refuses_an_out_of_scope_target() -> None:
    adapter = AegisScanAdapter("nmap", live_enabled=lambda: False)
    result = adapter.run(_req(target="evil.test", allowed=("example.com",)), _NoCancel())
    assert result.ok is False
    assert result.error_code in {"out_of_scope", "invalid_target", "ssrf_blocked"}


def _fake_factory(result: ScanResult):
    class _Stub:
        def run(self, request: ScanRequest) -> ScanResult:
            return result

    return lambda _name: _Stub()


def test_scan_maps_a_live_result_into_findings() -> None:
    finding = Finding(
        asset_id="AST-1", source=Source.AEGIS, severity=Severity.MEDIUM,
        title="Open port 22/tcp (ssh)",
    )
    live = ScanResult(
        scanner="nmap", state=ExecutionState.LIVE, target="example.com", findings=[finding],
    )
    adapter = AegisScanAdapter(
        "nmap", adapter_factory=_fake_factory(live), live_enabled=lambda: True
    )
    result = adapter.run(_req(), _NoCancel())
    assert result.ok is True
    assert [f.title for f in result.findings] == ["Open port 22/tcp (ssh)"]


def test_scan_maps_an_unavailable_result_to_a_failed_step() -> None:
    unavailable = ScanResult(
        scanner="nmap", state=ExecutionState.UNAVAILABLE, target="example.com",
    )
    adapter = AegisScanAdapter(
        "nmap", adapter_factory=_fake_factory(unavailable), live_enabled=lambda: True
    )
    result = adapter.run(_req(), _NoCancel())
    assert result.ok is False
    assert result.error_code == "unavailable"


def test_scan_turns_a_scanner_crash_into_a_stable_failed_result() -> None:
    def _boom(_name: str):
        class _Stub:
            def run(self, request: ScanRequest) -> ScanResult:
                raise RuntimeError("scanner blew up with sensitive detail")

        return _Stub()

    adapter = AegisScanAdapter("nmap", adapter_factory=_boom, live_enabled=lambda: True)
    result = adapter.run(_req(), _NoCancel())
    assert result.ok is False
    assert result.error_code == "scan_failed"  # no scanner text leaks


def test_aegis_is_registered_as_an_athena_adapter() -> None:
    assert "aegis" in available_adapters()
    resolved = resolve_adapters(("aegis",), http=None)  # type: ignore[arg-type]
    assert resolved["aegis"].name == "aegis"


def test_cli_pipeline_runs_the_scan_stage_and_reports(tmp_path: Path) -> None:
    plan = {
        "engagement_id": "ENG-PIPE",
        "name": "scan pipeline",
        "targets": [{"kind": "domain", "value": "example.com"}],
        "adapters": ["aegis"],
        "scope": {"allowed_domains": ["example.com"]},
        "authorization": {
            "engagement_id": "ENG-PIPE", "approval_reference": "SOW-1", "confirmed": True
        },
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    result = runner.invoke(
        app,
        ["athena", "run", str(plan_path), "--storage", str(tmp_path / "store"), "--report"],
    )
    # A finding (the labelled simulation) -> exit 1; a report is written.
    assert result.exit_code == 1, result.output
    summary = json.loads(result.output.split("\nathena:")[0])
    assert summary["findings"] >= 1
    reports = list((tmp_path / "store").glob(f"{summary['assessment_id']}.report.*"))
    assert reports
