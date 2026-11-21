"""Shared engine resource budgets across Themis execution surfaces (TOOLS-4.3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.engines.loader import load_all
from olympus.themis.application import ThemisApplicationService, ThemisRunRequest
from olympus.themis.base import ScannerAdapter
from olympus.themis.model import ScanRequest, ScanResult
from olympus.themis.resources import EngineResourceError, resolve_engine_runtime_budget
from olympus.themis.sandbox import SandboxPolicy
from olympus.themis.states import ExecutionState

pytestmark = pytest.mark.unit


def _sandbox(memory_bytes: int) -> SandboxPolicy:
    return SandboxPolicy(memory_bytes=memory_bytes, effective_uid=1000)


def test_reviewed_nuclei_budget_has_reproducible_measurement_metadata() -> None:
    adapter = load_all()["nuclei"].adapter
    assert adapter is not None and adapter.reviewed
    assert adapter.measurement is not None
    assert adapter.measurement.engine_version == "v3.11.1"
    assert adapter.measurement.data_version == "95131c8dd920db77a5e86e72fe2d2a3e5ca37d2d"
    assert adapter.measurement.cpu_count == 4
    assert adapter.measurement.ram_bytes == 15 * 1024**3


def test_omitted_limits_use_reviewed_engine_values_but_explicit_limits_win() -> None:
    roomy = _sandbox(8 * 1024**3)
    default = resolve_engine_runtime_budget(
        "nuclei", timeout_seconds=None, deadline_seconds=None, sandbox=roomy
    )
    assert (default.timeout_seconds, default.deadline_seconds) == (1200.0, 1500.0)
    assert default.resource_confidence == "measured"
    assert default.resource_profile == "network-heavy"

    explicit = resolve_engine_runtime_budget(
        "nuclei", timeout_seconds=90.0, deadline_seconds=120.0, sandbox=roomy
    )
    assert (explicit.timeout_seconds, explicit.deadline_seconds) == (90.0, 120.0)

    estimated = resolve_engine_runtime_budget(
        "nmap", timeout_seconds=None, deadline_seconds=None, sandbox=roomy
    )
    assert (estimated.timeout_seconds, estimated.deadline_seconds) == (300.0, 600.0)
    assert estimated.resource_confidence == "estimated"


def test_reviewed_memory_request_cannot_raise_the_sandbox_ceiling() -> None:
    with pytest.raises(EngineResourceError, match="THEMIS_SANDBOX_MEMORY_BYTES"):
        resolve_engine_runtime_budget(
            "nuclei",
            timeout_seconds=None,
            deadline_seconds=None,
            sandbox=_sandbox(2 * 1024**3),
        )


def test_offline_budget_resolution_does_not_depend_on_host_sandbox_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("THEMIS_SANDBOX_MEMORY_BYTES", "not-an-integer")
    budget = resolve_engine_runtime_budget(
        "nuclei", timeout_seconds=None, deadline_seconds=None, enforce_memory=False
    )
    assert budget.timeout_seconds == 1200.0


def test_application_service_propagates_same_budget_to_worker_style_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("THEMIS_SANDBOX_MEMORY_BYTES", str(4 * 1024**3))
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "schema_name": "olympus.themis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
            }
        ),
        encoding="utf-8",
    )
    captured: list[ScanRequest] = []

    class CapturingNuclei(ScannerAdapter):
        name = "nuclei"
        binary = "nuclei"
        install = "n/a"

        def build_argv(self, host: str, request: ScanRequest) -> list[str]:
            return ["nuclei"]

        def parse(self, output: object, host: str, request: ScanRequest) -> list[object]:
            return []

        def run(self, request: ScanRequest) -> ScanResult:
            captured.append(request)
            return ScanResult(
                scanner=self.name, state=ExecutionState.SIMULATION, target=request.target
            )

    service = ThemisApplicationService(
        adapter_factory=lambda _name: CapturingNuclei(), isolation_verifier=lambda: None
    )
    service.run(
        ThemisRunRequest(
            scanner="nuclei",
            target="127.0.0.1",
            target_kind="host",
            scope_path=scope,
            authorized=True,
            live_enabled=False,
            simulate=True,
        )
    )

    assert captured[0].timeout_seconds == 1200.0
    assert captured[0].deadline_seconds == 1500.0


def test_live_application_refuses_insufficient_memory_before_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("THEMIS_SANDBOX_MEMORY_BYTES", str(2 * 1024**3))
    scope = tmp_path / "scope.json"
    scope.write_text(
        '{"schema_name":"olympus.themis-scope","schema_version":"1.0.0",'
        '"allowed_hosts":["127.0.0.1"]}',
        encoding="utf-8",
    )

    def adapter_must_not_be_resolved(_name: str) -> ScannerAdapter:
        raise AssertionError("adapter was resolved despite failed resource preflight")

    service = ThemisApplicationService(
        adapter_factory=adapter_must_not_be_resolved, isolation_verifier=lambda: None
    )
    with pytest.raises(EngineResourceError, match="sandbox ceiling"):
        service.run(
            ThemisRunRequest(
                scanner="nuclei",
                target="127.0.0.1",
                target_kind="host",
                scope_path=scope,
                authorized=True,
                live_enabled=True,
            )
        )
