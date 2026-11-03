"""Presence probe and partial-coverage hook of ``ScannerAdapter`` (offline, no network)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from olympus.core.exit_codes import ExitCode
from olympus.core.models import Finding
from olympus.integrations.cli import _scan_exit_code
from olympus.themis import base as base_module
from olympus.themis.base import PresenceResult, ScannerAdapter
from olympus.themis.model import ScanRequest, ScanResult
from olympus.themis.runner import CommandOutput
from olympus.themis.states import ExecutionState

pytestmark = pytest.mark.unit


class _Fake(ScannerAdapter):
    name = "fake"
    binary = "fakebin"
    install = "apt-get install -y fakebin"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        return [self.binary, host]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        return []


class _Picky(_Fake):
    def recognises(self, version_output: str) -> bool:
        return "FakeScan" in version_output


def _no_run(*_args: object, **_kwargs: object) -> CommandOutput:
    raise AssertionError("a missing engine must never be executed")


def test_probe_reports_a_missing_engine_with_its_install_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(base_module, "which", lambda _b: None)
    monkeypatch.setattr(base_module, "run_command", _no_run)
    result = _Fake().probe()
    assert result == PresenceResult(
        engine="fake",
        present=False,
        detail="'fakebin' is not on PATH",
        install="apt-get install -y fakebin",
    )
    assert result.to_dict()["present"] is False


def test_probe_reports_a_present_engine_with_its_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base_module, "which", lambda _b: "/usr/bin/fakebin")
    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_kw: object) -> CommandOutput:
        seen.append(argv)
        return CommandOutput(exit_code=0, stdout="FakeScan 1.2.3\n", stderr="")

    monkeypatch.setattr(base_module, "run_command", fake_run)
    result = _Fake().probe()
    assert result.present is True
    assert result.path == "/usr/bin/fakebin"
    assert result.version == "FakeScan 1.2.3"
    assert seen == [["fakebin", "--version"]]  # fixed argv, no shell, no target


def test_probe_rejects_a_same_named_but_different_tool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base_module, "which", lambda _b: "/usr/bin/fakebin")
    monkeypatch.setattr(
        base_module,
        "run_command",
        lambda *_a, **_k: CommandOutput(exit_code=0, stdout="OtherTool 9\n", stderr=""),
    )
    result = _Picky().probe()
    assert result.present is False
    assert "is not the fake engine" in result.detail


def test_default_coverage_loss_keeps_existing_adapters_unchanged() -> None:
    request = ScanRequest(scanner="fake", target="127.0.0.1", allowed=("127.0.0.1",))
    assert _Fake().coverage_loss(CommandOutput(0, "", ""), request) is None


def test_partial_result_validation() -> None:
    live = ScanResult(scanner="fake", state=ExecutionState.LIVE, target="t")
    assert live.partial is False and live.partial_reason is None
    with pytest.raises(ValueError, match="say why"):
        ScanResult(scanner="fake", state=ExecutionState.LIVE, target="t", partial=True)
    with pytest.raises(ValueError, match="only a live"):
        ScanResult(
            scanner="fake",
            state=ExecutionState.FAILED,
            target="t",
            partial=True,
            partial_reason="x",
        )
    with pytest.raises(ValueError, match="requires partial"):
        ScanResult(scanner="fake", state=ExecutionState.LIVE, target="t", partial_reason="x")


@pytest.mark.parametrize(
    ("partial", "findings", "expected"),
    [
        (False, 0, ExitCode.OK),
        (False, 2, ExitCode.FINDINGS),
        (True, 0, ExitCode.PARTIAL),  # nothing found but coverage lost: NOT clean
        (True, 2, ExitCode.PARTIAL),  # findings but coverage lost: NOT exhaustive
    ],
)
def test_live_partial_runs_exit_five_never_clean(
    partial: bool, findings: int, expected: ExitCode
) -> None:
    result = SimpleNamespace(
        state=ExecutionState.LIVE, findings=[object()] * findings, partial=partial
    )
    assert _scan_exit_code(result) is expected


class _Lossy(_Fake):
    def resolve(self, host: str) -> tuple[str, ...]:
        return ("127.0.0.1",)

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        return "2 templates failed to load" if "WARN" in output.stderr else None


@pytest.mark.parametrize(("stderr", "partial"), [("", False), ("WARN templates", True)])
def test_run_marks_a_live_result_partial_only_when_the_adapter_reports_loss(
    monkeypatch: pytest.MonkeyPatch, stderr: str, partial: bool
) -> None:
    monkeypatch.setattr(base_module, "which", lambda _b: "/usr/bin/fakebin")
    monkeypatch.setattr(
        base_module,
        "run_command",
        lambda *_a, **_k: CommandOutput(exit_code=0, stdout="ok\n", stderr=stderr),
    )
    request = ScanRequest(
        scanner="fake",
        target="127.0.0.1",
        allowed=("127.0.0.1",),
        authorized=True,
        live_enabled=True,
    )
    result = _Lossy().run(request)
    assert result.state is ExecutionState.LIVE
    assert result.partial is partial
    assert (result.partial_reason is not None) is partial
    assert _scan_exit_code(result) is (ExitCode.PARTIAL if partial else ExitCode.OK)
