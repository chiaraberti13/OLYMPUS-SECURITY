"""Portable policy and contract tests for the AEGIS sandbox boundary."""

from __future__ import annotations

import json

import pytest

from olympus.aegis.model import ScanResult
from olympus.aegis.runner import TerminationCause, TerminationReport
from olympus.aegis.sandbox import (
    DEFAULT_SANDBOX_USER,
    SandboxError,
    SandboxPolicy,
    UnprivilegedIdentity,
)
from olympus.aegis.states import ExecutionState
from olympus.cli import app
from olympus.integrations.cli import sandbox_check


def _policy(**overrides: object) -> SandboxPolicy:
    return SandboxPolicy(**overrides)  # type: ignore[arg-type]


def test_policy_rejects_limits_outside_their_bounds() -> None:
    for field, value in (
        ("cpu_seconds", 0),
        ("memory_bytes", 1024),
        ("max_processes", 0),
        ("open_files", 4),
        ("file_size_bytes", 10),
        ("grace_seconds", 600.0),
        ("user", "  "),
    ):
        with pytest.raises(SandboxError):
            _policy(**{field: value})


def test_policy_reads_the_environment_and_refuses_unparsable_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_SANDBOX_CPU_SECONDS", "120")
    monkeypatch.setenv("AEGIS_SANDBOX_MAX_PROCESSES", "8")
    monkeypatch.setenv("AEGIS_SANDBOX_GRACE_SECONDS", "1.5")
    monkeypatch.setenv("AEGIS_SANDBOX_USER", "scanner")
    policy = SandboxPolicy.from_environment()
    assert (policy.cpu_seconds, policy.max_processes, policy.user) == (120, 8, "scanner")
    assert policy.grace_seconds == 1.5

    monkeypatch.setenv("AEGIS_SANDBOX_CPU_SECONDS", "lots")
    with pytest.raises(SandboxError, match="must be an integer"):
        SandboxPolicy.from_environment()
    monkeypatch.delenv("AEGIS_SANDBOX_CPU_SECONDS")
    monkeypatch.setenv("AEGIS_SANDBOX_ALLOW_ROOT", "perhaps")
    with pytest.raises(SandboxError, match="true/false"):
        SandboxPolicy.from_environment()


def test_default_policy_targets_an_unprivileged_account() -> None:
    assert SandboxPolicy().user == DEFAULT_SANDBOX_USER


def test_unprivileged_identity_rejects_uid_zero() -> None:
    with pytest.raises(SandboxError):
        UnprivilegedIdentity(name="root", uid=0, gid=0)


def test_the_result_contract_carries_no_termination_when_nothing_ran() -> None:
    result = ScanResult(scanner="fake", state=ExecutionState.DISABLED, target="127.0.0.1")
    assert result.to_dict()["termination"] is None


def test_timeout_reports_reach_the_result_contract() -> None:
    report = TerminationReport(
        cause=TerminationCause.TIMEOUT, detail="slow", limit="timeout_seconds"
    )
    result = ScanResult(
        scanner="fake", state=ExecutionState.FAILED, target="127.0.0.1", termination=report
    )
    assert result.to_dict()["termination"] == {
        "cause": "timeout",
        "detail": "slow",
        "exit_code": None,
        "signal_name": None,
        "limit": "timeout_seconds",
        "escalated_to_kill": False,
        "process_group_signalled": False,
        "unprivileged_user": None,
    }


def test_doctor_reports_the_isolation_scanners_will_actually_get() -> None:
    from typer.testing import CliRunner

    result = CliRunner().invoke(app, ["aegis", "doctor"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    check = next(item for item in payload["checks"] if item["name"] == "sandbox:isolation")
    assert "limits cpu_seconds=" in check["detail"]
    assert "open_files=" in check["detail"]


def test_doctor_reports_a_misconfigured_sandbox_as_not_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_SANDBOX_OPEN_FILES", "unlimited")
    check = sandbox_check()
    assert check.ok is False
    assert "must be an integer" in check.detail
