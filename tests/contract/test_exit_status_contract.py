"""Cross-module contract for terminal states and process exit codes."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from olympus.aegis.states import ExecutionState
from olympus.athena.application.coordinator import RunOutcome
from olympus.athena.cli import _exit_code_for
from olympus.athena.domain.assessment import AssessmentState
from olympus.core.coverage import RunStatus, exit_code_for
from olympus.core.exit_codes import ExitCode
from olympus.integrations.cli import _job_exit_code, _scan_exit_code


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (RunStatus.CLEAN, ExitCode.OK),
        (RunStatus.FINDINGS, ExitCode.FINDINGS),
        (RunStatus.PARTIAL, ExitCode.PARTIAL),
        (RunStatus.FAILED, ExitCode.FAILED),
        (RunStatus.CANCELLED, ExitCode.CANCELLED),
    ],
)
def test_every_terminal_status_has_one_exit_code(status: RunStatus, expected: ExitCode) -> None:
    assert exit_code_for(status) is expected


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (AssessmentState.SUCCEEDED, ExitCode.OK),
        (AssessmentState.PARTIAL, ExitCode.PARTIAL),
        (AssessmentState.FAILED, ExitCode.FAILED),
        (AssessmentState.CANCELLED, ExitCode.CANCELLED),
    ],
)
def test_athena_reduces_domain_states_to_the_shared_contract(
    state: AssessmentState, expected: ExitCode
) -> None:
    outcome = RunOutcome(assessment_id="ASM-CONTRACT", state=state, findings=[])
    assert _exit_code_for(outcome) == expected


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (ExecutionState.LIVE, ExitCode.OK),
        (ExecutionState.UNAVAILABLE, ExitCode.FAILED),
        (ExecutionState.FAILED, ExitCode.FAILED),
        (ExecutionState.DISABLED, ExitCode.NOT_AUTHORIZED),
        (ExecutionState.SIMULATION, ExitCode.OK),
    ],
)
def test_aegis_reduces_execution_states_to_the_shared_contract(
    state: ExecutionState, expected: ExitCode
) -> None:
    assert _scan_exit_code(SimpleNamespace(state=state, findings=[])) is expected


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("succeeded", ExitCode.OK),
        ("partial", ExitCode.PARTIAL),
        ("failed", ExitCode.FAILED),
        ("timed_out", ExitCode.FAILED),
        ("cancelled", ExitCode.CANCELLED),
        ("policy_denied", ExitCode.NOT_AUTHORIZED),
    ],
)
def test_aegis_jobs_reduce_lifecycle_states_to_the_shared_contract(
    state: str, expected: ExitCode
) -> None:
    job = SimpleNamespace(state=SimpleNamespace(value=state), result={"finding_count": 0})
    assert _job_exit_code(job) is expected


def test_cli_modules_do_not_embed_numeric_typer_exit_codes() -> None:
    root = Path(__file__).parents[2] / "src" / "olympus"
    violations: list[str] = []
    for path in sorted(root.rglob("cli.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "Exit":
                continue
            code = next((item.value for item in node.keywords if item.arg == "code"), None)
            if isinstance(code, ast.Constant) and isinstance(code.value, int):
                violations.append(f"{path.relative_to(root)}:{node.lineno}")
    assert violations == [], "numeric Typer exit codes bypass the shared contract: " + ", ".join(
        violations
    )
