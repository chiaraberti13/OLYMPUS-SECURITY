"""Cross-module contract for terminal states and process exit codes."""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from olympus.athena.application.coordinator import RunOutcome
from olympus.athena.cli import _exit_code_for
from olympus.athena.domain.assessment import AssessmentState
from olympus.core.coverage import RunStatus, exit_code_for
from olympus.core.exit_codes import EXIT_ENGINE_MISSING, ExitCode, normalize_exit_code
from olympus.integrations.cli import _job_exit_code, _scan_exit_code
from olympus.themis.states import ExecutionState


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
def test_themis_reduces_execution_states_to_the_shared_contract(
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
def test_themis_jobs_reduce_lifecycle_states_to_the_shared_contract(
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


@pytest.mark.contract
def test_exit_code_contract_is_exactly_zero_to_eight() -> None:
    assert {code.value for code in ExitCode} == set(range(9))
    assert ExitCode.ENGINE_MISSING == 8
    assert EXIT_ENGINE_MISSING is ExitCode.ENGINE_MISSING


@pytest.mark.contract
def test_engine_missing_is_a_canonical_code_and_unknown_codes_stay_failed() -> None:
    assert normalize_exit_code(8) is ExitCode.ENGINE_MISSING
    assert normalize_exit_code(9) is ExitCode.FAILED
    assert normalize_exit_code(-1) is ExitCode.FAILED


@pytest.mark.contract
def test_engine_missing_is_never_confused_with_partial_or_failed() -> None:
    # 5 = ran with reduced coverage, 6 = ran and failed, 8 = refused to start.
    assert len({ExitCode.PARTIAL, ExitCode.FAILED, ExitCode.ENGINE_MISSING}) == 3


@pytest.mark.contract
def test_tui_labels_every_exit_code() -> None:
    from olympus.tui.app import _EXIT_LABELS, describe_completion

    assert set(_EXIT_LABELS) == set(ExitCode)
    status, _, style = describe_completion(False, ExitCode.ENGINE_MISSING)
    assert "mandatory engine" in status
    assert style == "red"


@pytest.mark.contract
@pytest.mark.parametrize(
    "document",
    ["README.md", "README.it.md", "docs/run-status.md", "docs/reference.md"],
)
def test_documentation_lists_exit_code_8(document: str) -> None:
    text = (Path(__file__).parents[2] / document).read_text(encoding="utf-8")
    assert "`8`" in text, f"{document} does not document exit code 8"
