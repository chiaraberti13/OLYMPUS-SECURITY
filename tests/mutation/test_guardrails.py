"""Focused mutation tests for security and correctness boundaries."""

from __future__ import annotations

import pytest

from olympus.aegis.adapters.nmap import NmapAdapter
from olympus.aegis.base import ParseError
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.athena.application.coordinator import RunOutcome
from olympus.athena.cli import _exit_code_for
from olympus.athena.domain.assessment import (
    AssessmentState,
    Job,
    JobState,
    TransitionError,
    advance_job,
    derive_terminal_state,
)
from olympus.athena.scope import TargetOutOfScopeError, ensure_target_allowed
from olympus.core.coverage import Coverage, RunStatus, exit_code_for
from olympus.core.execution import redact_mapping, redact_text
from olympus.core.exit_codes import ExitCode


def test_scope_gate_accepts_domain_and_subdomain_but_rejects_suffix_spoof() -> None:
    allowed = ("example.com",)

    assert ensure_target_allowed("domain", "example.com", allowed) == "example.com"
    assert ensure_target_allowed("domain", "api.example.com", allowed) == "api.example.com"
    assert ensure_target_allowed("domain", "API.EXAMPLE.COM.", allowed) == "api.example.com"
    with pytest.raises(TargetOutOfScopeError):
        ensure_target_allowed("domain", "notexample.com", allowed)
    with pytest.raises(TargetOutOfScopeError):
        ensure_target_allowed("domain", "attacker.invalid", allowed)


def test_redaction_covers_nested_sensitive_keys_and_url_queries() -> None:
    result = redact_mapping(
        {
            "Authorization": "Bearer hidden-auth",
            "details": [
                {
                    "api_key": "hidden-key",
                    "url": "https://example.test/?token=hidden-token&page=2#results",
                }
            ],
            "x-api-key": "hidden-header-key",
        }
    )
    serialized = str(result)

    assert result["Authorization"] == "[REDACTED]"
    assert result["details"][0]["api_key"] == "[REDACTED]"  # type: ignore[index]
    assert "hidden-auth" not in serialized
    assert "hidden-key" not in serialized
    assert "hidden-token" not in serialized
    assert "hidden-header-key" not in serialized
    assert "[REDACTED]" in serialized
    assert "page=2" in serialized
    redacted_text = redact_text("failed https://example.test/?token=hidden-token&page=2")
    assert "hidden-token" not in redacted_text
    assert "[REDACTED]" in redacted_text
    assert "page=2" in redacted_text


def test_nmap_parser_emits_only_open_ports_and_flags_high_risk_port() -> None:
    xml = (
        "<nmaprun><host><ports>"
        '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>'
        '<port protocol="tcp" portid="8000"><state state="open"/><service name="http"/></port>'
        '<port protocol="tcp" portid="443"><state state="closed"/></port>'
        "</ports></host></nmaprun>"
    )
    request = ScanRequest(scanner="nmap", target="127.0.0.1", allowed=("127.0.0.1",))
    output = CommandOutput(exit_code=0, stdout=xml, stderr="")

    findings = NmapAdapter().parse(output, "127.0.0.1", request)

    assert len(findings) == 2
    assert "23/tcp" in findings[0].title
    assert findings[0].severity.value == "medium"
    assert "port=23/tcp" in findings[0].evidence
    assert "service=telnet" in findings[0].evidence
    assert "8000/tcp" in findings[1].title
    assert findings[1].severity.value == "info"
    assert "443/tcp" not in " ".join(finding.title for finding in findings)
    with pytest.raises(ParseError):
        NmapAdapter().parse(
            CommandOutput(exit_code=0, stdout="<broken", stderr=""), "127.0.0.1", request
        )


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (RunStatus.CLEAN, ExitCode.OK),
        (RunStatus.FINDINGS, ExitCode.FINDINGS),
        (RunStatus.PARTIAL, ExitCode.PARTIAL),
        (RunStatus.FAILED, ExitCode.FAILED),
    ],
)
def test_exit_codes_preserve_run_status(status: RunStatus, expected: ExitCode) -> None:
    assert exit_code_for(status) is expected


def test_coverage_status_keeps_partial_and_failure_distinct() -> None:
    assert Coverage(planned=1, completed=1).status(0) is RunStatus.CLEAN
    assert Coverage(planned=1, completed=1).status(1) is RunStatus.FINDINGS
    assert Coverage(planned=2, completed=1, failed=1).status(1) is RunStatus.PARTIAL
    assert Coverage(planned=1, failed=1).status(0) is RunStatus.FAILED


@pytest.mark.parametrize(
    ("state", "findings", "expected"),
    [
        (AssessmentState.SUCCEEDED, [], ExitCode.OK),
        (AssessmentState.SUCCEEDED, [object()], ExitCode.FINDINGS),
        (AssessmentState.PARTIAL, [], ExitCode.PARTIAL),
        (AssessmentState.CANCELLED, [], ExitCode.CANCELLED),
        (AssessmentState.FAILED, [], ExitCode.FAILED),
    ],
)
def test_athena_exit_code_contract(state, findings, expected) -> None:
    outcome = RunOutcome(assessment_id="ASM-1", state=state, findings=findings)
    assert _exit_code_for(outcome) == expected


def test_job_state_machine_rejects_terminal_skip_and_derives_partial() -> None:
    queued = Job(job_id="JOB-1", adapter="nmap", target_kind="domain", target_value="example.com")
    running = advance_job(queued, JobState.RUNNING)
    succeeded = advance_job(running, JobState.SUCCEEDED, result_id="RES-1")

    assert succeeded.state is JobState.SUCCEEDED
    with pytest.raises(TransitionError):
        advance_job(queued, JobState.SUCCEEDED)
    with pytest.raises(TransitionError):
        advance_job(succeeded, JobState.FAILED)

    failed = Job(
        job_id="JOB-2",
        adapter="nmap",
        target_kind="domain",
        target_value="example.com",
        state=JobState.FAILED,
    )
    assert derive_terminal_state((succeeded, failed)) is AssessmentState.PARTIAL
