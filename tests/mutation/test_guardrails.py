"""Focused mutation tests for security and correctness boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

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
from olympus.core.execution import redact_mapping, redact_text, safe_terminal_text
from olympus.core.exit_codes import ExitCode
from olympus.core.models import EngagementScope
from olympus.core.signing import generate_keypair
from olympus.engagements.manifest import (
    EngagementManifest,
    ManifestAuthorizationError,
    ManifestVerificationError,
    SignedEngagementManifest,
)
from olympus.themis.adapters.nmap import NmapAdapter
from olympus.themis.api import RequestConcurrencyGate
from olympus.themis.base import ParseError
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput


def test_api_concurrency_gate_rejects_overflow_and_recovers_after_release() -> None:
    gate = RequestConcurrencyGate(1)

    assert gate.try_acquire() is True
    assert gate.try_acquire() is False
    gate.release()
    assert gate.try_acquire() is True
    gate.release()


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


def test_terminal_text_removes_control_sequences_and_redacts_secrets() -> None:
    safe = safe_terminal_text("ok\x1b]0;title\x07\r\nhttps://x.test/?token=secret")

    assert "\x1b" not in safe and "\n" not in safe
    assert "secret" not in safe and "[REDACTED]" in safe


def _signed_manifest() -> tuple[SignedEngagementManifest, str, datetime]:
    private_key, public_key = generate_keypair()
    valid_from = datetime(2026, 10, 19, tzinfo=UTC)
    manifest = EngagementManifest(
        engagement_id="ENG-2026-00001",
        client="Example Client",
        owner="Security Owner",
        approver="Authorized Approver",
        contract_id="CONTRACT-2026-01",
        scope=EngagementScope(included=("example.com",), excluded=("admin.example.com",)),
        valid_from=valid_from,
        expires_at=valid_from + timedelta(hours=8),
        allowed_techniques=("nmap",),
    )
    return (
        SignedEngagementManifest.sign_manifest(manifest, private_key_pem=private_key),
        public_key,
        valid_from,
    )


def test_signed_manifest_gate_enforces_trusted_signature_and_scope() -> None:
    signed, public_key, valid_from = _signed_manifest()
    authorized = signed.authorize(
        trusted_public_key_pem=public_key,
        target="www.example.com",
        technique="nmap",
        now=valid_from,
    )
    assert authorized.engagement_id == "ENG-2026-00001"

    with pytest.raises(ManifestAuthorizationError):
        signed.authorize(
            trusted_public_key_pem=public_key,
            target="admin.example.com",
            technique="nmap",
            now=valid_from,
        )
    with pytest.raises(ManifestAuthorizationError):
        signed.authorize(
            trusted_public_key_pem=public_key,
            target="www.example.com",
            technique="nmap",
            now=signed.manifest.expires_at,
        )

    _other_private, other_public = generate_keypair()
    with pytest.raises(ManifestVerificationError):
        signed.authorize(
            trusted_public_key_pem=other_public,
            target="www.example.com",
            technique="nmap",
            now=valid_from,
        )


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
