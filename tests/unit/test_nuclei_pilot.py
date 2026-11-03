"""Pilot engine (TOOLS-4): nuclei through the whole adapter path, offline.

Fixtures are real nuclei v3.11.1 output (templates v10.5.1 @ 79fb682) captured against a
local lab server; see ``tests/fixtures/themis/nuclei/README.md``. Nothing here touches a
network: the process runner and the DNS resolver are injected, and the injected runner
fails the test if it is ever called for a request that must be refused first.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.core.enums import Severity
from olympus.core.exit_codes import ExitCode
from olympus.integrations.cli import _scan_exit_code
from olympus.themis import base as base_module
from olympus.themis.adapters.nuclei import NucleiAdapter
from olympus.themis.base import NotAuthorizedError
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput, TerminationCause, TerminationReport
from olympus.themis.scope import OutOfScopeError, SsrfBlockedError
from olympus.themis.states import ExecutionState

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).parents[1] / "fixtures" / "themis" / "nuclei"
COMPLETED = TerminationReport(cause=TerminationCause.COMPLETED, exit_code=0)
TARGET = "http://127.0.0.1:8099"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class _Lab(NucleiAdapter):
    """The real adapter with the DNS resolver injected (no lookup ever happens)."""

    def resolve(self, host: str) -> tuple[str, ...]:
        return ("127.0.0.1",)


def _request(**changes: object) -> ScanRequest:
    values: dict[str, object] = {
        "scanner": "nuclei",
        "target": TARGET,
        "target_kind": "url",
        "allowed": ("127.0.0.1",),
        "authorized": True,
        "live_enabled": True,
    }
    values.update(changes)
    return ScanRequest(**values)  # type: ignore[arg-type]


class _Runner:
    """Fake process runner: records every argv, replays one canned nuclei output."""

    def __init__(self, stdout: str = "", stderr: str = "", exit_code: int = 0) -> None:
        self.calls: list[list[str]] = []
        self._output = CommandOutput(exit_code, stdout, stderr, COMPLETED)

    def __call__(self, argv: list[str], **_kwargs: object) -> CommandOutput:
        self.calls.append(argv)
        if argv[1:] and argv[1] in {"--version", "-version", "-V"}:
            return CommandOutput(0, "", "[INF] Nuclei Engine Version: v3.11.1\n", COMPLETED)
        return self._output

    @property
    def scans(self) -> list[list[str]]:
        return [call for call in self.calls if "-target" in call]


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base_module, "which", lambda _binary: "/usr/local/bin/nuclei")


def _run(runner: _Runner, monkeypatch: pytest.MonkeyPatch, **changes: object):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(base_module, "run_command", runner)
    return _Lab().run(_request(**changes))


# --- the four output cases ------------------------------------------------- #
def test_multiple_findings(installed: None, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run(_Runner(_fixture("multiple.jsonl")), monkeypatch)
    assert result.state is ExecutionState.LIVE and result.partial is False
    assert len(result.findings) == 10
    assert {f.severity for f in result.findings} == {Severity.INFO}
    assert all("http-missing-security-headers" in f.title for f in result.findings)
    assert _scan_exit_code(result) is ExitCode.FINDINGS


def test_single_template_two_findings(installed: None, monkeypatch: pytest.MonkeyPatch) -> None:
    result = _run(_Runner(_fixture("tech-detect.jsonl")), monkeypatch)
    assert len(result.findings) == 2 and result.partial is False
    assert result.version == "[INF] Nuclei Engine Version: v3.11.1"


def test_no_findings_is_a_clean_result_not_a_failure(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run(_Runner(_fixture("none.jsonl")), monkeypatch)
    assert result.state is ExecutionState.LIVE
    assert result.findings == [] and result.partial is False
    assert _scan_exit_code(result) is ExitCode.OK


def test_malformed_records_make_the_run_partial_never_clean(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run(_Runner(_fixture("malformed.jsonl")), monkeypatch)
    assert result.state is ExecutionState.LIVE
    assert len(result.findings) == 5  # the five good records survive
    assert result.partial is True
    # Only the truncated JSON record counts: a stray non-JSON stdout line is ignored as noise
    # by design (the adapter only reads lines that start with '{').
    assert result.partial_reason is not None
    assert "1 nuclei output record(s)" in result.partial_reason
    assert _scan_exit_code(result) is ExitCode.PARTIAL  # 5, not 1 and not 0
    document = result.to_dict()
    assert document["schema_version"] == "1.3.0" and document["partial"] is True


def test_output_with_no_usable_record_is_a_failure_not_a_clean_empty(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    for garbage in ("[FTL] Could not run nuclei\n", '{"template-id": "cut off\n', "{}\n"):
        result = _run(_Runner(garbage), monkeypatch)
        assert result.state is ExecutionState.FAILED, garbage
        assert "parse failed" in (result.error or "")
        assert _scan_exit_code(result) is ExitCode.FAILED


def test_a_nonzero_exit_is_failed_even_with_valid_records(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _run(_Runner(_fixture("multiple.jsonl"), exit_code=2), monkeypatch)
    assert result.state is ExecutionState.FAILED and result.findings == []


# --- the command line ------------------------------------------------------ #
def test_the_runner_receives_only_manifest_flags_and_the_two_values(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("THEMIS_NUCLEI_TEMPLATES", "/opt/nuclei-templates")
    runner = _Runner(_fixture("none.jsonl"))
    _run(runner, monkeypatch)
    (argv,) = runner.scans
    assert argv[:5] == ["nuclei", "-target", TARGET, "-templates", "/opt/nuclei-templates"]
    assert "-omit-raw" in argv and "-no-interactsh" in argv and "-disable-update-check" in argv
    assert not any(
        token in argv for token in ("-update-templates", "-ut", "-proxy", "-l", "-config")
    )


# --- scope gating is unchanged and runs before any process ------------------ #
def _forbid(*_args: object, **_kwargs: object) -> CommandOutput:
    raise AssertionError("nuclei must not be started for a request that has to be refused")


def test_an_out_of_scope_target_is_refused_before_anything_runs(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(base_module, "run_command", _forbid)
    for target, kind in (("http://8.8.8.8/", "url"), ("8.8.8.8", "host"), ("evil.example", "host")):
        with pytest.raises(OutOfScopeError):
            _Lab().run(_request(target=target, target_kind=kind))
    # A non-global address that is not explicitly authorized is an SSRF block, also refused.
    with pytest.raises(SsrfBlockedError):
        _Lab().run(_request(target="http://203.0.113.9/"))


def test_a_hostname_resolving_into_a_private_range_is_blocked(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Rebinding(NucleiAdapter):
        def resolve(self, host: str) -> tuple[str, ...]:
            return ("169.254.169.254",)  # cloud metadata address

    monkeypatch.setattr(base_module, "run_command", _forbid_scan_only)
    with pytest.raises(SsrfBlockedError):
        _Rebinding().run(
            _request(target="http://lab.example/", allowed=(), allowed_domains=("lab.example",))
        )


def _forbid_scan_only(argv: list[str], **kwargs: object) -> CommandOutput:
    if "-target" in argv:
        raise AssertionError("the scan itself must not start")
    return CommandOutput(0, "", "v3.11.1", COMPLETED)


def test_an_unauthorized_live_request_is_refused(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(base_module, "run_command", _forbid)
    with pytest.raises(NotAuthorizedError):
        _Lab().run(_request(authorized=False))


def test_a_missing_engine_is_unavailable_and_nothing_is_resolved_or_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _NoDns(NucleiAdapter):
        def resolve(self, host: str) -> tuple[str, ...]:
            raise AssertionError("no DNS lookup before the presence check")

    monkeypatch.setattr(base_module, "which", lambda _binary: None)
    monkeypatch.setattr(base_module, "run_command", _forbid)
    result = _NoDns().run(_request())
    assert result.state is ExecutionState.UNAVAILABLE
    assert result.dependency is not None and _scan_exit_code(result) is ExitCode.FAILED


@pytest.mark.parametrize("target", ["-update-templates", "http://-evil/"])
def test_a_flag_shaped_target_is_rejected_before_any_process(
    installed: None, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    from olympus.themis.scope import TargetValidationError

    monkeypatch.setattr(base_module, "run_command", _forbid)
    with pytest.raises((TargetValidationError, OutOfScopeError)):
        _Lab().run(_request(target=target))


def test_text_after_a_space_in_a_url_stays_inside_the_single_target_argument(
    installed: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whitespace in a URL path is odd but harmless: argv elements are never split."""
    runner = _Runner(_fixture("none.jsonl"))
    target = "http://127.0.0.1/ -update-templates"
    _run(runner, monkeypatch, target=target)
    (argv,) = runner.scans
    assert argv[argv.index("-target") + 1] == target
    assert "-update-templates" not in argv  # never a separate argv token
