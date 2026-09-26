"""POSIX-only integration tests for AEGIS scanner process isolation.

These exercise the real kernel behaviour — a real fork/exec, real ``setrlimit``
violations, a real SIGTERM that a child ignores — because the guarantee being
tested is the kernel's, not the code's opinion of itself. Nothing here mocks
the process boundary.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from olympus.aegis.base import ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import (
    CommandError,
    CommandOutput,
    CommandOutputLimit,
    CommandTimeout,
    TerminationCause,
    run_command,
)
from olympus.aegis.sandbox import (
    DEFAULT_SANDBOX_USER,
    SandboxError,
    SandboxPolicy,
)
from olympus.aegis.states import ExecutionState
from olympus.core.execution import CancellationRequested, CancellationToken

pytestmark = pytest.mark.posix_only


def _policy(**overrides: object) -> SandboxPolicy:
    # Kernel-limit tests do not need a privilege transition. Keep that separate
    # from the explicitly root-only test so rootful developer containers with
    # restricted chown still exercise every other POSIX guarantee.
    overrides.setdefault("effective_uid", 1000)
    return SandboxPolicy(**overrides)  # type: ignore[arg-type]


# --- privilege drop -------------------------------------------------------- #
def test_no_drop_is_attempted_when_the_parent_is_already_unprivileged() -> None:
    assert _policy(effective_uid=1000).resolve_identity() is None


def test_running_as_root_is_refused_when_no_unprivileged_account_exists() -> None:
    policy = _policy(effective_uid=0, user="olympus-no-such-account")
    with pytest.raises(SandboxError, match="refusing to run a scanner as root"):
        policy.resolve_identity()
    # The opt-out is explicit, documented, and never the fallback.
    permissive = _policy(effective_uid=0, user="olympus-no-such-account", allow_root=True)
    assert permissive.resolve_identity() is None


def test_root_is_refused_even_when_the_configured_account_is_root() -> None:
    with pytest.raises(SandboxError, match="uid 0"):
        _policy(effective_uid=0, user="root").resolve_identity()


def test_run_command_refuses_when_isolation_cannot_be_established() -> None:
    with pytest.raises(CommandError, match="refusing to run a scanner as root") as caught:
        run_command(
            ["true"],
            timeout=5,
            sandbox=_policy(effective_uid=0, user="olympus-no-such-account"),
        )
    assert caught.value.report.cause is TerminationCause.SANDBOX_DENIED


@pytest.mark.root_only
def test_scanner_runs_as_an_unprivileged_user_when_started_as_root() -> None:
    output = run_command(["id", "-u"], timeout=15)
    assert output.stdout.strip() not in {"", "0"}
    assert output.termination is not None
    assert output.termination.unprivileged_user == DEFAULT_SANDBOX_USER


# --- resource limits ------------------------------------------------------- #
def test_resource_limits_are_applied_inside_the_child() -> None:
    policy = _policy(open_files=64, max_processes=17, memory_bytes=512 * 1024 * 1024)
    script = (
        "import json,resource;"
        "print(json.dumps({"
        "'nofile': resource.getrlimit(resource.RLIMIT_NOFILE),"
        "'core': resource.getrlimit(resource.RLIMIT_CORE),"
        "'nproc': resource.getrlimit(resource.RLIMIT_NPROC),"
        "'as': resource.getrlimit(resource.RLIMIT_AS)}))"
    )
    output = run_command([sys.executable, "-c", script], timeout=30, sandbox=policy)
    limits = json.loads(output.stdout)
    assert limits["nofile"] == [64, 64]
    assert limits["core"] == [0, 0]
    assert limits["nproc"] == [17, 17]
    assert limits["as"] == [512 * 1024 * 1024, 512 * 1024 * 1024]


def test_cpu_limit_is_enforced_by_the_kernel_with_a_structured_cause() -> None:
    output = run_command(
        [sys.executable, "-c", "\nwhile True:\n    pass\n"],
        timeout=60,
        sandbox=_policy(cpu_seconds=1),
    )
    assert output.exit_code < 0
    assert output.termination is not None
    assert output.termination.cause is TerminationCause.RESOURCE_LIMIT
    assert output.termination.limit == "cpu_seconds"
    assert output.termination.signal_name == "SIGXCPU"


def test_file_size_limit_bounds_temporary_space_with_a_structured_cause() -> None:
    # `dd` writes into the run's private scratch directory (its working
    # directory) and, unlike CPython, does not ignore SIGXFSZ — so this is the
    # kernel stopping a scanner that fills the disk, not a cooperating process.
    output = run_command(
        ["dd", "if=/dev/zero", "of=big", "bs=1048576", "count=4"],
        timeout=60,
        sandbox=_policy(file_size_bytes=1024 * 1024),
    )
    assert output.exit_code < 0
    assert output.termination is not None
    assert output.termination.cause is TerminationCause.RESOURCE_LIMIT
    assert output.termination.limit == "file_size_bytes"
    assert output.termination.signal_name == "SIGXFSZ"


def test_the_file_size_limit_also_stops_a_process_that_handles_the_error() -> None:
    # CPython ignores SIGXFSZ and surfaces EFBIG instead: the write must still
    # fail, so the limit holds for scanners written in Python too.
    script = (
        "import os;"
        "path=os.path.join(os.environ['TMPDIR'],'big');"
        "handle=open(path,'wb');"
        "handle.write(b'x'*(4*1024*1024));"
        "handle.flush()"
    )
    output = run_command(
        [sys.executable, "-c", script], timeout=60, sandbox=_policy(file_size_bytes=1024 * 1024)
    )
    assert output.exit_code != 0
    assert "File too large" in output.stderr or "EFBIG" in output.stderr


# --- isolated scratch space ------------------------------------------------ #
def test_each_run_gets_a_private_scratch_directory_that_is_removed_afterwards() -> None:
    script = (
        "import json,os,stat;"
        "temp=os.environ['TMPDIR'];"
        "print(json.dumps({'tmp': temp, 'home': os.environ['HOME'], 'cwd': os.getcwd(),"
        " 'mode': stat.S_IMODE(os.stat(temp).st_mode)}))"
    )
    output = run_command([sys.executable, "-c", script], timeout=30)
    seen = json.loads(output.stdout)
    assert seen["tmp"] == seen["home"] == seen["cwd"]
    assert seen["mode"] == 0o700
    assert not Path(seen["tmp"]).exists(), "the scratch directory must not outlive the run"


def test_two_runs_never_share_a_scratch_directory() -> None:
    script = "import os;print(os.environ['TMPDIR'])"
    first = run_command([sys.executable, "-c", script], timeout=30).stdout.strip()
    second = run_command([sys.executable, "-c", script], timeout=30).stdout.strip()
    assert first and second and first != second


# --- terminate → kill escalation ------------------------------------------- #
def test_a_child_that_ignores_sigterm_is_escalated_to_sigkill() -> None:
    script = "import signal,time;signal.signal(signal.SIGTERM, signal.SIG_IGN);time.sleep(60)"
    started = time.monotonic()
    with pytest.raises(CommandTimeout) as caught:
        run_command([sys.executable, "-c", script], timeout=0.5, sandbox=_policy(grace_seconds=0.5))
    report = caught.value.report
    assert report.cause is TerminationCause.TIMEOUT
    assert report.limit == "timeout_seconds"
    assert report.escalated_to_kill is True
    assert report.process_group_signalled is True
    assert time.monotonic() - started < 30, "escalation must not wait for the child to finish"


def test_a_cooperative_child_is_stopped_by_sigterm_without_escalation() -> None:
    with pytest.raises(CommandTimeout) as caught:
        run_command([sys.executable, "-c", "import time;time.sleep(60)"], timeout=0.5)
    assert caught.value.report.escalated_to_kill is False
    assert caught.value.report.process_group_signalled is True


@pytest.mark.linux_only
def test_the_whole_process_group_dies_not_just_the_scanner(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)  # the child may run as a different, unprivileged user
    script = (
        "import subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(120)']);"
        "open('grandchild.pid','w').write(str(child.pid));"
        "time.sleep(120)"
    )
    with pytest.raises(CommandTimeout):
        run_command([sys.executable, "-c", script], timeout=5, cwd=shared)
    pid = int((shared / "grandchild.pid").read_text())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not _process_is_gone(pid):
        time.sleep(0.1)
    assert _process_is_gone(pid), f"grandchild {pid} outlived its process group"


def _process_is_gone(pid: int) -> bool:
    """True when ``pid`` no longer runs (a reaped-by-init zombie counts)."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return True
    return state.rsplit(")", 1)[-1].split()[0] == "Z"


# --- structured causes on every other exit path ---------------------------- #
def test_output_limit_and_cancellation_carry_their_own_causes() -> None:
    with pytest.raises(CommandOutputLimit) as caught:
        run_command([sys.executable, "-c", "print('x'*100000)"], timeout=30, max_output_bytes=100)
    assert caught.value.report.cause is TerminationCause.OUTPUT_LIMIT
    assert caught.value.report.limit == "max_output_bytes"

    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        run_command(["true"], timeout=5, cancellation=token)


def test_a_clean_exit_is_reported_as_completed() -> None:
    output = run_command(["true"], timeout=10)
    assert output.termination is not None
    assert output.termination.cause is TerminationCause.COMPLETED
    assert output.termination.exit_code == 0


def test_a_fatal_signal_is_distinguished_from_a_resource_violation() -> None:
    output = run_command(["sh", "-c", "kill -9 $$"], timeout=30)
    assert output.termination is not None
    assert output.termination.cause is TerminationCause.SIGNALLED
    assert output.termination.signal_name == "SIGKILL"


def test_missing_binary_reports_a_start_failure() -> None:
    with pytest.raises(CommandError) as caught:
        run_command(["definitely-not-a-real-binary-xyz"], timeout=5)
    assert caught.value.report.cause is TerminationCause.START_FAILED


# --- the cause reaches the persisted result contract ----------------------- #
class _SignalledAdapter(ScannerAdapter):
    name = "fake"
    binary = "sh"
    install = "n/a"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        return ["sh", "-c", "kill -9 $$"]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list:  # type: ignore[type-arg]
        raise AssertionError("a killed scanner must never reach the parser")


def test_a_killed_scanner_fails_with_a_recorded_cause() -> None:
    result = _SignalledAdapter().run(
        ScanRequest(
            scanner="fake",
            target="127.0.0.1",
            allowed=("127.0.0.1",),
            authorized=True,
            live_enabled=True,
        )
    )
    assert result.state is ExecutionState.FAILED
    assert result.termination is not None
    assert result.termination.cause is TerminationCause.SIGNALLED
    assert "SIGKILL" in (result.error or "")
    document = result.to_dict()
    assert document["schema_version"] == "1.1.0"
    recorded = document["termination"]
    assert isinstance(recorded, dict)
    assert recorded["cause"] == "signalled"
    assert recorded["signal_name"] == "SIGKILL"
