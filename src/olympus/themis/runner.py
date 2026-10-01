"""Bounded, isolated, cancellable, shell-free subprocess execution for THEMIS.

Every scanner runs in its own session and process group, as an unprivileged
user, under kernel-enforced resource limits, with a private scratch directory,
and with a structured reason recorded for however it ended. See
:mod:`olympus.themis.sandbox` for the isolation policy itself.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from olympus.core.execution import Cancellation, CancellationRequested, NeverCancelled
from olympus.themis.sandbox import (
    SandboxError,
    SandboxPolicy,
    UnprivilegedIdentity,
    apply_resource_limits,
)


class TerminationCause(StrEnum):
    """Why a scanner process stopped running."""

    #: The process ran to completion and set its own exit status.
    COMPLETED = "completed"
    #: The per-command timeout elapsed and the process group was terminated.
    TIMEOUT = "timeout"
    #: Cooperative cancellation was requested by the caller.
    CANCELLED = "cancelled"
    #: Combined stdout/stderr passed the byte budget.
    OUTPUT_LIMIT = "output_limit"
    #: The kernel enforced a resource limit (CPU time, file size, ...).
    RESOURCE_LIMIT = "resource_limit"
    #: The process died from a signal nobody in Olympus sent it.
    SIGNALLED = "signalled"
    #: The process never started (missing binary, bad argv, exec failure).
    START_FAILED = "start_failed"
    #: The required isolation could not be established, so nothing was run.
    SANDBOX_DENIED = "sandbox_denied"


#: Signals the kernel raises when a process crosses one of its rlimits.
_RESOURCE_SIGNALS: dict[int, str] = {
    int(getattr(signal, "SIGXCPU", -1)): "cpu_seconds",
    int(getattr(signal, "SIGXFSZ", -1)): "file_size_bytes",
}


@dataclass(frozen=True)
class TerminationReport:
    """The structured, redaction-safe reason a command ended."""

    cause: TerminationCause
    detail: str = ""
    exit_code: int | None = None
    signal_name: str | None = None
    #: Name of the limit that was crossed (``cpu_seconds``, ``timeout_seconds``...).
    limit: str | None = None
    #: True when SIGTERM was ignored and SIGKILL had to follow.
    escalated_to_kill: bool = False
    #: True when the signal was delivered to the whole process group.
    process_group_signalled: bool = False
    unprivileged_user: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return the JSON-compatible mapping persisted with a scan result."""
        return {
            "cause": str(self.cause),
            "detail": self.detail,
            "exit_code": self.exit_code,
            "signal_name": self.signal_name,
            "limit": self.limit,
            "escalated_to_kill": self.escalated_to_kill,
            "process_group_signalled": self.process_group_signalled,
            "unprivileged_user": self.unprivileged_user,
        }


class CommandTimeout(RuntimeError):
    """Raised when a scanner exceeds its timeout and is terminated."""

    def __init__(self, message: str, report: TerminationReport | None = None) -> None:
        super().__init__(message)
        self.report = report or TerminationReport(cause=TerminationCause.TIMEOUT, detail=message)


class CommandError(RuntimeError):
    """Raised when a scanner process cannot be started or exits unsuccessfully."""

    def __init__(self, message: str, report: TerminationReport | None = None) -> None:
        super().__init__(message)
        self.report = report or TerminationReport(
            cause=TerminationCause.START_FAILED, detail=message
        )


class CommandOutputLimit(CommandError):
    """Raised when combined stdout/stderr exceeds its byte budget."""

    def __init__(self, message: str, report: TerminationReport | None = None) -> None:
        super().__init__(
            message,
            report
            or TerminationReport(
                cause=TerminationCause.OUTPUT_LIMIT, detail=message, limit="max_output_bytes"
            ),
        )


@dataclass(frozen=True)
class CommandOutput:
    """The bounded captured result of a completed subprocess."""

    exit_code: int
    stdout: str
    stderr: str
    termination: TerminationReport | None = None


def which(binary: str) -> str | None:
    """Return the resolved path of ``binary`` on PATH, or ``None``."""
    return shutil.which(binary)


def run_command(
    argv: list[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    max_output_bytes: int = 5_000_000,
    cancellation: Cancellation | None = None,
    environment: Mapping[str, str] | None = None,
    sandbox: SandboxPolicy | None = None,
) -> CommandOutput:
    """Run a fixed argv in an isolated, bounded, cancellable child process."""
    if not argv or not argv[0] or any("\x00" in argument for argument in argv):
        raise CommandError("command arguments must be non-empty and contain no NUL")
    if not 0.05 <= timeout <= 3_600:
        raise CommandError("command timeout must be between 0.05 and 3600 seconds")
    if not 1 <= max_output_bytes <= 100_000_000:
        raise CommandError("max_output_bytes must be between 1 and 100000000")
    working_directory: str | None = None
    if cwd is not None:
        path = Path(cwd)
        if path.is_symlink() or not path.is_dir():
            raise CommandError(f"command cwd must be a non-symlink directory: {path}")
        working_directory = str(path)
    resolved = which(argv[0])
    if resolved is None:
        raise CommandError(f"executable not found: {argv[0]}")
    try:
        policy = sandbox if sandbox is not None else SandboxPolicy.from_environment()
        identity = policy.resolve_identity()
    except SandboxError as exc:
        raise CommandError(
            str(exc),
            TerminationReport(cause=TerminationCause.SANDBOX_DENIED, detail=str(exc)),
        ) from exc
    token = cancellation or NeverCancelled()
    if token.is_cancelled():
        raise CancellationRequested("operation cancelled")

    workspace = _make_workspace(identity)
    try:
        return _run_in_workspace(
            argv,
            resolved=resolved,
            timeout=timeout,
            working_directory=working_directory or workspace,
            workspace=workspace,
            max_output_bytes=max_output_bytes,
            token=token,
            environment=environment,
            policy=policy,
            identity=identity,
        )
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def _run_in_workspace(
    argv: list[str],
    *,
    resolved: str,
    timeout: float,
    working_directory: str,
    workspace: str,
    max_output_bytes: int,
    token: Cancellation,
    environment: Mapping[str, str] | None,
    policy: SandboxPolicy,
    identity: UnprivilegedIdentity | None,
) -> CommandOutput:
    start_new_session = os.name == "posix"
    user = identity.name if identity is not None else None
    try:
        process = subprocess.Popen(  # noqa: S603 - resolved executable, fixed argument vector
            [resolved, *argv[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_directory,
            env=_subprocess_environment(environment, workspace),
            start_new_session=start_new_session,
            # The privilege drop is done by subprocess itself, in C, before the
            # hook below runs — no Python executes between fork and setuid.
            user=identity.uid if identity is not None else None,
            group=identity.gid if identity is not None else None,
            extra_groups=[] if identity is not None else None,
            umask=0o077 if os.name == "posix" else -1,
            # Resource limits have no Popen parameter, so they are lowered in
            # the one hook that runs in the child before exec.
            preexec_fn=((lambda: apply_resource_limits(policy)) if os.name == "posix" else None),
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise CommandError(
            f"could not start {argv[0]}: {exc}",
            TerminationReport(
                cause=TerminationCause.START_FAILED,
                detail=str(exc),
                unprivileged_user=user,
            ),
        ) from exc
    stdout_pipe, stderr_pipe = process.stdout, process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        _terminate(process, start_new_session, policy.grace_seconds)
        raise CommandError("scanner process pipes were not created")

    stdout = bytearray()
    stderr = bytearray()
    total = [0]
    lock = threading.Lock()
    exceeded = threading.Event()
    readers = [
        threading.Thread(
            target=_read_pipe,
            args=(stdout_pipe, stdout, max_output_bytes, total, lock, exceeded),
            daemon=True,
        ),
        threading.Thread(
            target=_read_pipe,
            args=(stderr_pipe, stderr, max_output_bytes, total, lock, exceeded),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    stop: TerminationCause | None = None
    try:
        while process.poll() is None:
            if token.is_cancelled():
                stop = TerminationCause.CANCELLED
                break
            if exceeded.is_set():
                stop = TerminationCause.OUTPUT_LIMIT
                break
            if time.monotonic() >= deadline:
                stop = TerminationCause.TIMEOUT
                break
            time.sleep(0.02)
    except BaseException:
        _terminate(process, start_new_session, policy.grace_seconds)
        _join(readers)
        raise
    # A process that exited on its own may still have breached a budget in the
    # same instant; those checks decide the outcome before the exit status does.
    if stop is None and token.is_cancelled():
        stop = TerminationCause.CANCELLED
    if stop is None and exceeded.is_set():
        stop = TerminationCause.OUTPUT_LIMIT
    if stop is not None:
        signalled, escalated = _terminate(process, start_new_session, policy.grace_seconds)
        _join(readers)
        raise _stop_error(
            stop,
            binary=argv[0],
            timeout=timeout,
            max_output_bytes=max_output_bytes,
            process_group_signalled=signalled,
            escalated=escalated,
            user=user,
        )
    _join(readers)
    return CommandOutput(
        exit_code=int(process.returncode),
        stdout=stdout.decode("utf-8", errors="replace"),
        stderr=stderr.decode("utf-8", errors="replace"),
        termination=_exit_report(int(process.returncode), argv[0], user),
    )


def _make_workspace(identity: UnprivilegedIdentity | None) -> str:
    """Create the private ``0700`` scratch directory used for one command."""
    workspace = tempfile.mkdtemp(prefix="olympus-themis-")
    try:
        Path(workspace).chmod(0o700)  # owner-only, explicitly not group/world
        if identity is not None:
            os.chown(workspace, identity.uid, identity.gid)
    except OSError as exc:
        shutil.rmtree(workspace, ignore_errors=True)
        raise CommandError(
            f"could not prepare an isolated scratch directory: {exc}",
            TerminationReport(cause=TerminationCause.SANDBOX_DENIED, detail=str(exc)),
        ) from exc
    return workspace


def _stop_error(
    cause: TerminationCause,
    *,
    binary: str,
    timeout: float,
    max_output_bytes: int,
    process_group_signalled: bool,
    escalated: bool,
    user: str | None,
) -> BaseException:
    if cause is TerminationCause.CANCELLED:
        return CancellationRequested("operation cancelled")
    if cause is TerminationCause.OUTPUT_LIMIT:
        message = f"{binary} output exceeds the {max_output_bytes} byte limit"
        limit = "max_output_bytes"
    else:
        message = f"{binary} exceeded {timeout:g}s and was terminated"
        limit = "timeout_seconds"
    report = TerminationReport(
        cause=cause,
        detail=message,
        limit=limit,
        escalated_to_kill=escalated,
        process_group_signalled=process_group_signalled,
        unprivileged_user=user,
    )
    if cause is TerminationCause.OUTPUT_LIMIT:
        return CommandOutputLimit(message, report)
    return CommandTimeout(message, report)


def _exit_report(returncode: int, binary: str, user: str | None) -> TerminationReport:
    """Classify a self-determined exit status, including fatal signals."""
    if returncode >= 0:
        return TerminationReport(
            cause=TerminationCause.COMPLETED, exit_code=returncode, unprivileged_user=user
        )
    number = -returncode
    name = signal.Signals(number).name if number in set(signal.Signals) else f"SIG{number}"
    limit = _RESOURCE_SIGNALS.get(number)
    if limit is not None:
        return TerminationReport(
            cause=TerminationCause.RESOURCE_LIMIT,
            detail=f"{binary} exceeded its {limit} limit and was killed by {name}",
            exit_code=returncode,
            signal_name=name,
            limit=limit,
            unprivileged_user=user,
        )
    return TerminationReport(
        cause=TerminationCause.SIGNALLED,
        detail=f"{binary} was killed by {name}",
        exit_code=returncode,
        signal_name=name,
        unprivileged_user=user,
    )


def _join(readers: list[threading.Thread]) -> None:
    for reader in readers:
        reader.join(timeout=1.0)


def _read_pipe(
    pipe: BinaryIO,
    destination: bytearray,
    maximum: int,
    total: list[int],
    lock: threading.Lock,
    exceeded: threading.Event,
) -> None:
    try:
        while not exceeded.is_set():
            chunk = pipe.read(65_536)
            if not chunk:
                return
            with lock:
                remaining = maximum - total[0]
                if remaining <= 0:
                    exceeded.set()
                    return
                destination.extend(chunk[:remaining])
                total[0] += min(len(chunk), remaining)
                if len(chunk) > remaining:
                    exceeded.set()
                    return
    finally:
        pipe.close()


def _subprocess_environment(extra: Mapping[str, str] | None, workspace: str) -> dict[str, str]:
    allowed = ("PATH", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment.setdefault("PATH", os.defpath)
    environment.setdefault("LANG", "C.UTF-8")
    environment["NO_COLOR"] = "1"
    # Scratch space is per-run and private: a scanner that writes temporary
    # files, caches or a home directory never touches the host's.
    environment["TMPDIR"] = workspace
    environment["TMP"] = workspace
    environment["TEMP"] = workspace
    environment["HOME"] = workspace
    if extra is not None:
        for key, value in extra.items():
            if not key or "=" in key or "\x00" in key or "\x00" in value:
                raise CommandError("subprocess environment contains an invalid key/value")
            environment[key] = value
    return environment


def _terminate(
    process: subprocess.Popen[bytes], start_new_session: bool, grace_seconds: float
) -> tuple[bool, bool]:
    """Stop the process group with a terminate → kill escalation.

    Returns ``(process_group_signalled, escalated_to_kill)``. SIGTERM gives a
    scanner the chance to flush partial output and remove its temporary files;
    SIGKILL follows only when it does not exit within the grace window.
    """
    group: int | None = None
    if start_new_session:
        with contextlib.suppress(OSError):
            group = os.getpgid(process.pid)

    def deliver(number: int) -> bool:
        try:
            if group is not None:
                os.killpg(group, number)
            elif number == signal.SIGTERM:  # pragma: no cover - non-POSIX
                process.terminate()
            else:  # pragma: no cover - non-POSIX
                process.kill()
            return True
        except (ProcessLookupError, PermissionError, OSError):
            return False

    signalled = deliver(signal.SIGTERM)
    try:
        process.wait(timeout=grace_seconds)
        return signalled and group is not None, False
    except subprocess.TimeoutExpired:
        pass
    deliver(signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=10)
    return group is not None, True
