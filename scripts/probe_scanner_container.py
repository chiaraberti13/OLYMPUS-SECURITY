"""Bounded, offline escape probes for the scanner container security boundary."""

from __future__ import annotations

import ctypes
import errno
import os
import subprocess
import sys
import time
from pathlib import Path

from olympus.themis.runner import CommandTimeout, TerminationCause, run_command
from olympus.themis.sandbox import SandboxPolicy

_CLONE_NEWUSER = 0x10000000
_PR_GET_NO_NEW_PRIVS = 39
_MAX_CHILDREN = 128
_TIMEOUT_SECONDS = 0.5
_GRACE_SECONDS = 0.5
_TIMEOUT_PROBE_DEADLINE_SECONDS = 10.0


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _status() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, separator, value = line.partition(":")
        if separator:
            result[key] = value.strip()
    return result


def _probe_security_state() -> None:
    status = _status()
    _require(int(status["CapEff"], 16) == 0, "effective capabilities are not empty")
    _require(status["NoNewPrivs"] == "1", "no-new-privileges is not active")
    _require(status["Seccomp"] == "2", "seccomp filter mode is not active")
    _require(int(status["Seccomp_filters"]) >= 1, "no seccomp filter is installed")

    libc = ctypes.CDLL(None, use_errno=True)
    _require(libc.prctl(_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "prctl disagrees")
    ctypes.set_errno(0)
    result = libc.unshare(_CLONE_NEWUSER)
    _require(result == -1 and ctypes.get_errno() == errno.EPERM, "user namespace was created")

    expected_apparmor = os.environ.get("EXPECTED_APPARMOR_PROFILE")
    if expected_apparmor:
        current = Path("/proc/self/attr/current").read_text().split()[0]
        _require(current == expected_apparmor, f"unexpected AppArmor profile: {current}")


def _probe_filesystem() -> None:
    try:
        Path("/etc/olympus-sec-b-escape").write_text("blocked")
    except OSError as exc:
        _require(exc.errno in {errno.EROFS, errno.EACCES, errno.EPERM}, f"unexpected error: {exc}")
    else:
        raise RuntimeError("read-only root filesystem accepted a write")

    scratch = Path("/data/sec-b-probe")
    scratch.write_text("bounded scratch")
    _require(scratch.read_text() == "bounded scratch", "scratch is not writable")
    scratch.unlink()

    host_secret = os.environ["HOST_SECRET_PATH"]
    _require(not Path(host_secret).exists(), "host-only canary is visible in the container")

    lsm_denied_path = os.environ.get("LSM_DENIED_PATH")
    if lsm_denied_path:
        try:
            Path(lsm_denied_path).read_bytes()
        except OSError as exc:
            _require(exc.errno in {errno.EACCES, errno.EPERM}, f"unexpected LSM error: {exc}")
        else:
            raise RuntimeError("AppArmor allowed access to the host-sensitive canary")

    try:
        with Path("/proc/kcore").open("rb") as stream:
            _require(stream.read(1) == b"", "kernel memory exposed readable data")
    except OSError as exc:
        _require(exc.errno in {errno.EACCES, errno.EPERM, errno.ENXIO}, f"unexpected error: {exc}")


def _probe_pid_limit() -> None:
    children: list[subprocess.Popen[bytes]] = []
    limited = False
    try:
        for _ in range(_MAX_CHILDREN):
            try:
                children.append(subprocess.Popen(["/usr/bin/sleep", "30"]))
            except OSError as exc:
                _require(exc.errno == errno.EAGAIN, f"unexpected process error: {exc}")
                limited = True
                break
        _require(limited, "PID limit was not enforced within the bounded probe")
    finally:
        for child in children:
            child.terminate()
        for child in children:
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=2)


def _probe_non_cooperative_timeout() -> None:
    non_cooperative_child = (
        "import signal,time;signal.signal(signal.SIGTERM, signal.SIG_IGN);time.sleep(60)"
    )
    started = time.monotonic()
    try:
        run_command(
            [sys.executable, "-c", non_cooperative_child],
            timeout=_TIMEOUT_SECONDS,
            sandbox=SandboxPolicy(grace_seconds=_GRACE_SECONDS),
        )
    except CommandTimeout as exc:
        report = exc.report
    else:
        raise RuntimeError("non-cooperative scanner exceeded its timeout without termination")

    elapsed = time.monotonic() - started
    _require(report.cause is TerminationCause.TIMEOUT, "timeout cause was not preserved")
    _require(report.limit == "timeout_seconds", "timeout limit was not recorded")
    _require(report.process_group_signalled, "scanner process group was not signalled")
    _require(report.escalated_to_kill, "SIGTERM was not escalated to SIGKILL")
    _require(
        elapsed < _TIMEOUT_PROBE_DEADLINE_SECONDS,
        f"timeout probe exceeded its deadline: {elapsed:.2f}s",
    )


def main() -> None:
    _probe_security_state()
    _probe_filesystem()
    _probe_non_cooperative_timeout()
    _probe_pid_limit()
    print("scanner container escape probes passed")


if __name__ == "__main__":
    main()
