"""Executable SEC-A smoke of the distributed runtime, without vendor/ or a target."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "olympus-native-runtime-test:local"
SECCOMP_PROFILE = ROOT / "deploy/security/themis-scanner-seccomp.json"


def test_native_image_runs_migrations_api_web_and_worker() -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.fail("Docker is required for the explicitly selected container suite")
    subprocess.run(
        [docker, "build", "-f", "docker/Dockerfile", "-t", IMAGE, "."],
        cwd=ROOT,
        check=True,
        timeout=600,
    )
    result = subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--security-opt",
            f"seccomp={SECCOMP_PROFILE}",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=128m,mode=1777",  # noqa: S108 - private container tmpfs
            "--tmpfs",
            "/data:rw,noexec,nosuid,uid=10001,gid=10001,mode=0700",
            "--mount",
            f"type=bind,source={ROOT / 'scripts' / 'smoke_native_runtime.py'},"
            "target=/validation.py,readonly",
            "--entrypoint",
            "python",
            IMAGE,
            "/validation.py",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert "smoke passed" in result.stdout

    denied = subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--security-opt",
            f"seccomp={SECCOMP_PROFILE}",
            "--entrypoint",
            "python",
            IMAGE,
            "-c",
            (
                "import ctypes, errno, os; "
                "libc=ctypes.CDLL(None, use_errno=True); "
                "result=libc.process_vm_readv(os.getpid(), None, 0, None, 0, 0); "
                "error=ctypes.get_errno(); "
                "assert result == -1 and error == errno.EPERM, (result, error); "
                "print('seccomp denied process_vm_readv')"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "seccomp denied process_vm_readv" in denied.stdout
