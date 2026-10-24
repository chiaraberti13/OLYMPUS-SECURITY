"""Executable SEC-A smoke of the distributed runtime, without vendor/ or a target."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "olympus-native-runtime-test:local"
SECCOMP_PROFILE = ROOT / "deploy/security/themis-scanner-seccomp.json"


def test_native_image_runs_migrations_api_web_worker_and_escape_probes(tmp_path: Path) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.fail("Docker is required for the explicitly selected container suite")
    apparmor_profile = os.environ.get("OLYMPUS_TEST_APPARMOR_PROFILE")
    apparmor_options = (
        ["--security-opt", f"apparmor={apparmor_profile}"] if apparmor_profile else []
    )
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
            *apparmor_options,
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
            *apparmor_options,
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

    host_canary = tmp_path / "host-only-sensitive-file"
    host_canary.write_text("synthetic host-only canary")
    lsm_canary = tmp_path / "apparmor-denied-canary"
    lsm_canary.write_text("synthetic bind-mounted canary")
    lsm_options = []
    if apparmor_profile:
        lsm_options = [
            "--mount",
            f"type=bind,source={lsm_canary},target=/run/host-sensitive/canary,readonly",
            "--env",
            "LSM_DENIED_PATH=/run/host-sensitive/canary",
            "--env",
            f"EXPECTED_APPARMOR_PROFILE={apparmor_profile}",
        ]
    probes = subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--pids-limit",
            "32",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--security-opt",
            f"seccomp={SECCOMP_PROFILE}",
            *apparmor_options,
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m,mode=1777",  # noqa: S108
            "--tmpfs",
            "/data:rw,noexec,nosuid,size=16m,uid=10001,gid=10001,mode=0700",
            "--env",
            f"HOST_SECRET_PATH={host_canary}",
            *lsm_options,
            "--mount",
            f"type=bind,source={ROOT / 'scripts' / 'probe_scanner_container.py'},"
            "target=/probe.py,readonly",
            "--entrypoint",
            "python",
            IMAGE,
            "/probe.py",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert "scanner container escape probes passed" in probes.stdout
