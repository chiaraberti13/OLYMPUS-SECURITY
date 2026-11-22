"""The L3 lab runner keeps every hardened-isolation flag (QA-3 / TOOLS-4.2 L3).

``labs/l3/run.sh`` runs a real engine live inside the hardened scanner container. The
live-scan gate ``require_scanner_isolation`` only passes when the container is truly
isolated; if this script dropped one of those flags a scan would either be refused or,
worse, run with weaker isolation. This test pins the flags (and the authorization and
evidence options) so a careless edit cannot silently relax the lab.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "labs" / "l3" / "run.sh"


def _script() -> str:
    return _SCRIPT.read_text(encoding="utf-8")


def test_script_exists() -> None:
    assert _SCRIPT.is_file(), "labs/l3/run.sh is missing"


def test_script_is_valid_bash() -> None:
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover - bash is present in CI and dev images
        pytest.skip("bash is not available to syntax-check the script")
    result = subprocess.run([bash, "-n", str(_SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"bash syntax error: {result.stderr}"


def test_every_isolation_flag_is_present() -> None:
    # Exactly the properties require_scanner_isolation() checks at runtime.
    text = _script()
    for flag in (
        "--read-only",
        "--cap-drop ALL",
        "no-new-privileges=true",
        "--user 10001:10001",
        "--tmpfs /tmp",
        "--tmpfs /data",
    ):
        assert flag in text, f"labs/l3/run.sh no longer sets the isolation flag {flag!r}"
    # seccomp must never be disabled.
    assert "seccomp=unconfined" not in text
    # privileged mode would defeat the whole point.
    assert "--privileged" not in text


def test_live_scan_is_authorized_scoped_and_evidenced() -> None:
    text = _script()
    assert "THEMIS_ENABLE_LIVE_SCANS=true" in text
    assert "OLYMPUS_EVIDENCE_SIGNING_KEY_FILE=" in text
    for option in ("--scope ", "--lab-policy ", "--i-am-authorized", "--evidence "):
        assert option in text, f"labs/l3/run.sh no longer passes {option.strip()!r}"
    # The target range is a private/documentation CIDR, never public or loopback.
    cidr = re.search(r"OLYMPUS_LAB_CIDR:-([0-9./]+)", text)
    assert cidr is not None and cidr.group(1).startswith(("172.", "10.", "192.168.", "192.0.2."))
    assert "127.0.0.1" not in text
    # The shared resolver supplies the reviewed per-engine budget. A hardcoded
    # timeout here would make the L3 path diverge from API/Web/worker execution.
    assert "--timeout" not in text and "--deadline" not in text


def test_findings_exit_code_does_not_abort_the_readback() -> None:
    # `themis run` exits 1 on findings and 5 on a partial run; under `set -e` that
    # would abort before the evidence read-back/banner. The runner must capture the
    # scan exit code and tolerate 0/1/5, then relax the evidence read bits as the
    # owner uid (10001) in a throwaway no-network container.
    text = _script()
    assert "scan_rc=" in text and "|| scan_rc=$?" in text
    assert "0 | 1 | 5)" in text
    assert "--entrypoint chmod" in text
    chmod_block = text[text.rindex("docker run", 0, text.index("--entrypoint chmod")) :]
    assert "--network none" in chmod_block and "--user 10001:10001" in chmod_block
    assert "a+r " in chmod_block


def test_script_carries_no_secret_material() -> None:
    text = _script()
    assert "BEGIN PRIVATE KEY" not in text and "BEGIN OPENSSH" not in text
    # The evidence key is generated at run time, not committed.
    assert "openssl genpkey -algorithm ed25519" in text
    # The engagement HMAC key must come from the environment, never be baked in.
    assert "OLYMPUS_POLICY_LAB_KEY:?" in text
    assert "olympus-lab-hmac-key" not in text  # no hardcoded key string
