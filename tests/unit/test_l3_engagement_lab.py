"""The engagement-signed L3 runner keeps isolation + signed-manifest authorization.

``labs/l3/run_engagement.sh`` runs nmap LIVE inside the hardened scanner container,
authorized by a signed ENGAGEMENT MANIFEST (approver Ed25519 key) rather than a
throw-away lab policy, and signs the run evidence (TOOLS-4.2 L3 formal promotion /
QA-3). This test pins the isolation flags and the manifest-authorization options so a
careless edit cannot silently relax the lab or drop the engagement binding.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "labs" / "l3" / "run_engagement.sh"


def _script() -> str:
    return _SCRIPT.read_text(encoding="utf-8")


def test_script_exists() -> None:
    assert _SCRIPT.is_file(), "labs/l3/run_engagement.sh is missing"


def test_script_is_valid_bash() -> None:
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover - bash is present in CI and dev images
        pytest.skip("bash is not available to syntax-check the script")
    result = subprocess.run([bash, "-n", str(_SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"bash syntax error: {result.stderr}"


def test_every_isolation_flag_is_present() -> None:
    text = _script()
    for flag in (
        "--read-only",
        "--cap-drop ALL",
        "no-new-privileges=true",
        "--user 10001:10001",
        "--tmpfs /tmp",
        "--tmpfs /data",
    ):
        assert flag in text, f"run_engagement.sh no longer sets the isolation flag {flag!r}"
    assert "seccomp=unconfined" not in text
    assert "--privileged" not in text


def test_live_scan_is_engagement_signed_and_evidenced() -> None:
    text = _script()
    assert "THEMIS_ENABLE_LIVE_SCANS=true" in text
    assert "OLYMPUS_EVIDENCE_SIGNING_KEY_FILE=" in text
    # The engagement (not lab-policy) authorization path and signed evidence.
    for option in (
        "--scope ",
        "--signed-manifest ",
        "--manifest-public-key ",
        "--engagement-storage ",
        "--i-am-authorized",
        "--evidence ",
    ):
        assert option in text, f"run_engagement.sh no longer passes {option.strip()!r}"
    # `themis run` requires a versioned scope authorizing the target in addition to
    # the signed engagement manifest; the runner must write and pass one.
    assert "olympus.themis-scope" in text
    # This runner is the engagement path, not the lab-policy one.
    assert "--lab-policy" not in text
    # nmap scans a host; the manifest scope covers the bare host.
    assert "--kind host" in text


def test_manifest_generation_runs_inside_the_scanner_image() -> None:
    # The approver keypair + signed manifest must be built inside the scanner image
    # (which ships olympus), not with a host python3 that has no olympus installed.
    text = _script()
    assert "generate_keypair" in text
    gen_at = text.index("generate_keypair")
    preamble = text[:gen_at]
    # The generate_keypair call lives inside a containerized python3 heredoc: the
    # most recent `docker run` before it must invoke python3 (the scanner image's
    # entrypoint is the `olympus` CLI, so python3 is reached via --entrypoint).
    assert "docker run" in preamble
    block = preamble[preamble.rindex("docker run") :]
    assert "python3" in block, (
        "the manifest-generation step must run python3 inside the scanner container"
    )
    assert "--entrypoint python3" in block, (
        "the scanner image entrypoint is `olympus`; the generation step must "
        "override it with --entrypoint python3"
    )
    # ...and it must not be a bare host-side `python3 - <<` invocation.
    assert "OLYMPUS_ENG_DIR=" not in text


def test_script_carries_no_secret_material() -> None:
    text = _script()
    assert "BEGIN PRIVATE KEY" not in text and "BEGIN OPENSSH" not in text
    # Both the approver key and the evidence key are generated at run time.
    assert "generate_keypair" in text
    assert "openssl genpkey -algorithm ed25519" in text
    # No engagement HMAC key is used on this path (it is signed-manifest, not lab-policy).
    assert "OLYMPUS_POLICY_LAB_KEY" not in text
