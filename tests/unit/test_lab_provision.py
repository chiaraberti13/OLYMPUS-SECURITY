"""The lab provisioner mirrors the engine manifests and stays authorized by design.

``scripts/lab/provision_lab.sh`` installs the mandatory engines at pinned versions
for an offline lab. If its pins drift from ``src/olympus/engines/<name>/engine.toml``
the lab would validate a tool Olympus is not pinned against — the same failure the
Dockerfile pin test guards for the image, so this test holds the script to the
manifests too, and checks the lab target never leaves host-local documentation space.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from olympus.engines.loader import load_all

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "lab" / "provision_lab.sh"


def _script() -> str:
    return _SCRIPT.read_text(encoding="utf-8")


def test_script_exists_and_is_valid_bash() -> None:
    assert _SCRIPT.is_file(), "scripts/lab/provision_lab.sh is missing"
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover - bash is present in CI and dev images
        pytest.skip("bash is not available to syntax-check the script")
    result = subprocess.run([bash, "-n", str(_SCRIPT)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, f"bash syntax error: {result.stderr}"


def test_go_engine_pins_match_the_manifests() -> None:
    text = _script()
    manifests = load_all()
    for name in ("httpx", "nuclei"):
        pinned = manifests[name].engine.pinned_version
        assert pinned is not None
        assert f"{name.upper()}_VERSION={pinned}\n" in text, (
            f"{name} pin in provision_lab.sh != manifest {pinned}"
        )


def test_nmap_commit_matches_the_manifest() -> None:
    text = _script()
    commit = load_all()["nmap"].engine.source.commit
    assert commit is not None and re.fullmatch(r"[0-9a-f]{40}", commit)
    assert f"NMAP_COMMIT={commit}\n" in text, "nmap commit in provision_lab.sh != manifest"


def test_templates_commit_matches_the_data_manifest() -> None:
    text = _script()
    data = _ROOT / "src" / "olympus" / "engines" / "_data" / "nuclei-templates.toml"
    commit = re.search(r'commit\s*=\s*"([0-9a-f]{40})"', data.read_text(encoding="utf-8"))
    assert commit is not None, "no pinned commit in the nuclei-templates data manifest"
    assert f"TPL_COMMIT={commit.group(1)}\n" in text, (
        "nuclei-templates commit in provision_lab.sh != data manifest"
    )


def test_lab_target_stays_in_documentation_space_never_loopback_or_public() -> None:
    # The Olympus lab policy forbids loopback/public targets and accepts only
    # owned private/documentation ranges; the provisioner must bind the target in
    # TEST-NET-1 (192.0.2.0/24) so the two agree and no real host is ever reached.
    text = _script()
    assert "192.0.2.0/24" in text
    assert "--bind 192.0.2." in text, "the lab server must bind a documentation address"
    # It must not serve the target on loopback or all-interfaces (which the policy rejects).
    assert "--bind 127.0.0.1" not in text
    assert "--bind 0.0.0.0" not in text


def test_script_carries_no_real_secret() -> None:
    # The target fixtures use obvious placeholders; there must be no real key material.
    text = _script()
    assert "labonly-not-a-secret" in text  # the placeholder is intentional
    assert "BEGIN PRIVATE KEY" not in text and "BEGIN OPENSSH" not in text


def test_python_can_load_the_scope_and_policy_the_script_writes(tmp_path: Path) -> None:
    # Extract the heredoc bodies and confirm they are the shapes Olympus parses.
    text = _script()
    scope = re.search(r"scope\.json\" <<'JSON'\n(.*?)\nJSON", text, re.S)
    assert scope is not None
    import json

    doc = json.loads(scope.group(1))
    assert doc["schema_name"] == "olympus.themis-scope"
    assert "192.0.2.0/24" in doc["allowed_cidrs"]
    assert "[lab]\nenabled = true" in text and 'allowed_networks = ["192.0.2.0/24"]' in text


def test_runs_under_the_current_interpreter_toolchain() -> None:
    # Guard that this test module itself is importable under the running Python,
    # so the drift gate participates in every CI interpreter matrix row.
    assert sys.version_info[:2] >= (3, 11)
