"""Security properties of the scanner-image publication gate (SEC-4.4).

No image may be published unless it was built, smoke-tested and
``engines doctor --strict``-validated on the same image in the same run. This is
verified here *offline* as a static contract so the gate cannot silently regress
into publishing on a pull request, publishing an unvalidated image, or storing a
registry password. The gate is written before any real publication exists; until
the owner flips ``PUBLISH_SCANNER_IMAGE`` and approves the protected environment,
the workflow validates on a tag and publishes nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-scanner-image.yml"


def _workflow() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # PyYAML parses the bare key ``on`` as the boolean True.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


def _job(workflow: dict[str, Any], name: str) -> dict[str, Any]:
    job = workflow["jobs"][name]
    assert isinstance(job, dict)
    return job


def test_only_triggers_on_a_version_tag_or_manual_dispatch() -> None:
    triggers = _triggers(_workflow())
    # Never a pull request or a branch push: an untrusted PR can never drive the
    # publication pipeline.
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"] == {"tags": ["v*.*.*"]}


def test_top_level_permissions_are_minimal() -> None:
    assert _workflow().get("permissions") == {"contents": "read"}


def test_publish_requires_validation_switch_and_protected_environment() -> None:
    workflow = _workflow()
    publish = _job(workflow, "publish")
    # An unvalidated image can never be published: publish hard-depends on validate.
    needs = publish["needs"]
    needs = [needs] if isinstance(needs, str) else list(needs)
    assert "validate" in needs
    # Passive by default: a tag, the owner switch, AND the protected environment.
    guard = publish["if"]
    assert "refs/tags/" in guard
    assert "PUBLISH_SCANNER_IMAGE" in guard and "'true'" in guard
    assert publish["environment"] == "publish-scanner-image"


def test_validation_builds_smoke_tests_and_runs_doctor_strict() -> None:
    validate = _job(_workflow(), "validate")
    run_steps = "\n".join(step.get("run", "") for step in validate["steps"])
    assert "docker build" in run_steps and "docker/Dockerfile.scanners" in run_steps
    assert "scripts/smoke_scanner_image.py" in run_steps
    assert "engines doctor --strict" in run_steps


def test_publish_is_keyless_no_stored_registry_secret() -> None:
    # The only secret used anywhere is the ephemeral GITHUB_TOKEN; no stored
    # registry password may appear.
    text = WORKFLOW.read_text(encoding="utf-8")
    secret_refs = {ref.split("}}")[0].strip() for ref in text.split("secrets.")[1:]}
    assert secret_refs <= {"GITHUB_TOKEN"}, f"unexpected stored secret(s): {secret_refs}"
    # And the publish job authenticates to GHCR with that ephemeral token: parse the
    # login step rather than substring-matching, so the registry is pinned exactly.
    publish = _job(_workflow(), "publish")
    login = next(
        step
        for step in publish["steps"]
        if str(step.get("uses", "")).startswith("docker/login-action@")
    )
    assert login["with"]["registry"] == "ghcr.io"
    # Not a secret value — the literal GitHub Actions expression for the ephemeral token.
    expected_token = "${{ secrets.GITHUB_TOKEN }}"  # noqa: S105
    assert login["with"]["password"] == expected_token
