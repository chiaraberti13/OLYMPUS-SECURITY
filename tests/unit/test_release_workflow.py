"""Security properties of the signed, keyless release workflow (SEC-4.5 / CICD-3).

The release pipeline is verified here *offline* as a static contract: it must stay
passive by default (only a version tag builds, PyPI publishing needs an explicit
owner switch and a protected environment) and keyless (no stored secrets — signing
and publishing go through OIDC). These are the properties the acceptance criteria
pin, enforced so the workflow cannot silently regress into publishing on a PR or
reintroducing a token.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/release.yml"


def _workflow() -> dict[str, Any]:
    data = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # PyYAML parses the bare key ``on`` as the boolean True.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return triggers


def test_release_workflow_only_triggers_on_a_version_tag() -> None:
    triggers = _triggers(_workflow())
    # Only a version tag or an explicit manual dispatch — never a PR or a branch push,
    # so an untrusted pull request can never drive the signing/publishing pipeline.
    assert set(triggers) == {"push", "workflow_dispatch"}
    assert triggers["push"] == {"tags": ["v*.*.*"]}
    assert "branches" not in triggers["push"]


def test_release_workflow_has_least_privilege_default_permissions() -> None:
    assert _workflow()["permissions"] == {"contents": "read"}


def test_pypi_publish_is_gated_three_ways_and_keyless() -> None:
    publish = _workflow()["jobs"]["publish-pypi"]
    # Gate 1 + 2: a tag build AND the owner-set repository variable.
    assert "startsWith(github.ref, 'refs/tags/')" in publish["if"]
    assert "vars.PYPI_PUBLISH == 'true'" in publish["if"]
    # Gate 3: a protected environment (owner approval).
    assert publish["environment"] == "release"
    # Keyless: Trusted Publishing needs the OIDC token, nothing else.
    assert publish["permissions"] == {"id-token": "write"}


def test_signing_and_provenance_use_oidc() -> None:
    jobs = _workflow()["jobs"]
    assert jobs["sign"]["permissions"]["id-token"] == "write"
    assert jobs["provenance"]["permissions"]["id-token"] == "write"


def test_release_workflow_stores_no_secrets() -> None:
    # Everything is keyless/OIDC: the workflow must not reference any secret or embed
    # a token/password, so there is nothing to leak or rotate.
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "secrets." not in text
    assert "password:" not in text.lower()


def test_build_job_emits_a_reproducible_sbom() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "python -m build" in text
    assert "olympus core sbom --reproducible --engines" in text
