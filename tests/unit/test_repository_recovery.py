"""Repository-level regression tests for post-merge verification and recovery."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def _workflow(name: str) -> dict[str, object]:
    document = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text())
    assert isinstance(document, dict)
    return document


def test_post_merge_verifier_is_exact_sha_read_only_and_preserves_evidence() -> None:
    workflow = _workflow("post-merge-verify.yml")
    triggers = workflow.get("on") or workflow[True]
    assert triggers["workflow_run"] == {
        "workflows": ["ci"],
        "types": ["completed"],
        "branches": ["main"],
    }
    assert workflow["permissions"] == {
        "contents": "read",
        "actions": "read",
        "checks": "read",
    }
    verify = workflow["jobs"]["verify"]
    assert verify["env"]["TARGET_SHA"] == (
        "${{ github.event.workflow_run.head_sha || inputs.sha }}"
    )
    steps = verify["steps"]
    checkout = next(step for step in steps if step.get("uses") == "actions/checkout@v7")
    assert checkout["with"]["ref"] == "${{ env.TARGET_SHA }}"
    shell = "\n".join(step.get("run", "") for step in steps)
    assert "audit_required_checks.py" in shell
    assert "commits/$TARGET_SHA/check-runs" in shell
    artifact = next(step for step in steps if step.get("uses") == "actions/upload-artifact@v7")
    assert artifact["if"] == "always()"
    assert artifact["with"]["if-no-files-found"] == "error"


def test_known_good_registry_is_versioned_unique_and_evidence_backed() -> None:
    registry = json.loads((ROOT / "docs" / "verify" / "known-good.json").read_text())
    assert registry["schema_name"] == "olympus.known-good-commits"
    assert registry["schema_version"] == "1.0.0"
    assert registry["repository"] == "chiaraberti13/OLYMPUS-SECURITY"
    entries = registry["entries"]
    assert isinstance(entries, list)
    assert entries, "a green post-merge SHA must remain registered"
    shas: list[str] = []
    for entry in entries:
        assert FULL_SHA.fullmatch(entry["sha"])
        assert entry["required_checks"] == 16
        assert entry["verdict"] == "pass"
        assert entry["tag"] is None or isinstance(entry["tag"], str)
        assert entry["release"] is None or isinstance(entry["release"], str)
        assert (ROOT / entry["evidence"]).is_file()
        assert entry["workflow_url"].startswith(
            "https://github.com/chiaraberti13/OLYMPUS-SECURITY/actions/runs/"
        )
        shas.append(entry["sha"])
    assert len(shas) == len(set(shas))


def test_runbook_requires_history_preserving_recovery() -> None:
    runbook = (ROOT / "docs" / "main-recovery.md").read_text(encoding="utf-8")
    assert "git revert <bad-sha>" in runbook
    assert "git revert -m 1 <merge-sha>" in runbook
    assert "Never recover by deleting history" in runbook
    assert "force-push" in runbook
    assert "known-good.json" in runbook
