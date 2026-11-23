"""System data retention/privacy governance (DATA-3).

The policy must cover every sensitive data class with a bounded retention rule and
a privacy classification, apply retention by reusing the audited core primitive,
refuse to "prune" a class governed elsewhere, and verify the custody chain that
historicises evidence by reusing the signed Minerva ledger.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from olympus.core.coverage import RunStatus
from olympus.core.models import Evidence
from olympus.minerva.custody import AcquisitionProvenance, CustodyAction, append_entry
from olympus.minerva.governance import (
    SYSTEM_POLICY,
    DataClass,
    Enforcement,
    GovernanceError,
    apply_retention,
    describe_policy,
    verify_custody,
)

pytestmark = pytest.mark.unit


def test_every_data_class_has_a_bounded_rule_and_privacy_flags() -> None:
    assert set(SYSTEM_POLICY) == set(DataClass)
    for rule in SYSTEM_POLICY.values():
        bounds = (
            rule.retention.max_age_days,
            rule.retention.max_files,
            rule.retention.max_total_bytes,
        )
        assert any(b is not None for b in bounds), f"{rule.data_class} retention is unbounded"
    # Classes that name people or targets must be flagged for redaction on egress.
    assert SYSTEM_POLICY[DataClass.AUDIT_TRAIL].contains_identities
    assert SYSTEM_POLICY[DataClass.JOB_RECORDS].contains_identities
    assert SYSTEM_POLICY[DataClass.SCANNER_OUTPUT].redaction_required
    # Signed engine evidence is the class tracked in the verifiable custody chain.
    assert SYSTEM_POLICY[DataClass.ENGINE_EVIDENCE].custody_tracked


def test_describe_policy_is_serialisable_and_complete() -> None:
    described = describe_policy()
    assert {d["data_class"] for d in described} == {str(c) for c in DataClass}
    assert all("retention" in d and "privacy" in d for d in described)


def test_apply_retention_prunes_a_directory_class(tmp_path: Path) -> None:
    for name in ("nmap-evidence.json", "httpx-evidence.json", "keep.txt"):
        (tmp_path / name).write_text("x", encoding="utf-8")
    # A far-future "now" makes every file older than the 365-day window.
    report = apply_retention(
        DataClass.ENGINE_EVIDENCE, tmp_path, now=datetime(2100, 1, 1, tzinfo=UTC)
    )
    assert report.examined == 2  # only the *-evidence.json* files match the pattern
    assert set(report.removed) == {"nmap-evidence.json", "httpx-evidence.json"}
    assert not (tmp_path / "nmap-evidence.json").exists()
    assert (tmp_path / "keep.txt").exists()  # outside the class pattern, untouched


def test_apply_retention_dry_run_removes_nothing(tmp_path: Path) -> None:
    (tmp_path / "a-evidence.json").write_text("x", encoding="utf-8")
    report = apply_retention(
        DataClass.ENGINE_EVIDENCE, tmp_path, dry_run=True, now=datetime(2100, 1, 1, tzinfo=UTC)
    )
    assert report.dry_run and report.removed == ("a-evidence.json",)
    assert (tmp_path / "a-evidence.json").exists()


@pytest.mark.parametrize(
    ("data_class", "enforcement"),
    [
        (DataClass.JOB_RECORDS, Enforcement.STORE_MANAGED),
        (DataClass.AUDIT_TRAIL, Enforcement.ROTATE_LOG),
    ],
)
def test_non_directory_classes_refuse_prune(
    tmp_path: Path, data_class: DataClass, enforcement: Enforcement
) -> None:
    assert SYSTEM_POLICY[data_class].enforcement is enforcement
    with pytest.raises(GovernanceError):
        apply_retention(data_class, tmp_path)


def _evidence() -> Evidence:
    return Evidence(
        evidence_id="EVD-2026-00001",
        evidence_type="scan-output",
        uri="file://olympus-lab/nmap-evidence.json",
        sha256="a" * 64,
    )


def _acquisition() -> AcquisitionProvenance:
    return AcquisitionProvenance(
        tool="nmap",
        tool_version="7.992",
        policy_sha256="b" * 64,
        scope_sha256="c" * 64,
        command_template=("nmap", "-sV", "{target}"),
        coverage_status=RunStatus.CLEAN,
        partial_reason=None,
    )


def test_verify_custody_confirms_an_unsigned_evidence_anchored_chain(tmp_path: Path) -> None:
    ledger = tmp_path / "custody.json"
    append_entry(
        ledger,
        _evidence(),
        CustodyAction.COLLECTED,
        "responder",
        datetime(2026, 11, 23, 9, tzinfo=UTC),
        acquisition=_acquisition(),
    )
    result = verify_custody(ledger, env={})
    assert result.entries == 1
    assert result.evidence_anchored is True
    assert result.signed is False
    assert result.ok is True


def test_verify_custody_missing_ledger_raises(tmp_path: Path) -> None:
    with pytest.raises(Exception):  # noqa: B017 - inspect_ledger raises on a missing ledger
        verify_custody(tmp_path / "nope.json", env={})


def test_cli_policy_and_store_managed_refusal(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from olympus.minerva.cli import app

    runner = CliRunner()
    policy = runner.invoke(app, ["governance-policy"])
    assert policy.exit_code == 0 and "engine-evidence" in policy.stdout
    refused = runner.invoke(app, ["governance-apply", "job-records", str(tmp_path)])
    assert refused.exit_code != 0  # store-managed class cannot be pruned as a directory
