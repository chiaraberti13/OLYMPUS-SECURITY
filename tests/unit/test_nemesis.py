"""Nemesis offline credential auditor — weak, default and reused passwords (RED-3).

Covers the pure core (policy, entropy estimate, known-password membership, reuse,
masking), the fail-closed application boundary (authorization, bounded I/O, parsing)
and the CLI. This file is also the committed evidence that backs the ``password-auditor``
capability in :mod:`olympus.integrations.suite_catalog`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.execution import (
    AuthorizationRequiredError,
    ExecutionPolicy,
    ExecutionPolicyError,
)
from olympus.nemesis.application import AuditRequest, parse_credentials, run_audit
from olympus.nemesis.audit import (
    CredentialEntry,
    PasswordPolicy,
    Weakness,
    audit_credentials,
    estimate_entropy_bits,
    report_to_dict,
)

pytestmark = pytest.mark.unit

runner = CliRunner()


# --- pure core ------------------------------------------------------------- #


def test_policy_rejects_impossible_bounds() -> None:
    with pytest.raises(ValueError, match="min_length"):
        PasswordPolicy(min_length=200, max_length=10)


def test_flags_every_deterministic_weakness() -> None:
    report = audit_credentials(
        [CredentialEntry("u", "short")],
        PasswordPolicy(min_length=12),
        known_passwords=None,
    )
    finding = report.findings[0]
    assert not finding.compliant
    assert Weakness.TOO_SHORT in finding.weaknesses
    assert Weakness.MISSING_UPPERCASE in finding.weaknesses
    assert Weakness.MISSING_DIGIT in finding.weaknesses
    assert Weakness.MISSING_SYMBOL in finding.weaknesses
    assert report.known_password_list_checked is False  # no list supplied


def test_known_and_reused_are_detected_case_insensitively() -> None:
    report = audit_credentials(
        [CredentialEntry("a", "Password1"), CredentialEntry("b", "Password1")],
        PasswordPolicy(),
        known_passwords=frozenset({"password1"}),
    )
    for finding in report.findings:
        assert Weakness.KNOWN_OR_DEFAULT in finding.weaknesses  # matched lowercased
        assert Weakness.REUSED in finding.weaknesses
        assert finding.reuse_count == 2
    assert report.reused_accounts == 2


def test_a_strong_unique_secret_is_compliant() -> None:
    report = audit_credentials(
        [CredentialEntry("svc", "Sup3rStr0ng!Pass#99")],
        PasswordPolicy(),
        known_passwords=frozenset({"password1"}),
    )
    assert report.findings[0].compliant
    assert report.findings[0].weaknesses == ()
    assert report.compliant == 1 and report.weak == 0


def test_low_entropy_only_when_policy_opts_in() -> None:
    weak = audit_credentials(
        [CredentialEntry("u", "aaaaaaaaaaaa")],
        PasswordPolicy(
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_symbol=False,
            min_entropy_bits=60.0,
        ),
    )
    assert Weakness.LOW_ENTROPY in weak.findings[0].weaknesses
    # Same secret with no entropy floor is not flagged for entropy.
    relaxed = audit_credentials(
        [CredentialEntry("u", "aaaaaaaaaaaa")],
        PasswordPolicy(
            require_uppercase=False,
            require_lowercase=False,
            require_digit=False,
            require_symbol=False,
        ),
    )
    assert Weakness.LOW_ENTROPY not in relaxed.findings[0].weaknesses


def test_entropy_estimate_grows_with_pool_and_length() -> None:
    assert estimate_entropy_bits("") == 0.0
    assert estimate_entropy_bits("aaaa") < estimate_entropy_bits("aA1!aA1!")


def test_report_and_mask_never_contain_the_raw_secret() -> None:
    secret = "Sup3rSecret!Value"  # noqa: S105 - test fixture, not a real credential
    report = audit_credentials([CredentialEntry("u", secret)], PasswordPolicy())
    document = report_to_dict(report)
    import json

    blob = json.dumps(document)
    assert secret not in blob
    assert report.findings[0].masked_secret != secret
    # fingerprint is a hash, not the secret, and is stable
    assert len(report.findings[0].fingerprint) == 64
    assert "estimated_entropy_bits" in document["epistemics"]["inference"]


def test_bounds_reject_an_oversized_secret() -> None:
    with pytest.raises(ValueError, match="bounded length"):
        audit_credentials([CredentialEntry("u", "x" * 5000)], PasswordPolicy())


# --- application boundary -------------------------------------------------- #


def test_parse_credentials_both_formats_and_rejects_malformed() -> None:
    entries = parse_credentials('admin:Pa:ss\n{"account":"svc","secret":"x"}\n\n')
    assert entries[0] == CredentialEntry("admin", "Pa:ss")  # split on first colon only
    assert entries[1] == CredentialEntry("svc", "x")
    with pytest.raises(ValueError, match="account:secret"):
        parse_credentials("no-separator-here\n")


def test_run_audit_is_fail_closed_without_authorization(tmp_path: Path) -> None:
    creds = tmp_path / "c.txt"
    creds.write_text("u:short\n", encoding="utf-8")
    with pytest.raises(AuthorizationRequiredError, match="authoriz"):
        run_audit(AuditRequest(input_path=creds), policy=ExecutionPolicy(authorized=False))


def test_run_audit_requires_approval_reference(tmp_path: Path) -> None:
    creds = tmp_path / "c.txt"
    creds.write_text("u:short\n", encoding="utf-8")
    with pytest.raises(ExecutionPolicyError, match="approval reference"):
        run_audit(AuditRequest(input_path=creds), policy=ExecutionPolicy(authorized=True))


def test_run_audit_refuses_an_empty_set(tmp_path: Path) -> None:
    creds = tmp_path / "c.txt"
    creds.write_text("\n\n", encoding="utf-8")
    with pytest.raises(ExecutionPolicyError, match="empty"):
        run_audit(
            AuditRequest(input_path=creds),
            policy=ExecutionPolicy(authorized=True, approval_reference="LAB"),
        )


def test_run_audit_end_to_end_with_wordlist(tmp_path: Path) -> None:
    creds = tmp_path / "c.txt"
    creds.write_text("admin:Password1\nsvc:Sup3rStr0ng!Pass#99\n", encoding="utf-8")
    wl = tmp_path / "w.txt"
    wl.write_text("password1\n", encoding="utf-8")
    report = run_audit(
        AuditRequest(input_path=creds, wordlist_path=wl),
        policy=ExecutionPolicy(authorized=True, approval_reference="LAB"),
    )
    assert report.audited == 2 and report.weak == 1 and report.compliant == 1
    assert report.known_password_list_checked is True


# --- CLI ------------------------------------------------------------------- #


def test_cli_audit_masks_and_exits_nonzero_on_weak(tmp_path: Path) -> None:
    creds = tmp_path / "c.txt"
    creds.write_text("admin:Password1\n", encoding="utf-8")
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        [
            "nemesis",
            "audit",
            str(creds),
            "--i-am-authorized",
            "--approval-reference",
            "LAB-1",
            "--format",
            "json",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "Password1" not in result.output  # masked everywhere
    assert out.exists()
    import stat

    assert stat.S_IMODE(out.stat().st_mode) == 0o600  # owner-only report
    assert "Password1" not in out.read_text(encoding="utf-8")


def test_cli_audit_is_fail_closed_without_authorization(tmp_path: Path) -> None:
    creds = tmp_path / "c.txt"
    creds.write_text("admin:Password1\n", encoding="utf-8")
    result = runner.invoke(app, ["nemesis", "audit", str(creds)])
    assert result.exit_code == 2  # USAGE: refused, nothing audited
    assert "authoriz" in result.output.lower()


def test_cli_audit_clean_set_exits_zero(tmp_path: Path) -> None:
    creds = tmp_path / "c.txt"
    creds.write_text("svc:Sup3rStr0ng!Pass#99\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["nemesis", "audit", str(creds), "--i-am-authorized", "--approval-reference", "LAB"],
    )
    assert result.exit_code == 0, result.output
    assert "1 compliant" in result.output
