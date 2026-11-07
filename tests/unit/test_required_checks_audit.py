"""Regression tests for the required-checks ruleset audit."""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts import audit_required_checks as audit_checks

ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
GITHUB_ACTIONS_APP_ID = 15368
EXPECTED = {
    "ruff · format · mypy (required)",
    *(f"pytest · Python 3.{minor} · Ubuntu" for minor in range(11, 15)),
    "first-party branch coverage · Python 3.11 · Ubuntu",
    "security-boundary mutation tests · Python 3.11 · Ubuntu",
    "POSIX sandbox · Python 3.11 · Ubuntu",
    "CLI smoke · macOS · Python 3.11",
    "CLI smoke · Windows · Python 3.11",
    "wheel · clean-install · CLI smoke",
    "native THEMIS container · no vendor · no live traffic",
    "pip-audit (blocking · runtime closure)",
    "gitleaks (blocking working-tree + history scan)",
    "CodeQL · Python · security-extended",
    "scanner-image gate",
}


def _rules(*, names: set[str] = EXPECTED, strict: bool = True) -> dict[str, object]:
    return {
        "name": "main protection",
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": strict,
                    "required_status_checks": [
                        {"context": name, "integration_id": GITHUB_ACTIONS_APP_ID}
                        for name in sorted(names)
                    ],
                },
            }
        ],
    }


def _checks(*, names: set[str] = EXPECTED, sha: str = SHA) -> dict[str, object]:
    runs = [
        {
            "name": name,
            "head_sha": sha,
            "conclusion": "success",
            "app": {"id": GITHUB_ACTIONS_APP_ID},
        }
        for name in sorted(names)
    ]
    return {"total_count": len(runs), "check_runs": runs}


def test_repository_workflows_define_the_canonical_sixteen_checks() -> None:
    assert set(audit_checks.expected_checks(ROOT)) == EXPECTED


def test_complete_strict_ruleset_and_successful_sha_pass() -> None:
    result = audit_checks.audit(
        sha=SHA,
        rules_document=_rules(),
        checks_document=_checks(),
        repository_root=ROOT,
    )
    assert result.success is True
    assert len(result.rows) == 16
    assert "Verdict: **PASS**" in audit_checks.render_markdown(result)


@pytest.mark.parametrize(
    ("rules", "checks"),
    [
        (_rules(names=EXPECTED - {"scanner-image gate"}), _checks()),
        (_rules(), _checks(names=EXPECTED - {"scanner-image gate"})),
        (_rules(strict=False), _checks()),
        (_rules(), _checks(sha="b" * 40)),
    ],
)
def test_missing_rule_run_freshness_or_strict_policy_fails_closed(
    rules: dict[str, object], checks: dict[str, object]
) -> None:
    result = audit_checks.audit(
        sha=SHA,
        rules_document=rules,
        checks_document=checks,
        repository_root=ROOT,
    )
    assert result.success is False
    assert "Verdict: **FAIL**" in audit_checks.render_markdown(result)


def test_incomplete_check_run_pagination_is_rejected() -> None:
    checks = _checks()
    checks["total_count"] = 17
    with pytest.raises(audit_checks.AuditInputError, match="all pages"):
        audit_checks.audit(
            sha=SHA,
            rules_document=_rules(),
            checks_document=checks,
            repository_root=ROOT,
        )


def test_wrong_github_app_cannot_satisfy_a_required_context() -> None:
    checks = _checks()
    runs = checks["check_runs"]
    assert isinstance(runs, list)
    runs[0]["app"] = {"id": 999}
    result = audit_checks.audit(
        sha=SHA,
        rules_document=_rules(),
        checks_document=checks,
        repository_root=ROOT,
    )
    assert result.success is False
    assert any(row.executed and not row.successful for row in result.rows)
