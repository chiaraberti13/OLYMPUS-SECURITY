"""Tests for the offline safety preview of a planned Themis run (UX-B).

The preview carries no new security logic: it reuses the scope check
(:func:`olympus.themis.scope.ensure_allowed`, no network activity) and the risk
classification (:mod:`olympus.integrations.activity`). These tests pin that the
preview is strictly offline, classifies every scope outcome, never understates
risk, asks for confirmation only when it should, and serializes stably.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.integrations.activity import ActivityType, RiskClass
from olympus.themis.application import ThemisRunRequest, ThemisScope
from olympus.themis.preview import (
    SCOPE_EXPLANATION,
    SafetyPreview,
    ScopeDecision,
    preview_run,
)

SCOPE = ThemisScope(
    allowed_hosts=("scanme.nmap.org",),
    allowed_domains=("example.com",),
    allowed_cidrs=("10.0.0.0/24",),
)


def _request(scanner: str, target: str, **kwargs: object) -> ThemisRunRequest:
    defaults: dict[str, object] = {
        "target_kind": "host",
        "scope_path": Path("/nonexistent/scope.json"),
        "authorized": True,
        "live_enabled": True,
    }
    defaults.update(kwargs)
    return ThemisRunRequest(scanner=scanner, target=target, **defaults)  # type: ignore[arg-type]


def test_literal_ip_in_cidr_is_in_scope() -> None:
    preview = preview_run(_request("nmap", "10.0.0.5"), SCOPE)
    assert preview.scope_decision is ScopeDecision.IN_SCOPE
    assert preview.normalized_host == "10.0.0.5"
    assert preview.blocks_launch is False


def test_hostname_matched_by_name_requires_resolution() -> None:
    preview = preview_run(_request("subfinder", "scanme.nmap.org"), SCOPE)
    assert preview.scope_decision is ScopeDecision.RESOLUTION_REQUIRED
    assert preview.normalized_host == "scanme.nmap.org"
    assert preview.blocks_launch is False


def test_subdomain_of_allowed_domain_requires_resolution() -> None:
    preview = preview_run(_request("httpx", "app.example.com"), SCOPE)
    assert preview.scope_decision is ScopeDecision.RESOLUTION_REQUIRED
    assert preview.normalized_host == "app.example.com"


def test_out_of_scope_target_blocks_launch() -> None:
    preview = preview_run(_request("sqlmap", "not-authorized.test"), SCOPE)
    assert preview.scope_decision is ScopeDecision.OUT_OF_SCOPE
    assert preview.blocks_launch is True


def test_non_global_ip_outside_scope_is_blocked() -> None:
    preview = preview_run(_request("nmap", "127.0.0.1"), SCOPE)
    assert preview.scope_decision is ScopeDecision.BLOCKED
    assert preview.blocks_launch is True


def test_malformed_target_is_invalid() -> None:
    preview = preview_run(_request("nmap", "http://has space/path", target_kind="url"), SCOPE)
    assert preview.scope_decision is ScopeDecision.INVALID
    assert preview.normalized_host is None
    assert preview.blocks_launch is True


@pytest.mark.parametrize(
    ("scanner", "expected_risk"),
    [
        ("subfinder", RiskClass.PASSIVE),
        ("nmap", RiskClass.ACTIVE),
        ("sqlmap", RiskClass.INTRUSIVE),
    ],
)
def test_risk_class_comes_from_the_shared_classifier(
    scanner: str, expected_risk: RiskClass
) -> None:
    preview = preview_run(_request(scanner, "10.0.0.5"), SCOPE)
    assert preview.risk is expected_risk
    assert preview.scanner_known is True


def test_active_and_intrusive_live_runs_require_confirmation() -> None:
    assert preview_run(_request("nmap", "10.0.0.5"), SCOPE).requires_confirmation is True
    assert preview_run(_request("sqlmap", "10.0.0.5"), SCOPE).requires_confirmation is True


def test_passive_run_does_not_require_confirmation() -> None:
    assert preview_run(_request("subfinder", "10.0.0.5"), SCOPE).requires_confirmation is False


def test_simulation_never_requires_confirmation_or_authorization() -> None:
    preview = preview_run(
        _request("sqlmap", "10.0.0.5", authorized=False, live_enabled=False, simulate=True),
        SCOPE,
    )
    assert preview.requires_confirmation is False
    assert "Simulation mode" in preview.authorization_detail


def test_unknown_scanner_defaults_to_active_and_is_flagged() -> None:
    preview = preview_run(_request("totally-made-up", "10.0.0.5"), SCOPE)
    assert preview.scanner_known is False
    assert preview.risk is RiskClass.ACTIVE  # never understated
    assert preview.activity is ActivityType.WEB
    assert preview.external_tool == "(unknown scanner)"
    assert preview.requires_confirmation is True


def test_api_engine_without_binary_is_named_as_remote_service() -> None:
    preview = preview_run(_request("zap", "10.0.0.5"), SCOPE)
    assert preview.external_tool == "(remote API service)"


def test_local_binary_scanner_names_its_binary() -> None:
    assert preview_run(_request("nmap", "10.0.0.5"), SCOPE).external_tool == "nmap"


def test_authorization_detail_reports_manifest_and_lab() -> None:
    manifest_preview = preview_run(
        _request(
            "nmap",
            "10.0.0.5",
            job_id="THEMIS-" + "A" * 32,
            manifest_sha256="a" * 64,
        ),
        SCOPE,
    )
    assert manifest_preview.signed_manifest is True
    assert "signed engagement manifest" in manifest_preview.authorization_detail

    unauthorized = preview_run(_request("nmap", "10.0.0.5", authorized=False), SCOPE)
    assert "NOT authorized" in unauthorized.authorization_detail


def test_authorization_detail_reports_live_lab_activation() -> None:
    preview = preview_run(
        _request(
            "nmap",
            "10.0.0.5",
            lab_policy_sha256="b" * 64,
            lab_allowed_cidrs=("10.0.0.0/24",),
            lab_activation_signature="c" * 64,
        ),
        SCOPE,
    )
    assert preview.lab_activation is True
    assert "signed live-lab activation" in preview.authorization_detail


def test_budget_and_output_paths_are_surfaced() -> None:
    preview = preview_run(
        _request(
            "nmap",
            "10.0.0.5",
            timeout_seconds=120.0,
            deadline_seconds=240.0,
            output_path=Path("results/out.json"),
            audit_path=Path("results/audit.ndjson"),
        ),
        SCOPE,
    )
    assert preview.timeout_seconds == 120.0
    assert preview.deadline_seconds == 240.0
    assert preview.output_path == "results/out.json"
    assert preview.audit_path == "results/audit.ndjson"


def test_to_dict_is_json_safe_and_complete() -> None:
    import json

    preview = preview_run(_request("nmap", "10.0.0.5"), SCOPE)
    data = preview.to_dict()
    # Round-trips through JSON with only primitive values.
    assert json.loads(json.dumps(data)) == data
    expected_keys = set(vars(preview))
    assert set(data) == expected_keys


def test_lines_render_every_status_as_a_word_no_colour() -> None:
    lines = preview_run(_request("sqlmap", "not-authorized.test"), SCOPE).lines()
    joined = "\n".join(lines)
    assert "OUT_OF_SCOPE" in joined
    assert "INTRUSIVE" in joined
    assert "BLOCKED" in joined  # launch line
    assert "\x1b[" not in joined  # no ANSI colour codes


def test_scope_explanation_covers_every_decision() -> None:
    assert set(SCOPE_EXPLANATION) == set(ScopeDecision)


def test_preview_does_no_dns_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """The preview must classify a hostname statically, never resolving it."""
    import olympus.themis.scope as scope_module

    def _forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("preview must not resolve DNS")

    monkeypatch.setattr(scope_module.socket, "getaddrinfo", _forbidden)
    preview = preview_run(_request("httpx", "app.example.com"), SCOPE)
    assert isinstance(preview, SafetyPreview)
    assert preview.scope_decision is ScopeDecision.RESOLUTION_REQUIRED


def test_planned_command_shows_the_redacted_argv_for_a_native_adapter() -> None:
    """A native scanner's dry-run argv is surfaced before any run (SEC-G)."""
    preview = preview_run(_request("nmap", "10.0.0.5"), SCOPE)
    assert preview.planned_command is not None
    assert preview.planned_command[0] == "nmap"
    assert "10.0.0.5" in preview.planned_command
    # It is shown as plain tokens in the rendered lines, never launched.
    assert any(line.startswith("Planned command:") for line in preview.lines())


def test_planned_command_redacts_url_query_secrets() -> None:
    """A target-controlled URL cannot leak a secret into the dry-run preview."""
    preview = preview_run(
        _request("httpx", "http://10.0.0.5/x?token=secret", target_kind="url"),
        SCOPE,
    )
    assert preview.scope_decision is ScopeDecision.IN_SCOPE
    assert preview.planned_command is not None
    joined = " ".join(preview.planned_command)
    assert "secret" not in joined
    assert "[REDACTED]" in joined


def test_planned_command_is_absent_when_the_launch_is_blocked() -> None:
    """No run is planned for a blocked target, so no command is shown."""
    preview = preview_run(_request("nmap", "203.0.113.9"), SCOPE)
    assert preview.blocks_launch is True
    assert preview.planned_command is None
    assert preview.to_dict()["planned_command"] is None
