"""Unit tests for Proteus authorized phishing simulation (training only)."""

import json
import stat
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.execution import (
    AuthorizationRequiredError,
    CancellationRequested,
    CancellationToken,
    ExecutionPolicy,
)
from olympus.proteus.application import CampaignApplicationService, CampaignBuildRequest
from olympus.proteus.campaign import (
    Campaign,
    build_campaign,
    campaign_report,
    export_campaign,
    load_campaign,
    render_email,
    render_training_page,
    tracking_link,
)
from olympus.proteus.scope import (
    ProteusOutOfScopeError,
    ProteusScope,
    ProteusScopeError,
    enforce_scope,
)

runner = CliRunner()


def _authorized_policy() -> ExecutionPolicy:
    return ExecutionPolicy(authorized=True, timeout_seconds=1.0, deadline_seconds=60.0)


def _scope(tmp_path: Path, *, engagement: str = "eng") -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "engagement": engagement,
                "allowed_domains": ["example.com"],
                "allowed_landing_origins": ["https://train.example"],
            }
        ),
        encoding="utf-8",
    )
    return path


def _build(tmp_path: Path, emails: list[str]) -> Campaign:
    return build_campaign(
        "eng",
        emails,
        _scope(tmp_path),
        tmp_path / "log",
        policy=_authorized_policy(),
        subject="Confirm",
        sender="it@example.com",
        landing_url="https://train.example/p",
    )


def test_scope_covers_by_domain() -> None:
    scope = ProteusScope(
        engagement="e",
        allowed_domains=("example.com",),
        allowed_landing_origins=("https://train.example",),
    )
    assert scope.covers("alice@example.com") is True
    assert scope.covers("alice@evil.test") is False
    assert scope.covers("not-an-email") is False


def test_enforce_blocks_and_logs(tmp_path: Path) -> None:
    log = tmp_path / "log"
    with pytest.raises(ProteusOutOfScopeError):
        enforce_scope("x@evil.test", _scope(tmp_path), log)
    audit = log.read_text(encoding="utf-8")
    assert "proteus.blocked_out_of_scope" in audit
    assert "x@evil.test" not in audit


def test_build_campaign_mints_unique_tokens(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com", "b@example.com"])
    tokens = {t.token for t in campaign.targets}
    assert len(tokens) == 2  # unique per target
    assert all(t.token for t in campaign.targets)


def test_build_campaign_rejects_out_of_scope(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationRequiredError):
        build_campaign(
            "eng",
            ["a@example.com"],
            _scope(tmp_path),
            tmp_path / "log",
            policy=ExecutionPolicy(authorized=False),
            subject="Confirm",
            sender="it@example.com",
            landing_url="https://train.example/p",
        )
    with pytest.raises(ProteusOutOfScopeError):
        _build(tmp_path, ["a@evil.test"])


def test_build_campaign_enforces_engagement_sender_landing_and_headers(tmp_path: Path) -> None:
    with pytest.raises(ProteusScopeError, match="does not match"):
        build_campaign(
            "other",
            ["a@example.com"],
            _scope(tmp_path),
            tmp_path / "log",
            policy=_authorized_policy(),
            subject="Confirm",
            sender="it@example.com",
            landing_url="https://train.example/p",
        )
    with pytest.raises(ProteusOutOfScopeError):
        build_campaign(
            "eng",
            ["a@example.com"],
            _scope(tmp_path),
            tmp_path / "log",
            policy=_authorized_policy(),
            subject="Confirm",
            sender="it@evil.test",
            landing_url="https://train.example/p",
        )
    with pytest.raises(ProteusOutOfScopeError):
        build_campaign(
            "eng",
            ["a@example.com"],
            _scope(tmp_path),
            tmp_path / "log",
            policy=_authorized_policy(),
            subject="Confirm",
            sender="it@example.com",
            landing_url="https://evil.test/p",
        )
    with pytest.raises(ValueError, match="one line"):
        build_campaign(
            "eng",
            ["a@example.com"],
            _scope(tmp_path),
            tmp_path / "log",
            policy=_authorized_policy(),
            subject="Confirm\nBcc: victim@example.com",
            sender="it@example.com",
            landing_url="https://train.example/p",
        )


def test_tracking_link_replaces_token_and_preserves_fragment(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com"])
    changed = replace(campaign, landing_url="https://train.example/p?lang=en&t=old#lesson")
    link = tracking_link(changed, changed.targets[0])
    assert "lang=en" in link
    assert "t=old" not in link
    assert link.endswith("#lesson")


def test_lure_email_contains_tracking_link(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com"])
    target = campaign.targets[0]
    body = render_email(campaign, target)
    assert tracking_link(campaign, target) in body
    assert target.token in body


def test_training_page_never_captures_credentials() -> None:
    page = render_training_page("Acme Corp").lower()
    # The core safety guarantee: no credential capture, ever.
    assert "<input" not in page
    assert "password" not in page
    assert "<form" not in page
    assert "phishing simulation" in page
    assert "acme corp" in page


def test_campaign_report_click_rate(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com", "b@example.com"])
    clicked = {campaign.targets[0].token}
    summary = campaign_report(campaign, clicked)
    assert summary["targets"] == 2
    assert summary["clicked"] == 1
    assert summary["click_rate_percent"] == 50.0


def test_application_requires_authorization_and_observes_cancellation(tmp_path: Path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("alice@example.com\n", encoding="utf-8")
    request = CampaignBuildRequest(
        engagement="eng",
        targets_path=targets,
        landing_url="https://train.example/p",
        subject="Confirm",
        sender="it@example.com",
        scope_path=_scope(tmp_path),
        audit_log_path=tmp_path / "log",
    )
    with pytest.raises(AuthorizationRequiredError):
        CampaignApplicationService().build(request)
    assert not (tmp_path / "log").exists()

    with pytest.raises(ProteusScopeError, match="HTTPS"):
        CampaignApplicationService().build(replace(request, landing_url="http://train.example/p"))

    token = CancellationToken()
    token.cancel()
    with pytest.raises(CancellationRequested):
        CampaignApplicationService(token).build(replace(request, authorized=True))


def test_campaign_contract_is_versioned_strict_and_owner_only(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com"])
    output = tmp_path / "campaign.json"
    export_campaign(campaign, output)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_name"] == "olympus.proteus-campaign"
    assert payload["schema_version"] == "1.0.0"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert load_campaign(output) == campaign

    payload["unexpected"] = True
    output.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly"):
        load_campaign(output)


def test_load_campaign_migrates_only_known_unversioned_shape(tmp_path: Path) -> None:
    campaign = _build(tmp_path, ["a@example.com"])
    payload = campaign.to_dict()
    payload.pop("schema_name")
    payload.pop("schema_version")
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_campaign(path) == campaign

    payload["schema_name"] = "olympus.proteus-campaign"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="schema_version"):
        load_campaign(path)


def test_cli_campaign_page_email_report(tmp_path: Path) -> None:
    targets = tmp_path / "targets.txt"
    targets.write_text("alice@example.com\nmallory@evil.test\n", encoding="utf-8")
    campaign_out = tmp_path / "campaign.json"
    result = runner.invoke(
        app,
        [
            "proteus",
            "campaign",
            "--engagement",
            "eng",
            "--targets",
            str(targets),
            "--landing-url",
            "https://train.example/p",
            "--scope",
            str(_scope(tmp_path)),
            "--log",
            str(tmp_path / "log"),
            "--i-am-authorized",
            "--output",
            str(campaign_out),
        ],
    )
    assert result.exit_code == 0, result.output
    campaign = json.loads(campaign_out.read_text(encoding="utf-8"))
    assert campaign["schema_name"] == "olympus.proteus-campaign"
    assert len(campaign["targets"]) == 1  # only in-scope alice
    token = campaign["targets"][0]["token"]
    assert token not in result.output
    assert "alice@example.com" not in result.stdout
    audit = (tmp_path / "log").read_text(encoding="utf-8")
    assert "mallory@evil.test" not in audit
    assert "proteus.campaign" in audit

    page_out = tmp_path / "page.html"
    assert (
        runner.invoke(
            app, ["proteus", "page", "--engagement", "eng", "--output", str(page_out)]
        ).exit_code
        == 0
    )

    email_result = runner.invoke(
        app, ["proteus", "email", "--campaign", str(campaign_out), "--token", token]
    )
    assert email_result.exit_code == 0
    assert token in email_result.output

    report_result = runner.invoke(
        app, ["proteus", "report", "--campaign", str(campaign_out), "--clicked", token]
    )
    assert report_result.exit_code == 0
    assert json.loads(report_result.output)["clicked"] == 1


def test_cli_campaign_requires_authorization(tmp_path: Path) -> None:
    targets = tmp_path / "t.txt"
    targets.write_text("alice@example.com\n", encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "proteus",
            "campaign",
            "--engagement",
            "e",
            "--targets",
            str(targets),
            "--landing-url",
            "https://train.example/p",
            "--scope",
            str(_scope(tmp_path)),
        ],
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output
