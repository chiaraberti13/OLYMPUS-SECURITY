"""Tests for the redacted outbound-notification output port (ROADMAP ``WEB-I``).

Pin the three invariants the module promises: the payload is **redacted** and
**versioned**, delivery is **off by default** (an empty dispatcher never calls
out), and the webhook channel only dials ``http(s)`` and reports — never raises —
on a rejected or failed delivery. The network is never touched: the poster is an
in-memory double.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.enums import Severity, Source
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Finding, ScanJob
from olympus.core.notifications import (
    DeliveryResult,
    NotificationDispatcher,
    NotificationKind,
    WebhookChannel,
    WebhookDeliveryError,
    notification_from_finding,
    notification_from_scan_job,
)

runner = CliRunner()


class _RecordingPoster:
    """An in-memory :class:`WebhookPoster` that records calls and returns a status."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.calls: list[tuple[str, bytes, dict[str, str]]] = []

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> int:
        self.calls.append((url, body, dict(headers)))
        return self.status


class _FailingPoster:
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> int:
        raise WebhookDeliveryError("address policy refused destination")


def _finding(**overrides: object) -> Finding:
    base: dict[str, object] = {
        "asset_id": "AST-1",
        "source": Source.ARTEMIS,
        "title": "Reflected XSS",
        "severity": Severity.HIGH,
    }
    base.update(overrides)
    return Finding(**base)  # type: ignore[arg-type]


# --- payload builders ------------------------------------------------------- #


def test_finding_notification_is_versioned_and_redacted() -> None:
    finding = _finding(description="leak at https://x.example/a?api_key=SECRET&id=7")
    notification = notification_from_finding(finding)

    assert notification.schema_name == "olympus.notification"
    assert notification.schema_version == "1.0.0"
    assert notification.kind is NotificationKind.FINDING
    assert notification.severity is Severity.HIGH
    # The secret query value is gone; the harmless one survives.
    assert "SECRET" not in notification.summary
    assert "[REDACTED]" in notification.summary
    assert "id=7" in notification.summary
    assert notification.labels["asset_id"] == "AST-1"


def test_finding_notification_neutralises_terminal_injection() -> None:
    notification = notification_from_finding(_finding(title="pwn\r\n\x1b[31mFAKE", description="x"))
    assert "\x1b" not in notification.title
    assert "\n" not in notification.title and "\r" not in notification.title


def test_scan_job_notification_describes_state() -> None:
    job = ScanJob(
        job_id="JOB-1",
        assessment_id="ASM-1",
        adapter="nmap",
        target_kind="host",
        target_value="10.0.0.5",
        state="failed",
        error_code="E_TIMEOUT",
    )
    notification = notification_from_scan_job(job)
    assert notification.kind is NotificationKind.JOB
    assert "failed" in notification.summary and "E_TIMEOUT" in notification.summary
    assert notification.labels["adapter"] == "nmap"


def test_canonical_json_is_deterministic() -> None:
    notification = notification_from_finding(_finding())
    assert notification.canonical_json() == notification.canonical_json()
    assert json.loads(notification.canonical_json())["schema_name"] == "olympus.notification"


# --- dispatcher & channels -------------------------------------------------- #


def test_dispatcher_is_off_by_default() -> None:
    dispatcher = NotificationDispatcher()
    assert dispatcher.enabled is False
    assert dispatcher.dispatch(notification_from_finding(_finding())) == ()


def test_webhook_channel_delivers_2xx_and_posts_versioned_body() -> None:
    poster = _RecordingPoster(status=202)
    channel = WebhookChannel("https://hooks.example/olympus", poster)
    result = channel.send(notification_from_finding(_finding()))

    assert result == DeliveryResult("webhook", delivered=True, detail="HTTP 202")
    (url, body, headers) = poster.calls[0]
    assert url == "https://hooks.example/olympus"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body)["schema_name"] == "olympus.notification"


def test_webhook_channel_marks_non_2xx_as_not_delivered() -> None:
    channel = WebhookChannel("https://hooks.example/olympus", _RecordingPoster(status=500))
    result = channel.send(notification_from_finding(_finding()))
    assert result.delivered is False and result.detail == "HTTP 500"


def test_webhook_channel_reports_delivery_error_without_raising() -> None:
    channel = WebhookChannel("https://hooks.example/olympus", _FailingPoster())
    result = channel.send(notification_from_finding(_finding()))
    assert result.delivered is False
    assert "refused" in result.detail


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://evil/x", "ftp://host/x"])
def test_webhook_channel_rejects_non_http_scheme(url: str) -> None:
    with pytest.raises(ValueError, match="http"):
        WebhookChannel(url, _RecordingPoster())


# --- CLI -------------------------------------------------------------------- #


def _write_findings(path: Path) -> Path:
    bundle = [
        _finding(title="Critical RCE", severity=Severity.CRITICAL).model_dump(mode="json"),
        _finding(title="Info banner", severity=Severity.INFO).model_dump(mode="json"),
    ]
    target = path / "findings.json"
    target.write_text(json.dumps(bundle), encoding="utf-8")
    return target


def test_cli_preview_is_off_by_default_and_filters_by_severity(tmp_path: Path) -> None:
    findings = _write_findings(tmp_path)
    result = runner.invoke(
        app, ["vulcan", "notify", "--findings", str(findings), "--format", "json"]
    )
    assert result.exit_code == int(ExitCode.OK), result.output
    payload = json.loads(result.stdout[result.stdout.index("[") : result.stdout.rindex("]") + 1])
    # MEDIUM default threshold keeps CRITICAL, drops INFO; nothing is delivered.
    assert len(payload) == 1
    assert payload[0]["delivery"] == "preview"


def test_cli_webhook_delivery_reports_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    findings = _write_findings(tmp_path)
    # Patch the transport the CLI constructs so no real network call is made.
    monkeypatch.setattr(
        "olympus.vulcan.cli.PinnedWebhookPoster", lambda: _RecordingPoster(status=503)
    )
    result = runner.invoke(
        app,
        ["vulcan", "notify", "--findings", str(findings), "--webhook", "https://hooks.example/x"],
    )
    # A 503 is a delivery failure -> partial exit (not a clean 0).
    assert result.exit_code == int(ExitCode.PARTIAL), result.output
    assert "delivery failure" in result.output
