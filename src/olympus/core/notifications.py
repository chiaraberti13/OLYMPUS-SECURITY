"""Optional, redacted outbound notifications — the output port (ROADMAP ``WEB-I``).

A defender wants to hear when something happens — a job closes, a finding lands —
without logging into a dashboard. This module is that **output port on the core**
(the roadmap's "Iris"), deliberately *not* a new domain module: it turns the
shared contracts Olympus already owns (:class:`~olympus.core.models.Finding`,
:class:`~olympus.core.models.ScanJob`) into a small, versioned, **redacted**
:class:`Notification` payload and delivers it over an operator-configured channel.

Three invariants hold, by construction:

* **Redacted, no secrets.** Every human-readable field passes through
  :func:`~olympus.core.execution.safe_terminal_text` (one line, controls
  stripped, URL credentials redacted) and every label through
  :func:`~olympus.core.execution.redact_mapping`. The payload carries
  *references* to results, never raw credentials — the same rule as the rest of
  the platform.
* **Off by default.** A :class:`NotificationDispatcher` with no channels is a
  no-op; nothing leaves the host until an operator wires a channel in.
* **SSRF-safe egress.** The default webhook transport pins every hop to the
  :func:`~olympus.core.pinning.global_address_policy` (public addresses only), so
  a misconfigured or hostile URL cannot be turned into a request against cloud
  metadata or an internal service.

The payload builders and the dispatcher are pure and offline; only the concrete
:class:`PinnedWebhookPoster` touches the network, behind the :class:`WebhookPoster`
protocol so tests inject an in-memory double.
"""

from __future__ import annotations

import json
import smtplib
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from enum import StrEnum
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import Field

from olympus.core.enums import Severity
from olympus.core.execution import redact_mapping, safe_terminal_text
from olympus.core.http import USER_AGENT
from olympus.core.models import Finding, OlympusModel, ScanJob
from olympus.core.pinning import (
    AddressPolicy,
    PinnedConnectionError,
    global_address_policy,
    pinned_handlers,
)

#: Webhook schemes Olympus will dial. A webhook is operator-configured, but the
#: egress is still constrained so a typo or a hostile value cannot reach, e.g., a
#: ``file://`` or ``gopher://`` SSRF gadget.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Bounds for the default transport: a webhook acknowledgement is small, so a
#: large body is drained-and-dropped rather than buffered.
_DEFAULT_TIMEOUT_SECONDS = 10.0
_DEFAULT_MAX_ACK_BYTES = 64 * 1024


class NotificationKind(StrEnum):
    """Which platform event a notification describes."""

    JOB = "job"
    FINDING = "finding"


class Notification(OlympusModel):
    """A redacted, versioned event payload safe to deliver to an external sink.

    This is the contract the webhook body carries, so a consumer can rely on its
    ``schema_name``/``schema_version`` exactly like any other Olympus document.
    """

    schema_name: Literal["olympus.notification"] = "olympus.notification"
    kind: NotificationKind
    title: str
    summary: str = ""
    severity: Severity | None = None
    engagement_id: str | None = None
    occurred_at: datetime | None = None
    labels: dict[str, str] = Field(default_factory=dict)

    def canonical_json(self) -> str:
        """Return the deterministic JSON encoding delivered on the wire."""
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _redact_labels(labels: Mapping[str, str]) -> dict[str, str]:
    """Redact label keys/values, coercing back to the contract's ``dict[str, str]``."""
    return {key: str(value) for key, value in redact_mapping(labels).items()}


def notification_from_finding(finding: Finding) -> Notification:
    """Build a redacted notification announcing a finding."""
    return Notification(
        kind=NotificationKind.FINDING,
        title=safe_terminal_text(f"[{finding.severity.value}] {finding.title}"),
        summary=safe_terminal_text(finding.description),
        severity=finding.severity,
        engagement_id=finding.engagement_id,
        occurred_at=finding.last_seen,
        labels=_redact_labels(
            {
                "finding_id": finding.finding_id,
                "asset_id": finding.asset_id,
                "source": finding.source.value,
                "status": finding.status.value,
            }
        ),
    )


def notification_from_scan_job(job: ScanJob) -> Notification:
    """Build a redacted notification announcing a scan job's state."""
    summary = f"adapter {job.adapter} on {job.target_kind} {job.target_value} is {job.state}"
    if job.error_code:
        summary += f" (error {job.error_code})"
    return Notification(
        kind=NotificationKind.JOB,
        title=safe_terminal_text(f"job {job.job_id}: {job.state}"),
        summary=safe_terminal_text(summary),
        labels=_redact_labels(
            {
                "job_id": job.job_id,
                "assessment_id": job.assessment_id,
                "adapter": job.adapter,
                "state": str(job.state),
                "target_kind": job.target_kind,
            }
        ),
    )


@dataclass(frozen=True)
class DeliveryResult:
    """The outcome of attempting to deliver one notification over one channel."""

    channel: str
    delivered: bool
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"channel": self.channel, "delivered": self.delivered, "detail": self.detail}


class NotificationChannel(Protocol):
    """A sink able to deliver a :class:`Notification` (webhook, e-mail, ...)."""

    @property
    def name(self) -> str:
        """A short, stable channel label used in delivery results."""
        ...

    def send(self, notification: Notification) -> DeliveryResult:
        """Deliver ``notification`` and report the outcome (never raise)."""
        ...


class WebhookDeliveryError(RuntimeError):
    """Raised by a poster when a webhook request cannot be completed."""


class WebhookPoster(Protocol):
    """Anything able to POST a notification body to a webhook URL."""

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> int:
        """POST ``body`` to ``url`` and return the HTTP status code."""
        ...


@dataclass(frozen=True)
class WebhookChannel:
    """Deliver notifications as a JSON ``POST`` to one operator-configured URL."""

    url: str
    poster: WebhookPoster
    name: str = "webhook"

    def __post_init__(self) -> None:
        scheme = urlsplit(self.url).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ValueError(f"webhook URL must be http(s), got scheme {scheme!r}")

    def send(self, notification: Notification) -> DeliveryResult:
        body = notification.canonical_json().encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        try:
            status = self.poster.post(self.url, body, headers)
        except WebhookDeliveryError as exc:
            return DeliveryResult(self.name, delivered=False, detail=str(exc))
        return DeliveryResult(self.name, delivered=200 <= status < 300, detail=f"HTTP {status}")


@dataclass
class PinnedWebhookPoster:
    """SSRF-safe webhook transport: pins every hop to a public-only address policy."""

    policy: AddressPolicy = field(default_factory=global_address_policy)
    timeout: float = _DEFAULT_TIMEOUT_SECONDS
    max_ack_bytes: int = _DEFAULT_MAX_ACK_BYTES

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> int:
        opener = urllib.request.build_opener(*pinned_handlers(self.policy))
        request = urllib.request.Request(  # noqa: S310 (WebhookChannel checked the scheme)
            url, data=body, headers=dict(headers), method="POST"
        )
        try:
            with opener.open(request, timeout=self.timeout) as response:
                response.read(self.max_ack_bytes)  # drain a bounded acknowledgement
                return int(response.status)
        except urllib.error.HTTPError as exc:
            # The endpoint answered but rejected the payload: a real, non-2xx result.
            return int(exc.code)
        except PinnedConnectionError as exc:
            raise WebhookDeliveryError(f"address policy refused destination: {exc}") from exc
        except urllib.error.URLError as exc:
            raise WebhookDeliveryError(f"webhook request failed: {exc.reason}") from exc


def _email_body(notification: Notification) -> str:
    """Render the already-redacted notification as a plain-text e-mail body."""
    lines = [notification.summary, ""]
    if notification.severity is not None:
        lines.append(f"Severity: {notification.severity.value}")
    if notification.engagement_id:
        lines.append(f"Engagement: {notification.engagement_id}")
    if notification.occurred_at is not None:
        lines.append(f"Occurred at: {notification.occurred_at.isoformat()}")
    lines.extend(f"{key}: {notification.labels[key]}" for key in sorted(notification.labels))
    lines.extend(["", "— Olympus (automated, authorized security testing)"])
    return "\n".join(lines)


class EmailTransport(Protocol):
    """Anything able to hand a built :class:`EmailMessage` to a mail server."""

    def send(self, message: EmailMessage) -> None:
        """Deliver ``message`` or raise on failure."""
        ...


@dataclass(frozen=True)
class EmailChannel:
    """Deliver notifications as a plain-text e-mail to one or more recipients."""

    transport: EmailTransport
    sender: str
    recipients: tuple[str, ...]
    name: str = "email"

    def __post_init__(self) -> None:
        if not self.recipients:
            raise ValueError("email channel needs at least one recipient")
        for address in (self.sender, *self.recipients):
            # A minimal sanity check; the title is already single-line
            # (safe_terminal_text) so a header cannot be forged via a newline.
            if "@" not in address or "\n" in address or "\r" in address:
                raise ValueError(f"invalid e-mail address: {address!r}")

    def send(self, notification: Notification) -> DeliveryResult:
        message = EmailMessage()
        message["Subject"] = notification.title
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)
        message.set_content(_email_body(notification))
        try:
            self.transport.send(message)
        except (OSError, smtplib.SMTPException) as exc:
            return DeliveryResult(self.name, delivered=False, detail=f"smtp error: {exc}")
        return DeliveryResult(
            self.name, delivered=True, detail=f"sent to {len(self.recipients)} recipient(s)"
        )


@dataclass
class SmtpEmailTransport:
    """Default e-mail transport over SMTP (stdlib ``smtplib``)."""

    host: str
    port: int = 25
    timeout: float = _DEFAULT_TIMEOUT_SECONDS

    def send(self, message: EmailMessage) -> None:
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
            smtp.send_message(message)


@dataclass(frozen=True)
class NotificationDispatcher:
    """Fan one notification out to every configured channel. Off by default."""

    channels: tuple[NotificationChannel, ...] = ()

    @property
    def enabled(self) -> bool:
        """``True`` only once at least one channel is wired in."""
        return bool(self.channels)

    def dispatch(self, notification: Notification) -> tuple[DeliveryResult, ...]:
        """Deliver ``notification`` to every channel; an empty dispatcher is a no-op."""
        return tuple(channel.send(notification) for channel in self.channels)


__all__ = [
    "DeliveryResult",
    "EmailChannel",
    "EmailTransport",
    "Notification",
    "NotificationChannel",
    "NotificationDispatcher",
    "NotificationKind",
    "PinnedWebhookPoster",
    "SmtpEmailTransport",
    "WebhookChannel",
    "WebhookDeliveryError",
    "WebhookPoster",
    "notification_from_finding",
    "notification_from_scan_job",
]
