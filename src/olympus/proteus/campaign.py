"""Validated, authorized awareness-campaign domain logic."""

from __future__ import annotations

import html
import json
import os
import re
import secrets
import tempfile
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from olympus.core.contracts import validate_contract_header
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.proteus.scope import (
    ProteusScopeError,
    enforce_landing_scope,
    enforce_scope,
    load_scope,
    normalize_email,
    normalize_landing_url,
)

CAMPAIGN_SCHEMA_NAME = "olympus.proteus-campaign"
CAMPAIGN_SCHEMA_VERSION = "1.0.0"
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
_MAX_TARGETS = 10_000


@dataclass(frozen=True)
class Target:
    """One recipient in a campaign, with its unique tracking token."""

    email: str
    token: str


@dataclass(frozen=True)
class Campaign:
    """A versioned awareness campaign containing bearer tracking tokens."""

    SCHEMA_NAME: ClassVar[str] = CAMPAIGN_SCHEMA_NAME
    SCHEMA_VERSION: ClassVar[str] = CAMPAIGN_SCHEMA_VERSION

    engagement: str
    subject: str
    sender: str
    landing_url: str
    targets: tuple[Target, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        """Return the strict persisted campaign contract."""
        return {
            "schema_name": self.SCHEMA_NAME,
            "schema_version": self.SCHEMA_VERSION,
            "engagement": self.engagement,
            "subject": self.subject,
            "sender": self.sender,
            "landing_url": self.landing_url,
            "targets": [{"email": target.email, "token": target.token} for target in self.targets],
        }


def _validate_header(value: str, field_name: str) -> str:
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > 255
        or any(character in normalized for character in "\r\n\x00")
    ):
        raise ValueError(f"{field_name} must be non-blank, at most 255 characters, and one line")
    return normalized


def _validate_token(value: str) -> str:
    if not _TOKEN.fullmatch(value):
        raise ValueError("campaign tokens must be 20 to 128 URL-safe characters")
    return value


def validate_campaign_metadata(
    engagement: str, subject: str, sender: str, landing_url: str
) -> tuple[str, str, str, str]:
    """Validate non-target campaign input before authorization or scope access."""
    return (
        _validate_header(engagement, "engagement"),
        _validate_header(subject, "subject"),
        normalize_email(_validate_header(sender, "sender")),
        normalize_landing_url(landing_url),
    )


def build_campaign(
    engagement: str,
    emails: list[str],
    scope_path: Path,
    log_path: Path,
    *,
    policy: ExecutionPolicy,
    subject: str,
    sender: str,
    landing_url: str,
    token_factory: Callable[[], str] | None = None,
    cancellation: Cancellation | None = None,
) -> Campaign:
    """Validate campaign settings, enforce every scope dimension, and mint tokens."""
    normalized_engagement, normalized_subject, normalized_sender, normalized_landing = (
        validate_campaign_metadata(engagement, subject, sender, landing_url)
    )
    if not emails:
        raise ValueError("campaign requires at least one in-scope target")
    if len(emails) > _MAX_TARGETS:
        raise ValueError(f"campaign supports at most {_MAX_TARGETS} targets")

    policy.require_authorization("Proteus awareness campaign")
    scope = load_scope(scope_path)
    if scope.engagement != normalized_engagement:
        raise ProteusScopeError(
            f"campaign engagement {normalized_engagement!r} does not match scope engagement "
            f"{scope.engagement!r}"
        )
    enforce_scope(normalized_sender, scope_path, log_path)
    enforce_landing_scope(normalized_landing, scope_path, log_path)

    factory = token_factory or (lambda: secrets.token_urlsafe(16))
    cancellation_token = cancellation or NeverCancelled()
    targets: list[Target] = []
    seen_emails: set[str] = set()
    seen_tokens: set[str] = set()
    for raw_email in emails:
        policy.check_cancellation(cancellation_token)
        email = normalize_email(raw_email)
        if email.lower() in seen_emails:
            raise ValueError(f"duplicate campaign target: {email}")
        enforce_scope(email, scope_path, log_path)
        target_token = _validate_token(factory())
        if target_token in seen_tokens:
            raise ValueError("token factory produced a duplicate campaign token")
        seen_emails.add(email.lower())
        seen_tokens.add(target_token)
        targets.append(Target(email=email, token=target_token))
    return Campaign(
        engagement=normalized_engagement,
        subject=normalized_subject,
        sender=normalized_sender,
        landing_url=normalized_landing,
        targets=tuple(targets),
    )


def tracking_link(campaign: Campaign, target: Target) -> str:
    """Return a query-safe training link with exactly one tracking token."""
    token = _validate_token(target.token)
    parsed = urlsplit(normalize_landing_url(campaign.landing_url))
    query = [(key, value) for key, value in parse_qsl(parsed.query) if key != "t"]
    query.append(("t", token))
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def render_email(campaign: Campaign, target: Target) -> str:
    """Render one plain-text simulated lure with injection-safe headers."""
    sender = normalize_email(_validate_header(campaign.sender, "sender"))
    recipient = normalize_email(target.email)
    subject = _validate_header(campaign.subject, "subject")
    return (
        f"From: {sender}\n"
        f"To: {recipient}\n"
        f"Subject: {subject}\n\n"
        "We noticed unusual activity on your account and need you to review it.\n"
        f"Please confirm your details here: {tracking_link(campaign, target)}\n\n"
        "If you do not act, access may be suspended.\n"
    )


def render_training_page(engagement: str) -> str:
    """Render a static awareness page with no form, script, or data capture."""
    safe = html.escape(_validate_header(engagement, "engagement"))
    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        "<title>Security awareness — simulated phishing</title></head>\n"
        '<body style="font-family:sans-serif;max-width:40rem;margin:3rem auto">\n'
        "<h1>This was a phishing simulation</h1>\n"
        f"<p>You clicked a link in an <strong>authorized security-awareness test</strong> "
        f"for <em>{safe}</em>. No information was collected and no account was affected.</p>\n"
        "<h2>How to spot the next one</h2>\n"
        "<ul>\n"
        "<li>Check the sender address and hover links before clicking.</li>\n"
        '<li>Be wary of urgency ("act now or lose access").</li>\n'
        "<li>Never enter credentials from an email link — navigate to the site yourself.</li>\n"
        "<li>Report suspicious messages to your security team.</li>\n"
        "</ul>\n"
        "<p>Thank you for helping keep the organization safe.</p>\n"
        "</body></html>\n"
    )


def campaign_report(campaign: Campaign, clicked_tokens: set[str]) -> dict[str, object]:
    """Summarize only known click tokens; unknown tokens never affect metrics."""
    valid = {target.token for target in campaign.targets}
    clicked = valid & clicked_tokens
    total = len(campaign.targets)
    rate = round(100 * len(clicked) / total, 1) if total else 0.0
    return {
        "schema_name": "olympus.proteus-campaign-report",
        "schema_version": "1.0.0",
        "engagement": campaign.engagement,
        "targets": total,
        "clicked": len(clicked),
        "click_rate_percent": rate,
        "clicked_emails": sorted(
            target.email for target in campaign.targets if target.token in clicked
        ),
    }


def export_campaign(campaign: Campaign, path: Path) -> None:
    """Atomically persist bearer tokens with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(campaign.to_dict(), indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        path.chmod(0o600)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def _migrate_legacy(raw: object) -> object:
    if not isinstance(raw, dict):
        return raw
    has_name = "schema_name" in raw
    has_version = "schema_version" in raw
    if not has_name and not has_version:
        return {"schema_name": CAMPAIGN_SCHEMA_NAME, "schema_version": "1.0.0", **raw}
    return raw


def load_campaign(path: Path) -> Campaign:
    """Load a strict campaign contract, with one explicit unversioned migration."""
    raw: object = _migrate_legacy(json.loads(path.read_text(encoding="utf-8")))
    document = validate_contract_header(raw, schema_name=CAMPAIGN_SCHEMA_NAME)
    expected = {
        "schema_name",
        "schema_version",
        "engagement",
        "subject",
        "sender",
        "landing_url",
        "targets",
    }
    if set(document) != expected:
        raise ValueError(f"campaign document must define exactly {sorted(expected)}")
    targets_raw: Any = document["targets"]
    if not isinstance(targets_raw, list) or len(targets_raw) > _MAX_TARGETS:
        raise ValueError(f"campaign targets must be an array of at most {_MAX_TARGETS} entries")
    targets: list[Target] = []
    seen_emails: set[str] = set()
    seen_tokens: set[str] = set()
    for item in targets_raw:
        if not isinstance(item, dict) or set(item) != {"email", "token"}:
            raise ValueError("each campaign target must define exactly email and token")
        email_value, token_value = item["email"], item["token"]
        if not isinstance(email_value, str) or not isinstance(token_value, str):
            raise ValueError("campaign target email and token must be strings")
        email = normalize_email(email_value)
        token = _validate_token(token_value)
        if email.lower() in seen_emails or token in seen_tokens:
            raise ValueError("campaign target emails and tokens must be unique")
        seen_emails.add(email.lower())
        seen_tokens.add(token)
        targets.append(Target(email, token))
    for field_name in ("engagement", "subject", "sender", "landing_url"):
        if not isinstance(document[field_name], str):
            raise ValueError(f"campaign {field_name} must be a string")
    return Campaign(
        engagement=_validate_header(document["engagement"], "engagement"),
        subject=_validate_header(document["subject"], "subject"),
        sender=normalize_email(_validate_header(document["sender"], "sender")),
        landing_url=normalize_landing_url(document["landing_url"]),
        targets=tuple(targets),
    )
