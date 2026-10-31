"""Application use cases for scoped Proteus awareness artifacts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from olympus.core.execution import (
    Cancellation,
    ExecutionPolicy,
    NeverCancelled,
    StructuredAuditRecord,
    append_structured_audit,
)
from olympus.proteus.campaign import (
    Campaign,
    build_campaign,
    campaign_report,
    load_campaign,
    render_email,
    render_training_page,
    validate_campaign_metadata,
)
from olympus.proteus.scope import (
    ProteusOutOfScopeError,
    ProteusScopeError,
    enforce_landing_scope,
    enforce_scope,
    load_scope,
    normalize_email,
)

_MAX_TARGET_FILE_BYTES = 1_000_000
_MAX_TARGETS = 10_000


class CampaignTokenNotFoundError(LookupError):
    """Raised when an operator requests an unknown campaign token."""


@dataclass(frozen=True)
class CampaignBuildRequest:
    engagement: str
    targets_path: Path
    landing_url: str
    subject: str
    sender: str
    scope_path: Path
    audit_log_path: Path
    authorized: bool = False


@dataclass(frozen=True)
class CampaignBuildOutcome:
    campaign: Campaign
    skipped_targets: tuple[str, ...]


@dataclass(frozen=True)
class CampaignApplicationService:
    """Run every Proteus workflow independently from Typer presentation."""

    cancellation: Cancellation = field(default_factory=NeverCancelled)
    token_factory: Callable[[], str] | None = None

    def build(self, request: CampaignBuildRequest) -> CampaignBuildOutcome:
        emails = [normalize_email(item) for item in self._load_targets(request.targets_path)]
        engagement, subject, sender, landing_url = validate_campaign_metadata(
            request.engagement,
            request.subject,
            request.sender,
            request.landing_url,
        )
        policy = ExecutionPolicy(
            authorized=request.authorized,
            timeout_seconds=1.0,
            deadline_seconds=60.0,
        )
        policy.require_authorization("Proteus awareness campaign")
        scope = load_scope(request.scope_path)
        if scope.engagement != engagement:
            raise ProteusScopeError(
                f"campaign engagement {engagement!r} does not match scope engagement "
                f"{scope.engagement!r}"
            )
        enforce_scope(sender, request.scope_path, request.audit_log_path)
        enforce_landing_scope(landing_url, request.scope_path, request.audit_log_path)
        kept: list[str] = []
        skipped: list[str] = []
        for email in emails:
            policy.check_cancellation(self.cancellation)
            try:
                enforce_scope(email, request.scope_path, request.audit_log_path)
            except ProteusOutOfScopeError:
                skipped.append(email)
            else:
                kept.append(email)
        policy.check_cancellation(self.cancellation)
        if not kept:
            raise ProteusOutOfScopeError("all campaign targets", request.scope_path)
        campaign = build_campaign(
            engagement,
            kept,
            request.scope_path,
            request.audit_log_path,
            policy=policy,
            subject=subject,
            sender=sender,
            landing_url=landing_url,
            token_factory=self.token_factory,
            cancellation=self.cancellation,
        )
        append_structured_audit(
            request.audit_log_path,
            StructuredAuditRecord(
                timestamp=datetime.now(UTC).isoformat(),
                execution_id=str(uuid4()),
                action="proteus.campaign",
                outcome="completed",
                target=None,
                metadata={
                    "engagement": campaign.engagement,
                    "targets": len(campaign.targets),
                    "skipped_targets": len(skipped),
                },
            ),
        )
        return CampaignBuildOutcome(campaign, tuple(skipped))

    def render_page(self, engagement: str) -> str:
        return render_training_page(engagement)

    def render_campaign_email(self, campaign_path: Path, token: str) -> str:
        campaign = load_campaign(campaign_path)
        target = next((item for item in campaign.targets if item.token == token), None)
        if target is None:
            raise CampaignTokenNotFoundError("campaign token was not found")
        return render_email(campaign, target)

    def report(self, campaign_path: Path, clicked_tokens: set[str]) -> dict[str, object]:
        return campaign_report(load_campaign(campaign_path), clicked_tokens)

    @staticmethod
    def _load_targets(path: Path) -> list[str]:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"targets must be a regular non-symlink file: {path}")
        if path.stat().st_size > _MAX_TARGET_FILE_BYTES:
            raise ValueError(f"targets file exceeds {_MAX_TARGET_FILE_BYTES} bytes")
        lines = path.read_text(encoding="utf-8").splitlines()
        targets = [
            line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")
        ]
        if not targets:
            raise ValueError("targets file contains no recipients")
        if len(targets) > _MAX_TARGETS:
            raise ValueError(f"targets file contains more than {_MAX_TARGETS} recipients")
        return targets
