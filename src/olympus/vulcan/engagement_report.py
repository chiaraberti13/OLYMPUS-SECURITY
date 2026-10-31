"""Reusable report front matter derived from a signed engagement manifest.

The scope, methodology and disclaimer of a professional report do not change
from one finding to the next — they are a property of the *engagement*. This
module turns an :class:`~olympus.engagements.manifest.EngagementManifest` (the
SEC-C authorization boundary) into a small, display-only
:class:`EngagementReportContext`, so every report for the same engagement
renders the same scope statement, the same authorized-technique methodology and
the same authorization disclaimer, parametrized only by the manifest.

The context carries plain, already-extracted values (never the manifest object
and never a signature). Building it is not an authorization decision: it only
restates, for the reader, what the manifest declares. Rendering lives in
:mod:`olympus.vulcan.report`, next to the other escaped renderers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from olympus.engagements.manifest import EngagementManifest


@dataclass(frozen=True)
class EngagementReportContext:
    """Display-only engagement facts that parametrize the reusable report sections."""

    engagement_id: str
    client: str
    owner: str
    approver: str
    contract_id: str
    valid_from: datetime
    expires_at: datetime
    scope_included: tuple[str, ...]
    scope_excluded: tuple[str, ...]
    allowed_techniques: tuple[str, ...]
    max_targets: int
    max_concurrency: int
    max_runtime_seconds: int

    def window_utc(self) -> tuple[str, str]:
        """Return the engagement validity window as ISO-8601 UTC strings."""
        return (
            self.valid_from.astimezone(UTC).isoformat(),
            self.expires_at.astimezone(UTC).isoformat(),
        )


def engagement_context(manifest: EngagementManifest) -> EngagementReportContext:
    """Extract the display-only report context from an engagement manifest.

    This restates the manifest for the reader; it verifies nothing and makes no
    authorization decision. Callers that need an authorization check must still
    go through :meth:`SignedEngagementManifest.authorize`.
    """
    return EngagementReportContext(
        engagement_id=manifest.engagement_id,
        client=manifest.client,
        owner=manifest.owner,
        approver=manifest.approver,
        contract_id=manifest.contract_id,
        valid_from=manifest.valid_from,
        expires_at=manifest.expires_at,
        scope_included=tuple(manifest.scope.included),
        scope_excluded=tuple(manifest.scope.excluded),
        allowed_techniques=tuple(manifest.allowed_techniques),
        max_targets=manifest.max_targets,
        max_concurrency=manifest.max_concurrency,
        max_runtime_seconds=manifest.max_runtime_seconds,
    )


__all__ = ["EngagementReportContext", "engagement_context"]
