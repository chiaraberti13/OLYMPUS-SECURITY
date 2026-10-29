"""Append-only audit event contract for Athena.

Audit events are minimal and redaction-safe by construction: they carry a
producer-local per-assessment sequence (reassigned durably by persistent sinks),
an action, an outcome, and a small
allowlisted metadata object. Targets are represented minimally; credentials,
HTTP bodies, environment values, exception text, and raw findings are never
recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from olympus.core.execution import redact_mapping

#: Metadata keys an audit event is permitted to carry.
ALLOWED_METADATA_KEYS = frozenset(
    {"adapter", "target", "state", "error_code", "job_id", "count", "reason"}
)


class AuditRedactionError(ValueError):
    """Raised when an audit event would carry a disallowed metadata key."""


@dataclass(frozen=True)
class AuditEvent:
    """A single append-only audit record."""

    assessment_id: str
    sequence: int
    timestamp: str
    action: str
    outcome: str
    job_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        disallowed = set(self.metadata) - ALLOWED_METADATA_KEYS
        if disallowed:
            raise AuditRedactionError(
                f"audit metadata contains disallowed keys: {sorted(disallowed)}"
            )
        redacted = redact_mapping(self.metadata)
        object.__setattr__(self, "metadata", {key: str(value) for key, value in redacted.items()})

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the event."""
        return {
            "assessment_id": self.assessment_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "action": self.action,
            "outcome": self.outcome,
            "job_id": self.job_id,
            "metadata": dict(self.metadata),
        }
