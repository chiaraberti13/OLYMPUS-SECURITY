"""Audit sink adapters for Athena.

Two implementations of :class:`~olympus.athena.ports.AuditSink`: an in-memory
sink for tests and a durable SQLite-backed sink that redacts by construction
(the :class:`~olympus.athena.domain.audit.AuditEvent` already forbids
non-allowlisted metadata keys before it reaches storage).
"""

from __future__ import annotations

import json

from olympus.athena.adapters.sqlite import SqliteAssessmentRepository
from olympus.athena.domain.audit import AuditEvent


class InMemoryAuditSink:
    """Collect audit events in order, for tests and dry runs."""

    atomic_with_repository = False

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self.events.append(event)


class SqliteAuditSink:
    """Persist events with store-assigned sequences, independent of producer restarts."""

    atomic_with_repository = True

    def __init__(self, repository: SqliteAssessmentRepository) -> None:
        self._repo = repository

    def append(self, event: AuditEvent) -> None:
        self._repo.append_audit(
            event.assessment_id,
            None,
            event.timestamp,
            event.action,
            event.outcome,
            event.job_id,
            json.dumps(event.metadata, sort_keys=True),
        )
