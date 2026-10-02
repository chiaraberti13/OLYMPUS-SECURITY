"""Append-only SQLite storage for finding lifecycle transitions (ROADMAP ``WEB-C``).

One row per transition, validated on the way in and out against the versioned
``olympus.finding-transition`` contract. The log is **append-only**: records are
inserted, never replaced or deleted, so the audit trail cannot be rewritten
through this API. The database file is owner-only (0600) because a transition
records who accepted or dismissed a real risk.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

from olympus.core.contracts import validate_contract_header
from olympus.core.models import FindingTransition

#: Guard against an oversized stored document exhausting memory on load.
MAX_DOCUMENT_BYTES = 1_000_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_transitions (
    transition_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    document TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_finding_transitions_finding
    ON finding_transitions (finding_id, occurred_at);
"""


class FindingTransitionStoreError(ValueError):
    """Raised when a stored transition document is invalid, oversized or duplicated."""


class SqliteFindingTransitionStore:
    """An append-only, durable audit log of finding status changes."""

    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
            path.parent.chmod(0o700)
        first_time = not path.exists()
        self._conn = sqlite3.connect(str(path))
        if first_time:
            with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
                path.chmod(0o600)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    def append(self, transition: FindingTransition) -> str:
        """Append one transition record and return its id.

        Append-only: a repeated ``transition_id`` is rejected rather than
        overwriting history.
        """
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO finding_transitions"
                    "(transition_id, finding_id, document, occurred_at) VALUES (?, ?, ?, ?)",
                    (
                        transition.transition_id,
                        transition.finding_id,
                        transition.model_dump_json(),
                        transition.occurred_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise FindingTransitionStoreError(
                f"duplicate transition_id: {transition.transition_id}"
            ) from exc
        return transition.transition_id

    def history(self, finding_id: str) -> list[FindingTransition]:
        """Return every transition for ``finding_id``, oldest first."""
        rows = self._conn.execute(
            "SELECT document FROM finding_transitions WHERE finding_id = ? "
            "ORDER BY occurred_at, transition_id",
            (finding_id,),
        ).fetchall()
        return [self._load(row["document"]) for row in rows]

    @staticmethod
    def _load(document: str) -> FindingTransition:
        if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise FindingTransitionStoreError("stored transition document exceeds the size limit")
        try:
            raw = json.loads(document)
        except json.JSONDecodeError as exc:
            raise FindingTransitionStoreError(f"invalid transition JSON: {exc.msg}") from exc
        try:
            raw = validate_contract_header(raw, schema_name="olympus.finding-transition")
            return FindingTransition.model_validate(raw)
        except ValueError as exc:
            raise FindingTransitionStoreError(str(exc)) from exc
