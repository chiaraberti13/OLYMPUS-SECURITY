"""SQLite-backed storage for engagements.

One table, one document per engagement, validated on the way in and out against
the versioned ``olympus.engagement`` contract. The database file is owner-only
(0600) because an engagement records the authorized perimeter of real testing.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

from olympus.core.contracts import validate_contract_header
from olympus.core.models import Engagement

#: Guard against an oversized stored document exhausting memory on load.
MAX_DOCUMENT_BYTES = 1_000_000

#: The canonical engagement database filename inside a storage directory, shared
#: by every interface (CLI, API, Web) so they all read the same engagements.
ENGAGEMENTS_DB_NAME = "engagements.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    engagement_id TEXT PRIMARY KEY,
    document TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


class EngagementStoreError(ValueError):
    """Raised when a stored engagement document is invalid or oversized."""


class SqliteEngagementStore:
    """A small, durable engagement repository shared by every interface."""

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

    def save(self, engagement: Engagement) -> str:
        """Insert or replace ``engagement`` and return its id."""
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO engagements"
                "(engagement_id, document, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (
                    engagement.engagement_id,
                    engagement.canonical_json(),
                    engagement.created_at.isoformat(),
                    engagement.updated_at.isoformat(),
                ),
            )
        return engagement.engagement_id

    def get(self, engagement_id: str) -> Engagement | None:
        """Return the stored engagement, or ``None`` if it does not exist."""
        row = self._conn.execute(
            "SELECT document FROM engagements WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()
        if row is None:
            return None
        return self._load(row["document"])

    def require(self, engagement_id: str) -> Engagement:
        """Return the stored engagement, or raise if it does not exist.

        Producers that must associate work with an engagement (Athena, Themis)
        resolve it through this helper so an unknown ``engagement_id`` fails loudly
        at the source rather than silently stamping objects with a dangling id.
        """
        engagement = self.get(engagement_id)
        if engagement is None:
            raise EngagementStoreError(f"unknown engagement_id: {engagement_id!r}")
        return engagement

    def list(self) -> list[Engagement]:
        """Return every stored engagement, most recently created first."""
        rows = self._conn.execute(
            "SELECT document FROM engagements ORDER BY created_at DESC, engagement_id"
        ).fetchall()
        return [self._load(row["document"]) for row in rows]

    @staticmethod
    def _load(document: str) -> Engagement:
        if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise EngagementStoreError("stored engagement document exceeds the size limit")
        try:
            raw = json.loads(document)
        except json.JSONDecodeError as exc:
            raise EngagementStoreError(f"invalid engagement JSON: {exc.msg}") from exc
        try:
            raw = validate_contract_header(raw, schema_name="olympus.engagement")
            return Engagement.model_validate(raw)
        except ValueError as exc:
            raise EngagementStoreError(str(exc)) from exc
