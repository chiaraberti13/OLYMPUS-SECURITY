"""SQLite-backed storage for engagements.

One table, one document per engagement, validated on the way in and out against
the versioned ``olympus.engagement`` contract. The database file is owner-only
(0600) because an engagement records the authorized perimeter of real testing.
"""

from __future__ import annotations

import contextlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from olympus.core.contracts import validate_contract_header
from olympus.core.models import Engagement
from olympus.engagements.manifest import EngagementManifest, SignedEngagementManifest

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
CREATE TABLE IF NOT EXISTS manifest_revocations (
    identifier TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_manifests (
    manifest_sha256 TEXT PRIMARY KEY,
    document TEXT NOT NULL,
    stored_at TEXT NOT NULL
);
"""


class EngagementStoreError(ValueError):
    """Raised when a stored engagement document is invalid or oversized."""


class SqliteEngagementStore:
    """A small, durable engagement repository shared by every interface."""

    def __init__(self, path: Path) -> None:
        self._path = path
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise OSError("engagement database must be a regular non-symlink file")
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

    def create(self, engagement: Engagement) -> str:
        """Insert a *new* engagement, refusing to overwrite an existing id.

        Unlike :meth:`save` (``INSERT OR REPLACE``, used for updates and import),
        this is fail-closed: if ``engagement.engagement_id`` already exists it
        raises :class:`EngagementStoreError` instead of silently replacing the
        stored engagement. That matters because :func:`olympus.core.ids.new_id`
        restarts its counter per process, so two separate ``engagement create``
        invocations would otherwise both mint ``ENG-<year>-00001`` and the second
        would destroy the first. Callers should allocate the id with
        :meth:`next_engagement_id`; this method is the last line of defence.
        """
        try:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO engagements"
                    "(engagement_id, document, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (
                        engagement.engagement_id,
                        engagement.canonical_json(),
                        engagement.created_at.isoformat(),
                        engagement.updated_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EngagementStoreError(
                f"engagement_id already exists: {engagement.engagement_id!r}"
            ) from exc
        return engagement.engagement_id

    def create_next(
        self, engagement: Engagement, *, year: int | None = None, attempts: int = 8
    ) -> Engagement:
        """Allocate a collision-free id and insert the engagement atomically.

        The id allocation (a ``SELECT`` of the current maximum) and the ``INSERT``
        run in the **same transaction**, and the ``engagement_id`` primary key plus
        a bounded retry make the pair safe under concurrent writers: two callers
        racing for the same sequence number cannot both succeed — the loser hits
        the UNIQUE constraint, recomputes against the now-committed row and takes
        the next id — so each gets a distinct id with neither a lost record nor a
        surfaced duplicate error. Returns the stored engagement with its id set.

        This supersedes calling :meth:`next_engagement_id` and :meth:`create`
        separately, where the gap between the read and the write is a race window.
        """
        target_year = engagement.created_at.year if year is None else year
        for _ in range(attempts):
            candidate = engagement.model_copy(
                update={"engagement_id": self.next_engagement_id(target_year)}
            )
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO engagements"
                        "(engagement_id, document, created_at, updated_at) VALUES (?, ?, ?, ?)",
                        (
                            candidate.engagement_id,
                            candidate.canonical_json(),
                            candidate.created_at.isoformat(),
                            candidate.updated_at.isoformat(),
                        ),
                    )
            except sqlite3.IntegrityError:
                continue  # another writer took this id; recompute and retry
            return candidate
        raise EngagementStoreError(
            f"could not allocate a unique engagement id after {attempts} attempts"
        )

    def next_engagement_id(self, year: int) -> str:
        """Allocate the next collision-free ``ENG-<year>-NNNNN`` id from stored state.

        The shared :func:`olympus.core.ids.new_id` generator restarts at ``1`` in
        every process, so a short-lived caller (a CLI invocation) would regenerate
        ids that already exist. This derives the next sequence number from the
        canonical ids actually persisted for ``year`` (``ENG-YYYY-NNNNN``), so it
        is unique regardless of process lifetime. The format matches ``new_id``
        (prefix ``ENG``, zero-padded to five digits).
        """
        prefix = f"ENG-{year}-"
        rows = self._conn.execute(
            "SELECT engagement_id FROM engagements WHERE engagement_id LIKE ?",
            (prefix + "%",),
        ).fetchall()
        highest = 0
        for row in rows:
            suffix = str(row["engagement_id"])[len(prefix) :]
            if suffix.isdigit():
                highest = max(highest, int(suffix))
        return f"{prefix}{highest + 1:05d}"

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

    def revoke_manifest(
        self, signed_manifest: SignedEngagementManifest, *, trusted_public_key_pem: str
    ) -> frozenset[str]:
        """Persist revocation identifiers only after verifying the signed manifest."""
        signed_manifest.verify_signature(trusted_public_key_pem=trusted_public_key_pem)
        identifiers = frozenset(
            {signed_manifest.manifest_sha256, signed_manifest.manifest.manifest_id}
        )
        revoked_at = datetime.now(UTC).isoformat()
        with self._conn:
            self._conn.executemany(
                "INSERT OR IGNORE INTO manifest_revocations (identifier, revoked_at) VALUES (?, ?)",
                ((identifier, revoked_at) for identifier in identifiers),
            )
        return identifiers

    def revoked_manifest_identifiers(self) -> frozenset[str]:
        """Return the durable revocation set for ``SignedEngagementManifest.authorize``."""
        rows = self._conn.execute("SELECT identifier FROM manifest_revocations").fetchall()
        return frozenset(str(row["identifier"]) for row in rows)

    def authorize_manifest(
        self,
        signed_manifest: SignedEngagementManifest,
        *,
        trusted_public_key_pem: str,
        target: str,
        technique: str,
        now: datetime,
    ) -> EngagementManifest:
        """Authorize against this store's persistent revocation register."""
        return signed_manifest.authorize(
            trusted_public_key_pem=trusted_public_key_pem,
            target=target,
            technique=technique,
            now=now,
            revoked=self.revoked_manifest_identifiers(),
        )

    def authorize_and_save_manifest(
        self,
        signed_manifest: SignedEngagementManifest,
        *,
        trusted_public_key_pem: str,
        target: str,
        technique: str,
        now: datetime,
    ) -> EngagementManifest:
        """Authorize and retain the signed document for worker-time revalidation."""
        manifest = self.authorize_manifest(
            signed_manifest,
            trusted_public_key_pem=trusted_public_key_pem,
            target=target,
            technique=technique,
            now=now,
        )
        document = json.dumps(
            signed_manifest.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise EngagementStoreError("signed manifest document exceeds the size limit")
        with self._conn:
            self._conn.execute(
                """INSERT INTO signed_manifests
                (manifest_sha256, document, stored_at) VALUES (?, ?, ?)
                ON CONFLICT(manifest_sha256) DO UPDATE SET
                    document = excluded.document, stored_at = excluded.stored_at""",
                (signed_manifest.manifest_sha256, document, datetime.now(UTC).isoformat()),
            )
        return manifest

    def authorize_stored_manifest(
        self,
        manifest_sha256: str,
        *,
        trusted_public_key_pem: str,
        target: str,
        technique: str,
        now: datetime,
    ) -> EngagementManifest:
        """Reload and reauthorize a queued job's exact signed manifest."""
        row = self._conn.execute(
            "SELECT document FROM signed_manifests WHERE manifest_sha256 = ?",
            (manifest_sha256,),
        ).fetchone()
        if row is None:
            raise EngagementStoreError("signed manifest bound to job is not available")
        document = str(row["document"])
        if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise EngagementStoreError("stored signed manifest document exceeds the size limit")
        try:
            signed_manifest = SignedEngagementManifest.model_validate_json(document)
        except ValueError as exc:
            raise EngagementStoreError("stored signed manifest document is invalid") from exc
        if signed_manifest.manifest_sha256 != manifest_sha256:
            raise EngagementStoreError("stored signed manifest digest does not match its key")
        return self.authorize_manifest(
            signed_manifest,
            trusted_public_key_pem=trusted_public_key_pem,
            target=target,
            technique=technique,
            now=now,
        )

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


class StoredManifestAuthorizer:
    """Short-lived SQLite adapter used by workers before scanner execution."""

    def __init__(self, database: Path, *, trusted_public_key_pem: str) -> None:
        if not trusted_public_key_pem.strip():
            raise ValueError("trusted manifest public key must not be empty")
        self._database = database
        self._trusted_public_key_pem = trusted_public_key_pem

    def authorize(
        self, *, manifest_sha256: str, target: str, technique: str, now: datetime
    ) -> None:
        """Recheck signature, digest, revocation, scope and time from durable state."""
        store = SqliteEngagementStore(self._database)
        try:
            store.authorize_stored_manifest(
                manifest_sha256,
                trusted_public_key_pem=self._trusted_public_key_pem,
                target=target,
                technique=technique,
                now=now,
            )
        finally:
            store.close()
