"""Append-only SQLite storage for finding lifecycle transitions (ROADMAP ``WEB-C``).

One row per transition, validated on the way in and out against the versioned
``olympus.finding-transition`` contract. The log is **append-only**: records are
inserted, never replaced or deleted, so the audit trail cannot be rewritten
through this API. The database file is owner-only (0600) because a transition
records who accepted or dismissed a real risk.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pydantic import SecretStr

from olympus.core.contracts import validate_contract_header
from olympus.core.crypto import ENCRYPTION_SCHEME, CryptoError, decrypt_to_text, encrypt_text
from olympus.core.migrations import initialize_sqlite_schema
from olympus.core.models import FindingTransition
from olympus.core.secrets import SecretProvider, resolve_secret

# The finding encryption-key policy (env name, minimum length) is defined once in
# olympus.findings.encryption and shared with the bundle-at-rest path; it is
# re-exported here so existing importers of FINDINGS_ENCRYPTION_KEY_ENV keep working.
from olympus.findings.encryption import (
    FINDINGS_ENCRYPTION_KEY_ENV,
)
from olympus.findings.encryption import (
    MIN_ENCRYPTION_KEY_LENGTH as _MIN_ENCRYPTION_KEY_LENGTH,
)

#: Guard against an oversized stored document exhausting memory on load.
MAX_DOCUMENT_BYTES = 1_000_000
MAX_STORED_DOCUMENT_BYTES = 2_000_000
SCHEMA_VERSION = 1

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


@dataclass(frozen=True)
class FindingTransitionBackupInfo:
    """Verification facts for one findings-lifecycle SQLite snapshot."""

    schema_version: int
    transition_count: int
    size_bytes: int
    sha256: str


class SqliteFindingTransitionStore:
    """An append-only, durable audit log of finding status changes."""

    def __init__(self, path: Path, *, secrets: SecretProvider | None = None) -> None:
        self._path = path
        self._encryption_key = _load_encryption_key(secrets)
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
        initialize_sqlite_schema(self._conn, _SCHEMA, current_version=SCHEMA_VERSION)

    def close(self) -> None:
        """Close the underlying connection."""
        self._conn.close()

    @staticmethod
    def backup_database(database: Path, destination: Path) -> FindingTransitionBackupInfo:
        """Atomically publish a verified, self-contained snapshot of this store.

        The snapshot preserves transition documents byte-for-byte, including
        encrypted documents. It does not contain or validate the encryption key.
        """
        source_path = _validated_database_file(database)
        if destination.is_symlink():
            raise OSError("finding-transition backup destination must not be a symlink")
        if destination.resolve() == source_path or _same_file(source_path, destination):
            raise ValueError("backup destination must differ from the live database")

        source, _ = _open_verified_transition_database(source_path, allow_sidecars=True)
        temporary: Path | None = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor, name = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
            )
            os.close(descriptor)
            temporary = Path(name)
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
                target.execute("PRAGMA journal_mode = DELETE")
            finally:
                target.close()
            temporary.chmod(0o600)
            info = SqliteFindingTransitionStore.verify_backup(temporary)
            temporary.replace(destination)
            destination.chmod(0o600)
            return info
        except BaseException:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise
        finally:
            source.close()

    @staticmethod
    def verify_backup(backup: Path) -> FindingTransitionBackupInfo:
        """Check store schema, integrity and fingerprint without decrypting rows."""
        connection, info = _open_verified_transition_database(backup)
        connection.close()
        return info

    @staticmethod
    def restore_backup(backup: Path, destination: Path) -> FindingTransitionBackupInfo:
        """Restore a verified snapshot to an absent path without overwriting."""
        source, info = _open_verified_transition_database(backup)
        temporary: Path | None = None
        try:
            if destination.is_symlink():
                raise OSError("restore destination must not be a symlink")
            if destination.resolve() == backup.resolve() or _same_file(backup, destination):
                raise ValueError("restore destination must differ from the backup")
            sidecars = tuple(
                Path(f"{destination}{suffix}") for suffix in ("-wal", "-shm", "-journal")
            )
            if destination.exists() or any(path.exists() or path.is_symlink() for path in sidecars):
                raise FileExistsError("restore destination and SQLite sidecars must be absent")
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor, name = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".restore", dir=destination.parent
            )
            os.close(descriptor)
            temporary = Path(name)
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
                target.execute("PRAGMA journal_mode = DELETE")
            finally:
                target.close()
            temporary.chmod(0o600)
            info = SqliteFindingTransitionStore.verify_backup(temporary)
            os.link(temporary, destination)
            temporary.unlink()
            return info
        except BaseException:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            raise
        finally:
            source.close()

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
                        self._encode(transition),
                        transition.occurred_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise FindingTransitionStoreError(
                f"duplicate transition_id: {transition.transition_id}"
            ) from exc
        return transition.transition_id

    def append_next(
        self, transition: FindingTransition, *, year: int | None = None, attempts: int = 8
    ) -> FindingTransition:
        """Allocate a collision-free id and append the transition atomically.

        The id allocation (a ``SELECT`` of the current maximum) and the ``INSERT``
        run in the **same transaction**, and the ``transition_id`` primary key plus
        a bounded retry make the pair safe under concurrent writers: two callers
        racing for the same sequence number cannot both succeed — the loser hits
        the UNIQUE constraint, recomputes against the now-committed row and takes
        the next id — so each append gets a distinct id with neither a lost record
        nor a surfaced duplicate error. Returns the stored transition with its id.

        This supersedes calling :meth:`next_transition_id` and :meth:`append`
        separately, where the gap between the read and the write is a race window.
        """
        target_year = transition.occurred_at.year if year is None else year
        for _ in range(attempts):
            candidate = transition.model_copy(
                update={"transition_id": self.next_transition_id(target_year)}
            )
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO finding_transitions"
                        "(transition_id, finding_id, document, occurred_at) VALUES (?, ?, ?, ?)",
                        (
                            candidate.transition_id,
                            candidate.finding_id,
                            self._encode(candidate),
                            candidate.occurred_at.isoformat(),
                        ),
                    )
            except sqlite3.IntegrityError:
                continue  # another writer took this id; recompute and retry
            return candidate
        raise FindingTransitionStoreError(
            f"could not allocate a unique transition id after {attempts} attempts"
        )

    def next_transition_id(self, year: int) -> str:
        """Allocate the next collision-free ``FTR-<year>-NNNNN`` id from stored state.

        The shared :func:`olympus.core.ids.new_id` generator restarts its counter
        at ``1`` in every process, so a short-lived caller (a CLI invocation, a
        restarted worker) would regenerate ids that already exist in this
        append-only ledger. This derives the next sequence number from the ids
        actually persisted for ``year``, so the id is unique regardless of process
        lifetime. The format matches ``new_id`` (prefix ``FTR``, zero-padded to at
        least five digits).
        """
        prefix = f"FTR-{year}-"
        rows = self._conn.execute(
            "SELECT transition_id FROM finding_transitions WHERE transition_id LIKE ?",
            (prefix + "%",),
        ).fetchall()
        highest = 0
        for row in rows:
            suffix = str(row["transition_id"])[len(prefix) :]
            if suffix.isdigit():
                highest = max(highest, int(suffix))
        return f"{prefix}{highest + 1:05d}"

    def history(self, finding_id: str) -> list[FindingTransition]:
        """Return every transition for ``finding_id``, oldest first."""
        rows = self._conn.execute(
            "SELECT document FROM finding_transitions WHERE finding_id = ? "
            "ORDER BY occurred_at, transition_id",
            (finding_id,),
        ).fetchall()
        return [self._load(row["document"]) for row in rows]

    def _encode(self, transition: FindingTransition) -> str:
        plaintext = transition.model_dump_json()
        if self._encryption_key is None:
            return plaintext
        return encrypt_text(plaintext, self._encryption_key.get_secret_value())

    def _load(self, document: str) -> FindingTransition:
        stored_bytes = len(document.encode("utf-8"))
        if stored_bytes > MAX_STORED_DOCUMENT_BYTES:
            raise FindingTransitionStoreError("stored transition document exceeds the size limit")
        try:
            raw = json.loads(document)
        except json.JSONDecodeError as exc:
            raise FindingTransitionStoreError(f"invalid transition JSON: {exc.msg}") from exc
        if isinstance(raw, dict) and raw.get("scheme") == ENCRYPTION_SCHEME:
            if self._encryption_key is None:
                raise FindingTransitionStoreError(
                    f"encrypted transition requires {FINDINGS_ENCRYPTION_KEY_ENV}"
                )
            try:
                document = decrypt_to_text(document, self._encryption_key.get_secret_value())
                raw = json.loads(document)
            except (CryptoError, json.JSONDecodeError) as exc:
                raise FindingTransitionStoreError(
                    "encrypted transition authentication failed"
                ) from exc
            if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
                raise FindingTransitionStoreError(
                    "decrypted transition document exceeds the size limit"
                )
        elif stored_bytes > MAX_DOCUMENT_BYTES:
            raise FindingTransitionStoreError("stored transition document exceeds the size limit")
        try:
            raw = validate_contract_header(raw, schema_name="olympus.finding-transition")
            return FindingTransition.model_validate(raw)
        except ValueError as exc:
            raise FindingTransitionStoreError(str(exc)) from exc


def _load_encryption_key(provider: SecretProvider | None) -> SecretStr | None:
    key = resolve_secret(FINDINGS_ENCRYPTION_KEY_ENV, provider=provider)
    if key is not None and len(key.get_secret_value()) < _MIN_ENCRYPTION_KEY_LENGTH:
        raise FindingTransitionStoreError(
            f"{FINDINGS_ENCRYPTION_KEY_ENV} must contain at least "
            f"{_MIN_ENCRYPTION_KEY_LENGTH} characters"
        )
    return key


def _validated_database_file(path: Path) -> Path:
    if path.is_symlink() or not path.is_file():
        raise OSError("finding-transition database must be a regular non-symlink file")
    return path.resolve()


def _same_file(source: Path, destination: Path) -> bool:
    try:
        return source.samefile(destination)
    except FileNotFoundError:
        return False


def _open_verified_transition_database(
    path: Path, *, allow_sidecars: bool = False
) -> tuple[sqlite3.Connection, FindingTransitionBackupInfo]:
    _validated_database_file(path)
    sidecars = tuple(Path(f"{path}{suffix}") for suffix in ("-wal", "-shm", "-journal"))
    if not allow_sidecars and any(sidecar.exists() or sidecar.is_symlink() for sidecar in sidecars):
        raise FindingTransitionStoreError(
            "finding-transition backup must be a self-contained SQLite file"
        )
    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != SCHEMA_VERSION:
            raise FindingTransitionStoreError(
                f"unsupported finding-transition backup schema version: {version}"
            )
        expected_columns = (
            "transition_id",
            "finding_id",
            "document",
            "occurred_at",
        )
        table_names = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        columns = tuple(
            str(row[1]) for row in connection.execute('PRAGMA table_info("finding_transitions")')
        )
        indexes = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if (
            table_names != {"finding_transitions"}
            or columns != expected_columns
            or indexes != {"idx_finding_transitions_finding"}
        ):
            raise FindingTransitionStoreError(
                "finding-transition backup schema does not match this release"
            )
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise FindingTransitionStoreError(
                "finding-transition backup failed SQLite integrity_check"
            )
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise FindingTransitionStoreError(
                "finding-transition backup contains foreign-key violations"
            )
        count = int(connection.execute("SELECT count(*) FROM finding_transitions").fetchone()[0])
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        info = FindingTransitionBackupInfo(
            schema_version=version,
            transition_count=count,
            size_bytes=path.stat().st_size,
            sha256=digest.hexdigest(),
        )
        return connection, info
    except BaseException:
        connection.close()
        raise
