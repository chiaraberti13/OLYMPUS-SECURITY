"""Crash-recoverable concurrency leases for the Themis control plane."""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

DEFAULT_REQUEST_LEASE_SECONDS = 30.0


@dataclass(frozen=True)
class RequestLease:
    """Opaque ownership token for one in-flight request."""

    token: str


class RequestConcurrencyGate:
    """Coordinate a non-blocking request cap through a SQLite sidecar.

    Separate API and Web processes configured with the same job database use
    the same sidecar and namespace. Expiring leases recover capacity after a
    process crash; live requests renew their lease before expiry.
    """

    def __init__(
        self,
        database: Path,
        limit: int,
        *,
        namespace: str = "themis-control-plane",
        lease_seconds: float = DEFAULT_REQUEST_LEASE_SECONDS,
        clock: Callable[[], float] = time.time,
        token_factory: Callable[[], str] = lambda: uuid4().hex,
    ) -> None:
        if not namespace or len(namespace) > 128:
            raise ValueError("concurrency namespace must contain 1 to 128 characters")
        if isinstance(limit, bool) or not 1 <= limit <= 4_096:
            raise ValueError("concurrency limit must be between 1 and 4096")
        if not 3.0 <= lease_seconds <= 3_600.0:
            raise ValueError("concurrency lease_seconds must be between 3 and 3600")
        self._path = database.with_name(f"{database.name}.requests")
        self._limit = limit
        self._namespace = namespace
        self._lease_seconds = lease_seconds
        self._clock = clock
        self._token_factory = token_factory
        self._initialize()

    @property
    def heartbeat_seconds(self) -> float:
        """Renew at one third of the lease lifetime."""
        return self._lease_seconds / 3.0

    @property
    def path(self) -> Path:
        """Return the sidecar path for operations diagnostics."""
        return self._path

    def try_acquire(self) -> RequestLease | None:
        """Acquire one slot atomically, or fail without queueing."""
        now = self._clock()
        try:
            with self._transaction() as db:
                self._purge_expired(db, now)
                active = int(
                    db.execute(
                        "SELECT COUNT(*) FROM request_leases WHERE namespace = ?",
                        (self._namespace,),
                    ).fetchone()[0]
                )
                if active >= self._limit:
                    return None
                token = self._token_factory()
                db.execute(
                    "INSERT INTO request_leases(namespace, token, expires_at) VALUES (?, ?, ?)",
                    (self._namespace, token, now + self._lease_seconds),
                )
        except (OSError, sqlite3.Error):
            return None
        return RequestLease(token)

    def renew(self, lease: RequestLease) -> bool:
        """Extend a live lease; missing/expired ownership fails closed."""
        now = self._clock()
        try:
            with self._transaction() as db:
                self._purge_expired(db, now)
                changed = db.execute(
                    "UPDATE request_leases SET expires_at = ? WHERE namespace = ? AND token = ?",
                    (now + self._lease_seconds, self._namespace, lease.token),
                ).rowcount
        except (OSError, sqlite3.Error):
            return False
        return changed == 1

    def release(self, lease: RequestLease) -> None:
        """Release owned capacity; expiry makes repeated release harmless."""
        try:
            with self._transaction() as db:
                db.execute(
                    "DELETE FROM request_leases WHERE namespace = ? AND token = ?",
                    (self._namespace, lease.token),
                )
        except (OSError, sqlite3.Error):
            # An expired lease is recoverable. A temporarily unavailable store
            # will purge it no later than the lease deadline.
            return

    def _initialize(self) -> None:
        if self._path.is_symlink():
            raise ValueError("Themis concurrency database must not be a symlink")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect(timeout=10.0) as db:
                db.execute("PRAGMA journal_mode = WAL")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS request_leases ("
                    "namespace TEXT NOT NULL, token TEXT NOT NULL, expires_at REAL NOT NULL, "
                    "PRIMARY KEY(namespace, token))"
                )
                db.execute(
                    "CREATE INDEX IF NOT EXISTS request_leases_expiry "
                    "ON request_leases(namespace, expires_at)"
                )
                db.execute(
                    "CREATE TABLE IF NOT EXISTS request_gate_config ("
                    "namespace TEXT PRIMARY KEY, concurrency_limit INTEGER NOT NULL)"
                )
        except sqlite3.Error as exc:
            raise ValueError("Themis concurrency database could not be initialized") from exc
        try:
            with self._transaction() as db:
                self._purge_expired(db, self._clock())
                configured = db.execute(
                    "SELECT concurrency_limit FROM request_gate_config WHERE namespace = ?",
                    (self._namespace,),
                ).fetchone()
                if configured is None:
                    db.execute(
                        "INSERT INTO request_gate_config(namespace, concurrency_limit) "
                        "VALUES (?, ?)",
                        (self._namespace, self._limit),
                    )
                elif int(configured[0]) != self._limit:
                    active = int(
                        db.execute(
                            "SELECT COUNT(*) FROM request_leases WHERE namespace = ?",
                            (self._namespace,),
                        ).fetchone()[0]
                    )
                    if active:
                        raise ValueError(
                            "Themis concurrency limit cannot change while requests are active"
                        )
                    db.execute(
                        "UPDATE request_gate_config SET concurrency_limit = ? WHERE namespace = ?",
                        (self._limit, self._namespace),
                    )
        except sqlite3.Error as exc:
            raise ValueError("Themis concurrency database could not be configured") from exc
        self._path.chmod(0o600)

    def _connect(self, *, timeout: float = 0.0) -> sqlite3.Connection:
        db = sqlite3.connect(self._path, timeout=timeout, isolation_level=None)
        db.execute(f"PRAGMA busy_timeout = {int(timeout * 1_000)}")
        return db

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _purge_expired(self, db: sqlite3.Connection, now: float) -> None:
        db.execute(
            "DELETE FROM request_leases WHERE namespace = ? AND expires_at <= ?",
            (self._namespace, now),
        )
