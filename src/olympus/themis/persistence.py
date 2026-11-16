"""Persistence backend selection for Themis jobs (ROADMAP DATA-2).

Every interface that needs the durable job store (CLI worker, API, web control
plane, ``themis jobs`` maintenance) resolves it through :func:`resolve_job_store`
instead of constructing a concrete store directly. This is the single seam where
the storage backend is chosen from a location/DSN:

* a filesystem path or a ``sqlite://`` / ``file:`` URL -> the local SQLite
  :class:`~olympus.themis.jobs.ThemisJobStore` (the default, single-host backend);
* a ``postgres://`` / ``postgresql://`` DSN -> :class:`UnsupportedBackendError`,
  an explicit, fail-closed refusal.

The PostgreSQL backend (for multi-user/concurrent deployments) is **planned, not
present**: rather than ship a stub that silently behaves like SQLite or crashes
obscurely, a Postgres DSN is refused with a clear message. The abstraction — the
:class:`JobStore` port below and this factory — is what lets that adapter drop in
later without touching the call sites.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import unquote, urlsplit

from olympus.themis.jobs import (
    DEFAULT_LEASE_SECONDS,
    JobExecution,
    JobRecords,
    JobState,
    ThemisJob,
    ThemisJobStore,
)

#: DSN schemes that name the planned PostgreSQL backend.
_POSTGRES_SCHEMES = frozenset({"postgres", "postgresql"})
#: DSN schemes that map to the local SQLite backend.
_SQLITE_SCHEMES = frozenset({"sqlite", "file"})


class UnsupportedBackendError(ValueError):
    """A persistence backend was requested that Olympus does not (yet) provide.

    A ``ValueError`` because asking for a backend that does not exist is a usage error:
    the CLI paths that already map ``ValueError`` to the USAGE exit code then refuse a
    Postgres DSN (or an unknown scheme) with a clear message instead of a traceback.
    """


@runtime_checkable
class JobStore(Protocol):
    """The durable job-store contract the worker and interfaces depend on (DATA-2).

    It is the structural port that any backend must satisfy; the SQLite
    :class:`~olympus.themis.jobs.ThemisJobStore` implements it today, and a future
    PostgreSQL adapter must implement the same surface. Only the methods the shared
    execution paths actually call are part of the port, so an alternative backend is
    held to a verifiable, minimal contract rather than every SQLite-specific detail.
    """

    def initialize(self) -> None: ...

    def submit(
        self,
        *,
        scanner: str,
        target: str,
        target_kind: str,
        scope_path: Path,
        authorized: bool,
        manifest_sha256: str | None = ...,
        idempotency_key: str | None = ...,
        max_attempts: int = ...,
    ) -> ThemisJob: ...

    def get(self, job_id: str) -> ThemisJob: ...

    def execution_record(self, job_id: str) -> JobExecution: ...

    def list(self, *, limit: int = ..., state: JobState | None = ...) -> JobRecords: ...

    def counts_by_state(self) -> dict[str, int]: ...

    def claim_next(self, worker_id: str, *, max_concurrent_jobs: int = ...) -> ThemisJob | None: ...

    def heartbeat(self, job_id: str, worker_id: str) -> ThemisJob: ...

    def cancel(self, job_id: str) -> ThemisJob: ...

    def cancellation_requested(self, job_id: str) -> bool: ...

    def complete(
        self,
        job_id: str,
        *,
        worker_id: str,
        state: JobState,
        result: dict[str, object] | None = ...,
        error: str | None = ...,
    ) -> ThemisJob: ...


def _sqlite_path(location: str | Path) -> Path:
    """Return the SQLite file path for ``location`` (a path or a sqlite/file URL).

    Raises :class:`UnsupportedBackendError` for a Postgres DSN or any other scheme, so
    an unknown or not-yet-available backend fails closed instead of being misread as a
    local file named ``postgresql:`` and silently creating the wrong store.
    """
    if isinstance(location, Path):
        return location
    text = location.strip()
    # A bare filesystem path (possibly with a Windows drive letter) has no URL scheme.
    split = urlsplit(text)
    scheme = split.scheme.lower()
    if not scheme or len(scheme) == 1:  # '' or a drive letter like 'c:'
        return Path(text)
    if scheme in _POSTGRES_SCHEMES:
        raise UnsupportedBackendError(
            "PostgreSQL job backend is not available yet (ROADMAP DATA-2): a Postgres DSN "
            "cannot be used. Use a local path or a sqlite:// URL; the Postgres adapter is "
            "planned for multi-user/concurrent deployments."
        )
    if scheme not in _SQLITE_SCHEMES:
        raise UnsupportedBackendError(
            f"unknown persistence backend scheme {scheme!r}: use a local path, a sqlite:// URL, "
            "or (once available) a postgresql:// DSN."
        )
    # sqlite:///abs/path -> netloc '' path '/abs/path'; file:rel or sqlite://rel keep the rest.
    raw = (split.netloc + split.path) if split.path else split.netloc
    resolved = unquote(raw)
    # Collapse an accidental leading '//' (POSIX treats it specially) to a single '/'.
    while resolved.startswith("//"):
        resolved = resolved[1:]
    if not resolved:
        raise UnsupportedBackendError(f"{scheme}:// URL has no database path")
    return Path(resolved)


def resolve_job_store(
    location: str | Path,
    *,
    lease_seconds: float = DEFAULT_LEASE_SECONDS,
) -> ThemisJobStore:
    """Resolve the durable job store for ``location`` (DATA-2 backend selection).

    A filesystem path or a ``sqlite://`` / ``file:`` URL yields the local SQLite store;
    a ``postgres(ql)://`` DSN or an unknown scheme raises :class:`UnsupportedBackendError`.
    The returned store is not yet initialized (callers that write call ``initialize``),
    matching direct ``ThemisJobStore`` construction.
    """
    return ThemisJobStore(_sqlite_path(location), lease_seconds=lease_seconds)


def describe_backend(location: str | Path) -> str:
    """Return a short, non-secret label of the backend ``location`` selects.

    Never echoes credentials: for a DSN it reports only the scheme, so it is safe to log
    or show in a readiness view.
    """
    if isinstance(location, Path):
        return "sqlite"
    scheme = urlsplit(location.strip()).scheme.lower()
    if not scheme or len(scheme) == 1:
        return "sqlite"
    if scheme in _POSTGRES_SCHEMES:
        return "postgresql (planned, unavailable)"
    if scheme in _SQLITE_SCHEMES:
        return "sqlite"
    return f"{scheme} (unsupported)"


__all__ = [
    "JobStore",
    "UnsupportedBackendError",
    "describe_backend",
    "resolve_job_store",
]
