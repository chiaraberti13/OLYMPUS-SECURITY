"""Shared engagement resolution and scope enforcement (ROADMAP WEB-B slice 3).

The API and the web control plane expose the *same* engagements, backed by the
*same* :class:`~olympus.engagements.store.SqliteEngagementStore`, and derive
scope enforcement from the *same* engagement scope. To keep the two interfaces
genuinely identical — not merely similar — every behaviour lives here and both
layers call it:

* opening the owner-only store for a short-lived read (a fresh connection per
  call, because the interfaces serve requests from a worker thread pool while a
  :class:`sqlite3.Connection` is bound to the thread that created it);
* deriving the host that an engagement scope is checked against from a typed
  target (``host``/``domain`` verbatim, ``url`` by its parsed hostname);
* answering whether an engagement authorizes a given target.

The helpers are pure and raise :class:`EngagementStoreError` on an unknown or
invalid engagement; each interface translates that into its own surface (an HTTP
status on the API, an error page on the web) rather than duplicating the lookup.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from olympus.core.models import Engagement
from olympus.engagements.store import EngagementStoreError, SqliteEngagementStore


def load_engagements(database: Path) -> list[Engagement]:
    """Return every stored engagement (most recent first) from ``database``.

    A fresh connection is opened and closed for the read so the call is safe
    from any worker thread.
    """
    store = SqliteEngagementStore(database)
    try:
        return store.list()
    finally:
        store.close()


def require_engagement(database: Path, engagement_id: str) -> Engagement:
    """Return the stored engagement, or raise if it does not exist.

    Mirrors :meth:`SqliteEngagementStore.require` so an unknown id fails loudly
    rather than silently skipping scope enforcement.
    """
    store = SqliteEngagementStore(database)
    try:
        return store.require(engagement_id)
    finally:
        store.close()


def host_for_target(target: str, target_kind: str) -> str:
    """Return the hostname an engagement scope is matched against.

    ``host`` and ``domain`` targets are used verbatim; a ``url`` target is
    reduced to its hostname so the engagement scope — which is expressed in
    hostnames and domains — is checked against the right value and never against
    a scheme, port, path or query string.
    """
    if target_kind == "url":
        return urlsplit(target).hostname or ""
    return target.strip()


def engagement_covers(engagement: Engagement, target: str, target_kind: str) -> bool:
    """Return ``True`` if ``engagement`` authorizes testing ``target``.

    Scope enforcement is derived from the engagement's own scope, identically on
    every interface: a target outside the authorized perimeter is rejected
    before any job is queued.
    """
    host = host_for_target(target, target_kind)
    if not host:
        return False
    return engagement.covers(host)


__all__ = [
    "EngagementStoreError",
    "engagement_covers",
    "host_for_target",
    "load_engagements",
    "require_engagement",
]
