"""Unit tests for the Engagement contract and its SQLite store (WEB-B)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from olympus.core.enums import EngagementStatus
from olympus.core.models import Engagement, EngagementScope
from olympus.engagements.store import EngagementStoreError, SqliteEngagementStore


def _engagement(name: str = "ACME") -> Engagement:
    return Engagement(
        name=name,
        client="ACME",
        scope=EngagementScope(
            included=("example.com", "api.example.com"), excluded=("db.example.com",)
        ),
        authorization_reference="CONTRACT-1",
    )


def test_scope_covers_included_but_not_excluded() -> None:
    scope = EngagementScope(included=("example.com",), excluded=("secret.example.com",))
    assert scope.covers("example.com")
    assert scope.covers("www.example.com")  # subdomain of an included domain
    assert not scope.covers("secret.example.com")  # excluded exactly
    assert not scope.covers("deep.secret.example.com")  # excluded subtree
    assert not scope.covers("other.org")  # not included


def test_scope_normalizes_entries() -> None:
    scope = EngagementScope(included=("  Example.COM. ",), excluded=("DB.Example.com",))
    assert scope.included == ("example.com",)
    assert scope.excluded == ("db.example.com",)


def test_scope_requires_at_least_one_included() -> None:
    with pytest.raises(ValidationError):
        EngagementScope(included=())


def test_scope_rejects_entries_with_spaces() -> None:
    with pytest.raises(ValidationError):
        EngagementScope(included=("bad domain",))


def test_engagement_has_stable_identity_and_schema() -> None:
    engagement = _engagement()
    assert engagement.schema_name == "olympus.engagement"
    assert engagement.engagement_id.startswith("ENG-")
    assert engagement.status is EngagementStatus.ACTIVE
    # The digest is deterministic for the same canonical content.
    assert (
        engagement.digest()
        == Engagement.model_validate(engagement.model_dump(mode="json")).digest()
    )


def test_store_round_trips_and_lists(tmp_path: Path) -> None:
    store = SqliteEngagementStore(tmp_path / "engagements.db")
    try:
        first = _engagement("first")
        second = _engagement("second")
        store.save(first)
        store.save(second)
        loaded = store.get(first.engagement_id)
        assert loaded is not None and loaded.name == "first"
        assert loaded.scope.covers("www.example.com")
        ids = {item.engagement_id for item in store.list()}
        assert {first.engagement_id, second.engagement_id} <= ids
        assert store.get("ENG-UNKNOWN") is None
    finally:
        store.close()


def test_store_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "engagements.db"
    store = SqliteEngagementStore(path)
    store.close()
    assert (path.stat().st_mode & 0o777) == 0o600


def test_store_rejects_a_tampered_document(tmp_path: Path) -> None:
    import sqlite3

    store = SqliteEngagementStore(tmp_path / "engagements.db")
    store.save(_engagement())
    store.close()
    conn = sqlite3.connect(str(tmp_path / "engagements.db"))
    conn.execute("UPDATE engagements SET document = ?", ('{"schema_name": "olympus.wrong"}',))
    conn.commit()
    conn.close()
    reopened = SqliteEngagementStore(tmp_path / "engagements.db")
    try:
        with pytest.raises(EngagementStoreError):
            reopened.list()
    finally:
        reopened.close()
