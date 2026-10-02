"""Unit tests for the finding transition audit record and its store (WEB-C)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from olympus.core.enums import FindingStatus, Source
from olympus.core.finding_lifecycle import FindingTransitionError, record_transition
from olympus.core.models import Finding, FindingTransition
from olympus.findings.store import FindingTransitionStoreError, SqliteFindingTransitionStore

TRANSITION_ID = re.compile(r"^FTR-\d{4}-\d{5}$")


def _finding(status: FindingStatus = FindingStatus.NEW, **kwargs: object) -> Finding:
    return Finding(
        asset_id="AST-2026-00001", source=Source.THEMIS, title="x", status=status, **kwargs
    )  # type: ignore[arg-type]


def test_transition_record_has_traceable_id_and_schema() -> None:
    record = FindingTransition(
        finding_id="FND-2026-00001",
        from_status=FindingStatus.NEW,
        to_status=FindingStatus.CONFIRMED,
        actor="analyst@team",
    )
    assert TRANSITION_ID.match(record.transition_id)
    assert record.schema_name == "olympus.finding-transition"
    assert record.schema_version == "1.0.0"


def test_transition_record_rejects_multiline_actor() -> None:
    with pytest.raises(ValidationError):
        FindingTransition(
            finding_id="FND-2026-00001",
            from_status=FindingStatus.NEW,
            to_status=FindingStatus.CONFIRMED,
            actor="line1\nline2",
        )


def test_record_transition_returns_finding_and_audit_record() -> None:
    finding = _finding(FindingStatus.NEW, engagement_id="ENG-2026-00001")
    moved, record = record_transition(
        finding, FindingStatus.CONFIRMED, actor="analyst@team", reason="verified"
    )
    assert moved.status is FindingStatus.CONFIRMED
    assert finding.status is FindingStatus.NEW  # original untouched
    assert record.from_status is FindingStatus.NEW
    assert record.to_status is FindingStatus.CONFIRMED
    assert record.actor == "analyst@team"
    assert record.reason == "verified"
    assert record.finding_id == finding.finding_id
    assert record.occurred_at == moved.last_seen
    assert record.engagement_id == "ENG-2026-00001"  # scoped to the same engagement


def test_record_transition_rejects_illegal_move_without_a_record() -> None:
    with pytest.raises(FindingTransitionError):
        record_transition(_finding(FindingStatus.CLOSED), FindingStatus.NEW, actor="a")


def test_store_appends_and_returns_history_oldest_first(tmp_path: Path) -> None:
    store = SqliteFindingTransitionStore(tmp_path / "ft.db")
    try:
        finding = _finding(FindingStatus.NEW)
        moved, first = record_transition(finding, FindingStatus.CONFIRMED, actor="a")
        _, second = record_transition(moved, FindingStatus.IN_REMEDIATION, actor="a")
        store.append(first)
        store.append(second)
        history = store.history(finding.finding_id)
        assert [r.to_status for r in history] == [
            FindingStatus.CONFIRMED,
            FindingStatus.IN_REMEDIATION,
        ]
        assert store.history("FND-UNKNOWN") == []
    finally:
        store.close()


def test_store_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "ft.db"
    store = SqliteFindingTransitionStore(path)
    store.close()
    assert (path.stat().st_mode & 0o777) == 0o600


def test_store_is_append_only_rejecting_duplicate_ids(tmp_path: Path) -> None:
    store = SqliteFindingTransitionStore(tmp_path / "ft.db")
    try:
        _, record = record_transition(_finding(), FindingStatus.CONFIRMED, actor="a")
        store.append(record)
        with pytest.raises(FindingTransitionStoreError, match="duplicate transition_id"):
            store.append(record)
    finally:
        store.close()


def test_store_rejects_a_tampered_document(tmp_path: Path) -> None:
    import sqlite3

    store = SqliteFindingTransitionStore(tmp_path / "ft.db")
    _, record = record_transition(_finding(), FindingStatus.CONFIRMED, actor="a")
    store.append(record)
    store.close()
    conn = sqlite3.connect(str(tmp_path / "ft.db"))
    conn.execute(
        "UPDATE finding_transitions SET document = ?", ('{"schema_name": "olympus.wrong"}',)
    )
    conn.commit()
    conn.close()
    reopened = SqliteFindingTransitionStore(tmp_path / "ft.db")
    try:
        with pytest.raises(FindingTransitionStoreError):
            reopened.history(record.finding_id)
    finally:
        reopened.close()
