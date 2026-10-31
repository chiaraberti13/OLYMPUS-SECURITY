"""Unit tests for the finding transition audit record and its store (WEB-C)."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from olympus.core.enums import FindingStatus, Source
from olympus.core.finding_lifecycle import FindingTransitionError, record_transition
from olympus.core.models import Finding, FindingTransition
from olympus.core.secrets import EnvSecretProvider
from olympus.findings.store import (
    FINDINGS_ENCRYPTION_KEY_ENV,
    FindingTransitionStoreError,
    SqliteFindingTransitionStore,
)

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


def test_store_append_next_allocates_distinct_ids(tmp_path: Path) -> None:
    # Two stores on the same ledger (CLI and a restarted worker) append without
    # colliding; each gets a distinct id derived from persisted state.
    database = tmp_path / "ft.db"
    a = SqliteFindingTransitionStore(database)
    b = SqliteFindingTransitionStore(database)
    try:
        finding = _finding(FindingStatus.NEW)
        moved, first = record_transition(finding, FindingStatus.CONFIRMED, actor="a")
        _, second = record_transition(moved, FindingStatus.IN_REMEDIATION, actor="a")
        stored_first = a.append_next(first)
        stored_second = b.append_next(second)
        assert stored_first.transition_id != stored_second.transition_id
        assert [r.to_status for r in a.history(finding.finding_id)] == [
            FindingStatus.CONFIRMED,
            FindingStatus.IN_REMEDIATION,
        ]
    finally:
        a.close()
        b.close()


def test_store_append_next_is_concurrency_safe(tmp_path: Path) -> None:
    # DEV-E-03: concurrent appends to the shared append-only ledger each get a
    # distinct id with no lost record and no surfaced duplicate error.
    import threading

    database = tmp_path / "ft.db"
    SqliteFindingTransitionStore(database).close()
    finding = _finding(FindingStatus.NEW)
    _, built = record_transition(finding, FindingStatus.CONFIRMED, actor="a")
    worker_count = 8
    barrier = threading.Barrier(worker_count)
    ids: list[str] = []
    errors: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        store = SqliteFindingTransitionStore(database)
        try:
            barrier.wait()
            stored = store.append_next(built)
            with lock:
                ids.append(stored.transition_id)
        except Exception as exc:
            with lock:
                errors.append(repr(exc))
        finally:
            store.close()

    threads = [threading.Thread(target=worker) for _ in range(worker_count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(set(ids)) == worker_count  # every appended id is distinct
    verify = SqliteFindingTransitionStore(database)
    try:
        assert len(verify.history(finding.finding_id)) == worker_count  # all persisted
    finally:
        verify.close()


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


def test_next_transition_id_is_collision_free_against_stored_state(tmp_path: Path) -> None:
    path = tmp_path / "ft.db"
    store = SqliteFindingTransitionStore(path)
    try:
        # An empty ledger allocates the first id for the year.
        first = store.next_transition_id(2026)
        assert first == "FTR-2026-00001"
        _, record = record_transition(_finding(), FindingStatus.CONFIRMED, actor="a")
        store.append(record.model_copy(update={"transition_id": first}))
        # The next allocation skips the persisted id even in a brand-new process
        # where new_id() would restart at FTR-2026-00001.
        assert store.next_transition_id(2026) == "FTR-2026-00002"
        # A different calendar year keeps its own sequence.
        assert store.next_transition_id(2027) == "FTR-2027-00001"
    finally:
        store.close()


def test_store_rejects_a_tampered_document(tmp_path: Path) -> None:
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


def test_store_encrypts_transition_documents_and_reads_them_with_the_same_key(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ft.db"
    provider = EnvSecretProvider(environ={FINDINGS_ENCRYPTION_KEY_ENV: "f" * 32})
    store = SqliteFindingTransitionStore(path, secrets=provider)
    finding = _finding()
    _, record = record_transition(
        finding,
        FindingStatus.CONFIRMED,
        actor="analyst@example.test",
        reason="credential exposed in synthetic fixture",
    )
    store.append(record)
    store.close()

    connection = sqlite3.connect(str(path))
    stored = connection.execute("SELECT document FROM finding_transitions").fetchone()[0]
    connection.close()
    assert "analyst@example.test" not in stored
    assert "credential exposed" not in stored
    assert '"scheme": "olympus.enc.v1"' in stored

    reopened = SqliteFindingTransitionStore(path, secrets=provider)
    try:
        assert reopened.history(finding.finding_id) == [record]
    finally:
        reopened.close()


def test_encrypted_store_fails_closed_without_the_correct_key(tmp_path: Path) -> None:
    path = tmp_path / "ft.db"
    provider = EnvSecretProvider(environ={FINDINGS_ENCRYPTION_KEY_ENV: "f" * 32})
    store = SqliteFindingTransitionStore(path, secrets=provider)
    finding = _finding()
    _, record = record_transition(finding, FindingStatus.CONFIRMED, actor="a")
    store.append(record)
    store.close()

    for environ in ({}, {FINDINGS_ENCRYPTION_KEY_ENV: "x" * 32}):
        reopened = SqliteFindingTransitionStore(path, secrets=EnvSecretProvider(environ=environ))
        try:
            with pytest.raises(FindingTransitionStoreError):
                reopened.history(finding.finding_id)
        finally:
            reopened.close()


def test_store_rejects_a_short_encryption_key(tmp_path: Path) -> None:
    with pytest.raises(FindingTransitionStoreError, match="at least 32"):
        SqliteFindingTransitionStore(
            tmp_path / "ft.db",
            secrets=EnvSecretProvider(environ={FINDINGS_ENCRYPTION_KEY_ENV: "short"}),
        )


def test_encrypted_store_keeps_legacy_plaintext_rows_readable(tmp_path: Path) -> None:
    path = tmp_path / "ft.db"
    finding = _finding()
    _, legacy = record_transition(finding, FindingStatus.CONFIRMED, actor="legacy")
    plaintext = SqliteFindingTransitionStore(path, secrets=EnvSecretProvider(environ={}))
    plaintext.append(legacy)
    plaintext.close()

    encrypted = SqliteFindingTransitionStore(
        path,
        secrets=EnvSecretProvider(environ={FINDINGS_ENCRYPTION_KEY_ENV: "f" * 32}),
    )
    try:
        assert encrypted.history(finding.finding_id) == [legacy]
    finally:
        encrypted.close()
