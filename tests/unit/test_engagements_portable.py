"""Portable NDJSON engagement import/export and its CLI (ROADMAP ``WEB-J``).

The acceptance criterion is that an engagement exported from one installation is
reimportable into another without data loss or contract violation. These tests
pin that round-trip, the deterministic wire format, the strict all-or-nothing
import, and the CLI exit codes.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.core.models import Engagement, EngagementScope
from olympus.engagements.portable import (
    EngagementPortabilityError,
    export_engagements,
    import_engagements,
)
from olympus.engagements.store import ENGAGEMENTS_DB_NAME, SqliteEngagementStore

runner = CliRunner()


def _engagement(eid: str, name: str, included: tuple[str, ...]) -> Engagement:
    return Engagement(
        engagement_id=eid,
        name=name,
        client="ACME",
        scope=EngagementScope(included=included, excluded=()),
    )


def test_export_is_deterministic_and_sorted_by_id() -> None:
    e1 = _engagement("ENG-2026-00001", "Alpha", ("a.example",))
    e2 = _engagement("ENG-2026-00002", "Beta", ("b.example",))
    first = export_engagements([e2, e1])
    assert first == export_engagements([e1, e2])  # order-independent
    lines = first.splitlines()
    assert json.loads(lines[0])["engagement_id"] == "ENG-2026-00001"
    assert json.loads(lines[1])["engagement_id"] == "ENG-2026-00002"


def test_round_trip_preserves_every_engagement_losslessly() -> None:
    originals = [
        _engagement("ENG-2026-00001", "Alpha", ("a.example",)),
        _engagement("ENG-2026-00002", "Beta", ("b.example", "c.example")),
    ]
    restored = import_engagements(export_engagements(originals))
    assert sorted(e.digest() for e in restored) == sorted(e.digest() for e in originals)


def test_import_ignores_blank_lines() -> None:
    e1 = _engagement("ENG-2026-00001", "Alpha", ("a.example",))
    text = "\n" + e1.canonical_json() + "\n\n"
    assert len(import_engagements(text)) == 1


def test_import_is_all_or_nothing_on_a_bad_line() -> None:
    good = _engagement("ENG-2026-00001", "Alpha", ("a.example",)).canonical_json()
    try:
        import_engagements(good + '\n{"schema_name": "wrong"}')
    except EngagementPortabilityError as exc:
        assert "line 2" in str(exc)
    else:  # pragma: no cover - the call must raise
        raise AssertionError("expected EngagementPortabilityError")


def test_import_rejects_an_oversize_line() -> None:
    e1 = _engagement("ENG-2026-00001", "Alpha", ("a.example",))
    try:
        import_engagements(e1.canonical_json(), max_line_bytes=10)
    except EngagementPortabilityError as exc:
        assert "byte limit" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected EngagementPortabilityError")


def _store(path: Path) -> SqliteEngagementStore:
    return SqliteEngagementStore(path / ENGAGEMENTS_DB_NAME)


def test_cli_export_then_import_moves_engagements_between_stores(tmp_path: Path) -> None:
    source = tmp_path / "a"
    source.mkdir()
    store = _store(source)
    originals = [
        _engagement("ENG-2026-00001", "Alpha", ("a.example",)),
        _engagement("ENG-2026-00002", "Beta", ("b.example",)),
    ]
    for engagement in originals:
        store.save(engagement)
    store.close()

    bundle = tmp_path / "engagements.ndjson"
    exported = runner.invoke(
        app, ["engagement", "export", "--storage", str(source), "-o", str(bundle)]
    )
    assert exported.exit_code == 0, exported.output
    assert json.loads(exported.output)["exported"] == 2

    target = tmp_path / "b"
    target.mkdir()
    imported = runner.invoke(
        app, ["engagement", "import", "--storage", str(target), "-i", str(bundle)]
    )
    assert imported.exit_code == 0, imported.output
    assert json.loads(imported.output)["imported"] == 2

    restored = _store(target)
    try:
        assert sorted(e.digest() for e in restored.list()) == sorted(e.digest() for e in originals)
    finally:
        restored.close()


def test_cli_import_rejects_a_malformed_file_without_writing(tmp_path: Path) -> None:
    bundle = tmp_path / "bad.ndjson"
    bundle.write_text("{not json}\n", encoding="utf-8")
    target = tmp_path / "b"
    target.mkdir()
    result = runner.invoke(
        app, ["engagement", "import", "--storage", str(target), "-i", str(bundle)]
    )
    assert result.exit_code == ExitCode.USAGE
    assert "invalid import" in result.output
    # Nothing was persisted.
    store = _store(target)
    try:
        assert store.list() == []
    finally:
        store.close()


def test_cli_export_unknown_id_fails_loudly(tmp_path: Path) -> None:
    source = tmp_path / "a"
    source.mkdir()
    _store(source).close()
    result = runner.invoke(
        app,
        [
            "engagement",
            "export",
            "--storage",
            str(source),
            "-o",
            str(tmp_path / "out.ndjson"),
            "--id",
            "ENG-2026-09999",
        ],
    )
    assert result.exit_code == ExitCode.USAGE
