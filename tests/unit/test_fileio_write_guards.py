"""Write destinations are validated before any bytes are written (§5.2).

`ensure_write_target` refuses a symlink target, an escape past an allowed base
(including through a symlinked parent), and — with `overwrite=False` — an
existing file. The atomic writers gain a race-free exclusive-create mode.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from olympus.core.fileio import (
    UnsafeWriteTarget,
    atomic_text_writer,
    atomic_write_bytes,
    atomic_write_text,
    ensure_write_target,
    iter_regular_utf8_lines,
)


def test_ensure_write_target_rejects_a_symlink_destination(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = tmp_path / "target.txt"
    link.symlink_to(outside)
    with pytest.raises(UnsafeWriteTarget, match="symlink"):
        ensure_write_target(link)


def test_ensure_write_target_allows_a_path_inside_the_base(tmp_path: Path) -> None:
    base = tmp_path / "out"
    base.mkdir()
    target = base / "nested" / "report.json"
    assert ensure_write_target(target, base=base) == target


def test_ensure_write_target_rejects_a_traversal_escape(tmp_path: Path) -> None:
    base = tmp_path / "out"
    base.mkdir()
    escape = base / ".." / "elsewhere.json"
    with pytest.raises(UnsafeWriteTarget, match="escapes the allowed base"):
        ensure_write_target(escape, base=base)


def test_ensure_write_target_rejects_a_symlinked_parent_escape(tmp_path: Path) -> None:
    base = tmp_path / "out"
    base.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    # A symlinked directory *inside* base that points outside it.
    (base / "link").symlink_to(external)
    target = base / "link" / "report.json"
    with pytest.raises(UnsafeWriteTarget, match="escapes the allowed base"):
        ensure_write_target(target, base=base)


def test_ensure_write_target_rejects_an_existing_file_when_create_only(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_text("existing", encoding="utf-8")
    with pytest.raises(UnsafeWriteTarget, match="overwrite"):
        ensure_write_target(target, overwrite=False)
    # Overwrite allowed by default.
    assert ensure_write_target(target) == target


def test_atomic_write_create_only_refuses_an_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    atomic_write_text(target, "first", overwrite=False)  # creates
    assert target.read_text(encoding="utf-8") == "first"
    with pytest.raises(UnsafeWriteTarget, match="overwrite"):
        atomic_write_text(target, "second", overwrite=False)
    assert target.read_text(encoding="utf-8") == "first"  # untouched


def test_atomic_write_create_only_leaves_no_temporary_behind(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    target.write_bytes(b"existing")
    with pytest.raises(UnsafeWriteTarget):
        atomic_write_bytes(target, b"new", overwrite=False)
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "report.json"]
    assert leftovers == []


def test_atomic_write_overwrite_replaces_by_default(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    atomic_write_text(target, "first")
    atomic_write_text(target, "second")  # default overwrite=True
    assert target.read_text(encoding="utf-8") == "second"


def test_streaming_reader_enforces_total_and_line_budgets(tmp_path: Path) -> None:
    source = tmp_path / "events.ndjson"
    source.write_text("one\ntwo\n", encoding="utf-8")
    assert list(iter_regular_utf8_lines(source, max_bytes=8, max_line_bytes=4, label="events")) == [
        "one\n",
        "two\n",
    ]
    with pytest.raises(ValueError, match="exceeds the 3 byte limit"):
        list(iter_regular_utf8_lines(source, max_bytes=8, max_line_bytes=3, label="events"))
    with pytest.raises(ValueError, match="exceeds the 7 byte limit"):
        list(iter_regular_utf8_lines(source, max_bytes=7, max_line_bytes=4, label="events"))


def test_atomic_stream_writer_rolls_back_a_partial_output(tmp_path: Path) -> None:
    target = tmp_path / "events.ndjson"
    target.write_text("previous\n", encoding="utf-8")
    with (
        pytest.raises(RuntimeError, match="stop"),
        atomic_text_writer(target, mode=0o600) as output,
    ):
        output.write("partial\n")
        raise RuntimeError("stop")
    assert target.read_text(encoding="utf-8") == "previous\n"
    assert [path.name for path in tmp_path.iterdir()] == ["events.ndjson"]
