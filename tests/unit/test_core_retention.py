"""Tests for retention and best-effort secure deletion.

Deletion is exercised against real files: what matters is whether the bytes are
gone from the file and whether the path is unlinked, not whether a mock was
called.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.retention import (
    RetentionError,
    RetentionPolicy,
    prune_paths,
    rotate_log,
    secure_delete,
)

runner = CliRunner()


def _artefact(
    directory: Path, name: str, *, content: str = "evidence", age_days: float = 0
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(content, encoding="utf-8")
    if age_days:
        stamp = time.time() - age_days * 86_400
        os.utime(path, (stamp, stamp))
    return path


# --- secure deletion ------------------------------------------------------- #
def test_secure_delete_overwrites_then_unlinks(tmp_path: Path) -> None:
    path = _artefact(tmp_path, "evidence.json", content="password=hunter2")
    inode = path.stat().st_ino
    freed = secure_delete(path)

    assert freed == len("password=hunter2")
    assert not path.exists()
    # Nothing in the directory still holds the plaintext under that inode.
    assert all(entry.stat().st_ino != inode for entry in tmp_path.iterdir())


def test_secure_delete_removes_the_plaintext_before_unlinking(tmp_path: Path) -> None:
    path = _artefact(tmp_path, "big.txt", content="SECRET" * 1000)
    # Hold an open descriptor so the file's blocks survive the unlink and can
    # be read back: this observes the overwrite itself, not just the removal.
    with path.open("rb") as handle:
        secure_delete(path)
        handle.seek(0)
        assert b"SECRET" not in handle.read()


def test_secure_delete_refuses_symlinks_and_directories(tmp_path: Path) -> None:
    real = _artefact(tmp_path, "real.txt", content="keep me")
    link = tmp_path / "link.txt"
    link.symlink_to(real)
    with pytest.raises(RetentionError, match="symlink"):
        secure_delete(link)
    assert real.read_text() == "keep me"

    subdirectory = tmp_path / "subdir"
    subdirectory.mkdir()
    with pytest.raises((RetentionError, OSError)):
        secure_delete(subdirectory)


def test_secure_delete_of_a_missing_file_is_not_an_error(tmp_path: Path) -> None:
    assert secure_delete(tmp_path / "never-existed") == 0


def test_deletion_without_overwriting_is_opt_in(tmp_path: Path) -> None:
    path = _artefact(tmp_path, "quick.txt", content="data")
    assert secure_delete(path, overwrite=False) == 4
    assert not path.exists()


# --- retention policy ------------------------------------------------------ #
def test_a_policy_must_bound_something() -> None:
    with pytest.raises(RetentionError, match="must bound"):
        RetentionPolicy()
    with pytest.raises(RetentionError, match="max_age_days"):
        RetentionPolicy(max_age_days=99_999)
    with pytest.raises(RetentionError, match="max_files"):
        RetentionPolicy(max_files=99_999)


def test_age_based_retention_deletes_only_what_is_too_old(tmp_path: Path) -> None:
    old = _artefact(tmp_path, "old.json", age_days=40)
    recent = _artefact(tmp_path, "recent.json", age_days=2)

    report = prune_paths(tmp_path, policy=RetentionPolicy(max_age_days=30))

    assert report.removed == ("old.json",)
    assert report.kept == 1
    assert not old.exists() and recent.exists()


def test_count_based_retention_deletes_the_oldest_first(tmp_path: Path) -> None:
    for index, age in enumerate((5, 4, 3, 2, 1)):
        _artefact(tmp_path, f"report-{index}.json", age_days=age)

    report = prune_paths(tmp_path, policy=RetentionPolicy(max_files=2))

    assert report.removed == ("report-0.json", "report-1.json", "report-2.json")
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "report-3.json",
        "report-4.json",
    ]


def test_size_based_retention_deletes_until_it_fits(tmp_path: Path) -> None:
    _artefact(tmp_path, "a.bin", content="x" * 100, age_days=3)
    _artefact(tmp_path, "b.bin", content="x" * 100, age_days=2)
    _artefact(tmp_path, "c.bin", content="x" * 100, age_days=1)

    report = prune_paths(tmp_path, policy=RetentionPolicy(max_total_bytes=250))

    assert report.removed == ("a.bin",)
    assert report.freed_bytes == 100


def test_a_dry_run_reports_without_deleting(tmp_path: Path) -> None:
    path = _artefact(tmp_path, "old.json", age_days=90)
    report = prune_paths(tmp_path, policy=RetentionPolicy(max_age_days=30), dry_run=True)

    assert report.removed == ("old.json",) and report.dry_run is True
    assert path.exists(), "a dry run must not delete anything"


def test_retention_ignores_subdirectories_and_symlinks(tmp_path: Path) -> None:
    (tmp_path / "nested").mkdir()
    _artefact(tmp_path / "nested", "inner.json", age_days=90)
    target = _artefact(tmp_path, "target.json", age_days=90)
    link = tmp_path / "link.json"
    link.symlink_to(target)

    report = prune_paths(tmp_path, policy=RetentionPolicy(max_age_days=1), pattern="*.json")

    assert report.removed == ("target.json",)
    assert (tmp_path / "nested" / "inner.json").exists()
    assert link.is_symlink(), "a symlink is never followed or removed"


def test_retention_refuses_a_pattern_that_leaves_the_directory(tmp_path: Path) -> None:
    with pytest.raises(RetentionError, match="one directory"):
        prune_paths(tmp_path, policy=RetentionPolicy(max_age_days=1), pattern="../*")


def test_retention_refuses_a_symlinked_directory(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(RetentionError, match="non-symlink directory"):
        prune_paths(link, policy=RetentionPolicy(max_age_days=1))


def test_the_cutoff_is_evaluated_against_a_caller_supplied_moment(tmp_path: Path) -> None:
    _artefact(tmp_path, "yesterday.json", age_days=1)
    future = datetime.now(UTC) + timedelta(days=30)

    report = prune_paths(tmp_path, policy=RetentionPolicy(max_age_days=10), now=future)

    assert report.removed == ("yesterday.json",)


# --- log rotation ---------------------------------------------------------- #
def test_a_log_under_its_budget_is_left_alone(tmp_path: Path) -> None:
    log = _artefact(tmp_path, "audit.ndjson", content="line\n")
    report = rotate_log(log, max_bytes=1_000, keep=3)

    assert report.removed == () and report.kept == 1
    assert log.read_text() == "line\n"


def test_rotation_shifts_generations_and_drops_the_oldest(tmp_path: Path) -> None:
    log = _artefact(tmp_path, "audit.ndjson", content="current\n")
    _artefact(tmp_path, "audit.ndjson.1", content="one\n")
    _artefact(tmp_path, "audit.ndjson.2", content="two\n")

    report = rotate_log(log, max_bytes=1, keep=2)

    assert report.removed == ("audit.ndjson.2",)
    assert (tmp_path / "audit.ndjson.1").read_text() == "current\n"
    assert (tmp_path / "audit.ndjson.2").read_text() == "one\n"
    assert not log.exists(), "the live log is rolled, and recreated on the next append"


def test_rotation_with_no_history_deletes_the_live_log(tmp_path: Path) -> None:
    log = _artefact(tmp_path, "audit.ndjson", content="secret entry\n")
    report = rotate_log(log, max_bytes=1, keep=0)

    assert report.removed == ("audit.ndjson",)
    assert not log.exists()


def test_rotation_validates_its_budget_and_refuses_symlinks(tmp_path: Path) -> None:
    log = _artefact(tmp_path, "audit.ndjson", content="x" * 100)
    with pytest.raises(RetentionError, match="max_bytes"):
        rotate_log(log, max_bytes=0, keep=1)
    with pytest.raises(RetentionError, match="keep"):
        rotate_log(log, max_bytes=10, keep=1_000)

    link = tmp_path / "link.ndjson"
    link.symlink_to(log)
    with pytest.raises(RetentionError, match="symlink"):
        rotate_log(link, max_bytes=1, keep=1)


def test_rotating_a_missing_log_is_not_an_error(tmp_path: Path) -> None:
    assert rotate_log(tmp_path / "absent.ndjson", max_bytes=1, keep=1).examined == 0


# --- operator surface ------------------------------------------------------ #
def test_retention_cli_prunes_and_reports(tmp_path: Path) -> None:
    _artefact(tmp_path, "old.json", age_days=90)
    _artefact(tmp_path, "new.json", age_days=1)

    result = runner.invoke(
        app, ["themis", "retention", "prune", str(tmp_path), "--older-than-days", "30"]
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["removed"] == ["old.json"] and payload["kept"] == 1
    assert (tmp_path / "new.json").exists()


def test_retention_cli_requires_a_bound(tmp_path: Path) -> None:
    result = runner.invoke(app, ["themis", "retention", "prune", str(tmp_path)])
    assert result.exit_code == 2
    assert "must bound" in result.output


def test_rotate_log_cli(tmp_path: Path) -> None:
    log = _artefact(tmp_path, "audit.ndjson", content="x" * 200)
    result = runner.invoke(
        app,
        ["themis", "retention", "rotate-log", str(log), "--max-bytes", "100", "--keep", "1"],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "audit.ndjson.1").exists()
