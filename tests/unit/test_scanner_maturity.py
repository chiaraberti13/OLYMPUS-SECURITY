"""The generated maturity status block, and the guard that keeps it honest (DEV-G).

``docs/scanner-maturity.md`` carries curated prose, but its "Lo stato oggi"
table — the per-stage counts and the scanner names at each stage — is generated
from ``olympus.integrations.maturity`` (the registry plus the declared ledger).
These tests pin that the committed block equals the generator output, so a stale
table fails the build instead of quietly drifting, exactly as
``test_scanner_matrix.py`` does for the scanner matrix.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.integrations import maturity
from olympus.integrations.maturity import (
    LADDER,
    STATUS_BLOCK_BEGIN,
    STATUS_BLOCK_END,
    names_by_stage,
    render_status_section,
    summary,
)
from olympus.integrations.scanners import REGISTRY

runner = CliRunner()

_DOC = Path(__file__).resolve().parents[2] / "docs" / "scanner-maturity.md"


def _committed_section() -> str:
    text = _DOC.read_text(encoding="utf-8")
    start = text.index(STATUS_BLOCK_BEGIN)
    end = text.index(STATUS_BLOCK_END) + len(STATUS_BLOCK_END)
    return text[start:end]


def test_committed_maturity_block_matches_the_generator() -> None:
    """The one test that keeps the maturity table honest.

    If this fails the committed block has drifted from the registry/ledger. Do
    not edit the assertion — run ``olympus themis maturity --write`` and commit.
    """
    assert _committed_section() == render_status_section()


def test_markers_appear_exactly_once_each() -> None:
    text = _DOC.read_text(encoding="utf-8")
    assert text.count(STATUS_BLOCK_BEGIN) == 1
    assert text.count(STATUS_BLOCK_END) == 1


def test_generated_block_counts_match_the_live_summary() -> None:
    section = render_status_section()
    live = summary()
    for stage in LADDER:
        # Each stage line is "<stage> <count> [names...]"; the count is field 2.
        row = next(line for line in section.splitlines() if line.startswith(stage.value))
        fields = row.split()
        assert fields[0] == stage.value
        assert int(fields[1]) == live[stage.value]


def test_generated_block_lists_every_catalogued_scanner_once() -> None:
    section = render_status_section()
    grouped = names_by_stage()
    listed = [name for names in grouped.values() for name in names]
    # Every registry scanner is placed at exactly one stage.
    assert sorted(listed) == sorted(spec.name for spec in REGISTRY)
    for name in listed:
        assert name in section


def test_names_are_sorted_within_each_stage() -> None:
    for names in names_by_stage().values():
        assert names == sorted(names)


# --- CLI -------------------------------------------------------------------- #


def test_maturity_command_prints_the_section() -> None:
    result = runner.invoke(app, ["themis", "maturity"])
    assert result.exit_code == 0, result.output
    assert STATUS_BLOCK_BEGIN in result.stdout
    assert STATUS_BLOCK_END in result.stdout


def test_maturity_check_passes_when_the_doc_is_current() -> None:
    result = runner.invoke(app, ["themis", "maturity", "--check"])
    assert result.exit_code == 0, result.output
    assert "up to date" in result.output


def test_maturity_write_is_idempotent_on_a_current_doc() -> None:
    before = _DOC.read_text(encoding="utf-8")
    result = runner.invoke(app, ["themis", "maturity", "--write"])
    assert result.exit_code == 0, result.output
    assert _DOC.read_text(encoding="utf-8") == before


def test_maturity_check_fails_on_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    """A changed generator with an unwritten doc is a CI failure, exit 2."""
    monkeypatch.setattr(
        maturity,
        "render_status_section",
        lambda: f"{STATUS_BLOCK_BEGIN}\ndrifted\n{STATUS_BLOCK_END}",
    )
    result = runner.invoke(app, ["themis", "maturity", "--check"])
    assert result.exit_code == int(ExitCode.USAGE)
    assert "stale" in result.output
