"""The generated scanner matrix, and the guard that keeps the doc from drifting."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.aegis.registry import implemented
from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.integrations import matrix
from olympus.integrations.scanners import REGISTRY

runner = CliRunner()

_DOC = Path(__file__).resolve().parents[2] / "docs" / "scanner-matrix.md"


def test_committed_matrix_matches_the_generator() -> None:
    """The one test that keeps docs/scanner-matrix.md honest.

    If this fails the committed matrix has drifted from the registry. Do not edit
    the assertion — run ``olympus aegis matrix --write`` and commit the result.
    """
    assert _DOC.read_text(encoding="utf-8") == matrix.render()


def test_render_lists_every_catalogued_scanner() -> None:
    rendered = matrix.render()
    for spec in REGISTRY:
        assert f"| {spec.name} |" in rendered


def test_render_derives_the_native_adapter_column() -> None:
    rendered = matrix.render()
    for name in implemented():
        # Each implemented adapter's row must carry the implemented marker.
        row = next(line for line in rendered.splitlines() if line.startswith(f"| {name} |"))
        assert "✅ implemented" in row


def test_render_marks_a_catalog_only_engine_as_pending() -> None:
    rendered = matrix.render()
    row = next(line for line in rendered.splitlines() if line.startswith("| wpscan |"))
    assert "— pending" in row and "n/a" in row


def test_render_shows_offline_tested_as_parser_only() -> None:
    rendered = matrix.render()
    row = next(line for line in rendered.splitlines() if line.startswith("| testssl |"))
    assert "parser only" in row


def test_totals_count_the_whole_catalogue() -> None:
    rendered = matrix.render()
    total = len(REGISTRY)
    assert f"adapters implemented**: {len(implemented())}/{total}" in rendered
    assert "**Production-ready**: **0/24**" in rendered


def test_api_engines_render_as_api_daemon() -> None:
    rendered = matrix.render()
    for name in ("nessus", "zap", "openvas", "burp", "acunetix"):
        row = next(line for line in rendered.splitlines() if line.startswith(f"| {name} |"))
        assert "`API/daemon`" in row


# --- CLI -------------------------------------------------------------------- #


def test_matrix_command_prints_the_document() -> None:
    result = runner.invoke(app, ["aegis", "matrix"])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("# AEGIS 24-scanner classification")


def test_matrix_check_passes_when_the_doc_is_current() -> None:
    result = runner.invoke(app, ["aegis", "matrix", "--check"])
    assert result.exit_code == 0, result.output
    assert "up to date" in result.output


def test_matrix_write_is_idempotent_on_a_current_doc(tmp_path: Path) -> None:
    """Writing the already-current doc must not change it."""
    before = _DOC.read_text(encoding="utf-8")
    result = runner.invoke(app, ["aegis", "matrix", "--write"])
    assert result.exit_code == 0, result.output
    assert _DOC.read_text(encoding="utf-8") == before


def test_matrix_check_fails_on_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    """A changed generator with an unwritten doc is a CI failure, exit 2."""
    monkeypatch.setattr(matrix, "render", lambda: "# drifted\n")
    result = runner.invoke(app, ["aegis", "matrix", "--check"])
    assert result.exit_code == int(ExitCode.USAGE)
    assert "stale" in result.output
