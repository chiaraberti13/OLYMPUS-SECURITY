"""The CLI reference is generated from the command tree and never drifts (DEV-F).

``docs/cli-reference.md`` is produced by ``olympus.cli_reference.render_document``
from the live Typer tree. These tests pin that the committed doc is current (the
drift gate), that the render is deterministic, and that real commands with their
options actually appear — so the page cannot silently fall behind the CLI.
"""

from __future__ import annotations

from pathlib import Path

from olympus.cli_reference import (
    BLOCK_BEGIN,
    BLOCK_END,
    render_cli_reference,
    render_document,
)

_DOC = Path(__file__).resolve().parents[2] / "docs" / "cli-reference.md"


def test_committed_reference_is_current() -> None:
    assert _DOC.read_text(encoding="utf-8") == render_document(), (
        "docs/cli-reference.md is stale; run "
        "`python scripts/generate_cli_reference.py` to regenerate it."
    )


def test_render_is_deterministic() -> None:
    assert render_document() == render_document()


def test_generated_block_is_marker_delimited() -> None:
    document = render_document()
    assert BLOCK_BEGIN in document and BLOCK_END in document
    assert document.index(BLOCK_BEGIN) < document.index(BLOCK_END)


def test_real_commands_and_options_are_documented() -> None:
    body = render_cli_reference()
    # A command from each of several modules, with a known option, must appear.
    assert "### `olympus vulcan notify`" in body
    assert "`--webhook`" in body
    assert "### `olympus minerva verify`" in body
    assert "### `olympus apollo run`" in body


def test_commands_are_sorted_for_stability() -> None:
    headings = [line for line in render_cli_reference().splitlines() if line.startswith("### ")]
    assert headings == sorted(headings)
