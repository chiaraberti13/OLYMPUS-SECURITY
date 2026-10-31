"""Shared output rendering: pick JSON (machine) or a table (human).

Every command that prints a list of records can offer ``--format json|table``
through these helpers, so the platform reads consistently: JSON to pipe into
other tools, a compact table for a human at a terminal.
"""

from __future__ import annotations

import io
import json
from enum import StrEnum

from rich.console import Console
from rich.table import Table
from rich.text import Text

from olympus.core.execution import safe_terminal_text


class OutputFormat(StrEnum):
    """How a command should render its records."""

    JSON = "json"
    TABLE = "table"


def render_table(columns: list[str], rows: list[list[str]], *, title: str | None = None) -> str:
    """Render ``rows`` as a plain-text table (no ANSI), suitable for any stream."""
    safe_title = Text(safe_terminal_text(title)) if title is not None else None
    table = Table(title=safe_title, show_lines=False)
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        # Text renderables bypass Rich's markup parser; scanner-controlled values
        # such as ``[link=...]`` must remain literal, inert table content.
        table.add_row(*(Text(safe_terminal_text(value)) for value in row))
    buffer = io.StringIO()
    Console(file=buffer, force_terminal=False, no_color=True, width=100).print(table)
    return buffer.getvalue()


def render(
    records: list[dict[str, object]],
    columns: list[str],
    output_format: OutputFormat,
    *,
    title: str | None = None,
) -> str:
    """Render ``records`` as JSON or as a table over the given ``columns``."""
    if output_format is OutputFormat.JSON:
        return json.dumps(records, indent=2, sort_keys=True)
    rows = [[str(record.get(column, "")) for column in columns] for record in records]
    return render_table(columns, rows, title=title)
