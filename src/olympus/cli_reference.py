"""Generate the CLI reference from the Typer command tree (ROADMAP ``DEV-F``).

The per-command help lives once, in the Typer decorators. Hand-writing a CLI
reference beside it guarantees drift. This module introspects the real command
tree (``olympus.cli:app``) and renders a deterministic Markdown reference, so the
documentation is derived from the code and a stale page fails the drift gate
(``scripts/generate_cli_reference.py --check``) instead of misleading a reader.

Pure and offline: it reads the command objects, never executes a command and
never touches the network. The output is deterministic — groups and commands are
sorted by name and options keep their declaration order — so regenerating on an
unchanged tree yields byte-identical output.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

import typer

from olympus.cli import app

#: Markers delimiting the generated block, mirroring the maturity-status block in
#: ``docs/scanner-maturity.md`` so the same drift-gate discipline applies.
BLOCK_BEGIN = "<!-- GENERATED:cli-reference START -->"
BLOCK_END = "<!-- GENERATED:cli-reference END -->"

_DOC_HEADER = """# CLI reference

Every `olympus` command and its options, generated from the Typer command tree
(`olympus.cli:app`) — the single source of truth, so this page cannot drift from
the real CLI. Do not edit the generated block by hand; run
`python scripts/generate_cli_reference.py` (or `--check` in CI) instead.
"""


def _cell(text: str) -> str:
    """Make free text safe for a single Markdown table cell."""
    return " ".join(text.split()).replace("|", "\\|") or "—"


def _default_repr(default: Any) -> str:
    """Render a parameter default for the reference, readable and deterministic."""
    if default is None or default == "" or default == []:
        return "—"
    if isinstance(default, Enum):
        return f"`{default.value}`"
    return f"`{default}`"


def _params(command: Any) -> list[str]:
    """Return the Markdown table rows for one command's options and arguments.

    Uses ``command.params`` (the declared options/arguments, without the
    auto-generated ``--help``) so no execution context is needed.
    """
    rows: list[str] = []
    for parameter in command.params:
        if getattr(parameter, "hidden", False):
            continue
        flags = ", ".join(f"`{opt}`" for opt in parameter.opts)
        kind = "argument" if parameter.param_type_name == "argument" else "option"
        required = "yes" if parameter.required else "no"
        help_text = _cell(getattr(parameter, "help", "") or "")
        rows.append(
            f"| {flags} | {kind} | {required} | {_default_repr(parameter.default)} | {help_text} |"
        )
    return rows


def _walk(command: Any, path: str, out: list[str]) -> None:
    """Depth-first render of a command (or recurse into a group), sorted by name.

    A group is detected by its ``commands`` mapping rather than by
    ``isinstance(click.Group)``: ``TyperGroup`` does not subclass the ``click``
    this module could import (Typer vendors its own click), but it still exposes
    ``commands``.
    """
    subcommands: dict[str, Any] = getattr(command, "commands", {}) or {}
    if subcommands:
        for name in sorted(subcommands):
            child = subcommands[name]
            if getattr(child, "hidden", False):
                continue
            _walk(child, f"{path} {name}", out)
        return

    out.append(f"### `{path}`")
    out.append("")
    out.append(_cell(command.get_short_help_str(limit=200) or ""))
    out.append("")
    rows = _params(command)
    if rows:
        out.append("| Name | Kind | Required | Default | Description |")
        out.append("| --- | --- | --- | --- | --- |")
        out.extend(rows)
        out.append("")


def render_cli_reference() -> str:
    """Return the deterministic Markdown body for every command in the tree."""
    root = typer.main.get_command(app)
    out: list[str] = []
    _walk(root, "olympus", out)
    return "\n".join(out).rstrip() + "\n"


def render_cli_reference_section() -> str:
    """Return the marker-delimited generated block."""
    return f"{BLOCK_BEGIN}\n{render_cli_reference()}{BLOCK_END}\n"


def render_document() -> str:
    """Return the full ``docs/cli-reference.md`` content (header + generated block)."""
    return f"{_DOC_HEADER}\n{render_cli_reference_section()}"


__all__ = [
    "BLOCK_BEGIN",
    "BLOCK_END",
    "render_cli_reference",
    "render_cli_reference_section",
    "render_document",
]
