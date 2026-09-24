"""Tool and command catalogue used by the Olympus terminal interface."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import click


@dataclass(frozen=True)
class ToolSpec:
    command: str
    title: str
    category: str
    description: str


@dataclass(frozen=True)
class CommandSpec:
    path: tuple[str, ...]
    title: str
    description: str
    usage: str


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("argus", "ARGUS", "RECON", "OSINT, asset discovery and passive reconnaissance."),
    ToolSpec("athena", "ATHENA", "ASSESS", "Assessment planning, orchestration and lifecycle."),
    ToolSpec("helios", "HELIOS", "ASSESS", "Scoped network attack-surface mapping."),
    ToolSpec("artemis", "ARTEMIS", "ASSESS", "Authorized web-application assessment."),
    ToolSpec("aegis", "AEGIS", "ENGINES", "Specialist-engine readiness, jobs and execution."),
    ToolSpec("hermes", "HERMES", "DEFEND", "Secret and sensitive-data scanning with SARIF."),
    ToolSpec("apollo", "APOLLO", "DEFEND", "Detection rules over normalized security events."),
    ToolSpec("minerva", "MINERVA", "RESPOND", "Incident triage and chain of custody."),
    ToolSpec("vulcan", "VULCAN", "REPORT", "Finding aggregation, ranking and reporting."),
    ToolSpec("metis", "METIS", "INTEL", "CTI cases, IOC correlation and engagement plans."),
    ToolSpec("proteus", "PROTEUS", "EXERCISE", "Authorized social-engineering campaign modelling."),
    ToolSpec("core", "CORE", "PLATFORM", "Shared, versioned data-contract utilities."),
)


def commands_for(root: click.Group, tool: ToolSpec) -> tuple[CommandSpec, ...]:
    """Return every executable leaf below one Olympus tool."""
    command = root.commands.get(tool.command)
    if command is None:
        return ()
    return tuple(_walk(command, (tool.command,)))


def _walk(command: click.Command, path: tuple[str, ...]) -> Iterator[CommandSpec]:
    children: dict[str, click.Command] | None = getattr(command, "commands", None)
    if children:
        for name, child in sorted(children.items()):
            if child.hidden:
                continue
            yield from _walk(child, (*path, name))
        return
    context = click.Context(command, info_name=" ".join(path))
    usage = command.get_usage(context).strip()
    description = command.help or command.short_help or "No description available."
    yield CommandSpec(
        path=path,
        title=" / ".join(path[1:]) if len(path) > 1 else path[0],
        description=" ".join(description.split()),
        usage=usage,
    )
