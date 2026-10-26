"""Derive structured input forms from the Typer command tree (ROADMAP ``UX-A``).

A guided TUI or web form must not be a single free-text argument box. This module
turns each command's real Click/Typer parameters into an interface-agnostic form
schema — one typed field per option (text, integer, number, checkbox, select,
path, repeatable) with its required flag, stable default, choices and numeric
range — so the TUI and the web UI render the *same* schema instead of each
re-deriving the CLI's shape. It also validates a set of entered values locally,
before anything runs.

Pure and offline: it reads the command objects and never executes a command. Like
:mod:`olympus.cli_reference`, environment-specific defaults (computed paths) are
omitted so the schema is deterministic across machines.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Any

import typer

from olympus.cli import app


class FieldKind(StrEnum):
    """The control a UI should render for one parameter."""

    TEXT = "text"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    CHOICE = "choice"
    PATH = "path"


@dataclass(frozen=True)
class FormField:
    """One typed input derived from a command parameter."""

    name: str
    flags: tuple[str, ...]
    kind: FieldKind
    required: bool
    multiple: bool = False
    default: str | None = None
    choices: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    help: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "flags": list(self.flags),
            "kind": self.kind.value,
            "required": self.required,
            "multiple": self.multiple,
            "default": self.default,
            "choices": list(self.choices),
            "minimum": self.minimum,
            "maximum": self.maximum,
            "help": self.help,
        }


@dataclass(frozen=True)
class CommandForm:
    """The full input form for one command path (e.g. ``olympus themis scan``)."""

    path: str
    help: str
    fields: tuple[FormField, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "help": self.help,
            "fields": [field.to_dict() for field in self.fields],
        }


def _stable_default(default: Any) -> str | None:
    """Return a machine-independent default, or ``None`` for computed/path values."""
    if default is None or default == "" or default == []:
        return None
    if isinstance(default, bool):
        return str(default)
    if isinstance(default, int | float):
        return str(default)
    if isinstance(default, Enum):
        return str(default.value)
    text = str(default)
    if "/" in text or "\\" in text:  # absolute/relative paths differ per machine
        return None
    return text


def _kind(parameter: Any) -> tuple[FieldKind, tuple[str, ...], float | None, float | None]:
    """Classify a Click parameter into a field kind plus choices/range metadata."""
    if getattr(parameter, "is_flag", False):
        return FieldKind.BOOLEAN, (), None, None
    param_type = parameter.type
    choices = getattr(param_type, "choices", None)
    if choices:
        return FieldKind.CHOICE, tuple(str(choice) for choice in choices), None, None
    type_name = getattr(param_type, "name", "") or ""
    minimum = getattr(param_type, "min", None)
    maximum = getattr(param_type, "max", None)
    if type_name == "path":
        return FieldKind.PATH, (), None, None
    if "int" in type_name:
        return FieldKind.INTEGER, (), minimum, maximum
    if "float" in type_name:
        return FieldKind.NUMBER, (), minimum, maximum
    return FieldKind.TEXT, (), None, None


def _field(parameter: Any) -> FormField:
    kind, choices, minimum, maximum = _kind(parameter)
    return FormField(
        name=parameter.name,
        flags=tuple(parameter.opts),
        kind=kind,
        required=bool(parameter.required),
        multiple=bool(getattr(parameter, "multiple", False)),
        default=_stable_default(parameter.default),
        choices=choices,
        minimum=minimum,
        maximum=maximum,
        help=" ".join((getattr(parameter, "help", "") or "").split()),
    )


def _resolve(root: Any, path: Sequence[str]) -> Any:
    command = root
    for name in path:
        subcommands = getattr(command, "commands", {}) or {}
        if name not in subcommands:
            raise KeyError(f"no such command: {' '.join(path)}")
        command = subcommands[name]
    return command


def form_for(path: str | Sequence[str]) -> CommandForm:
    """Return the input form for one command path (``"themis scan"`` or a sequence)."""
    parts = path.split() if isinstance(path, str) else list(path)
    root = typer.main.get_command(app)
    command = _resolve(root, parts)
    if getattr(command, "commands", None):
        raise KeyError(f"{' '.join(parts)} is a command group, not a runnable command")
    fields = tuple(
        _field(parameter) for parameter in command.params if not getattr(parameter, "hidden", False)
    )
    return CommandForm(
        path="olympus " + " ".join(parts),
        help=" ".join((command.get_short_help_str(limit=200) or "").split()),
        fields=fields,
    )


def _walk(command: Any, path: str, out: dict[str, CommandForm]) -> None:
    subcommands: dict[str, Any] = getattr(command, "commands", {}) or {}
    if subcommands:
        for name in sorted(subcommands):
            child = subcommands[name]
            if getattr(child, "hidden", False):
                continue
            _walk(child, f"{path} {name}", out)
        return
    fields = tuple(
        _field(parameter) for parameter in command.params if not getattr(parameter, "hidden", False)
    )
    out[path] = CommandForm(
        path=f"olympus {path}",
        help=" ".join((command.get_short_help_str(limit=200) or "").split()),
        fields=fields,
    )


def forms_for_app() -> dict[str, CommandForm]:
    """Return every runnable command's form, keyed by its ``group command`` path."""
    root = typer.main.get_command(app)
    commands: dict[str, Any] = getattr(root, "commands", {}) or {}
    out: dict[str, CommandForm] = {}
    for name in sorted(commands):
        _walk(commands[name], name, out)
    return dict(sorted(out.items()))


def validate_values(form: CommandForm, values: Mapping[str, object]) -> list[str]:
    """Validate entered ``values`` against ``form`` locally, before any run.

    Returns a list of human-readable errors (empty means valid): missing required
    fields, values outside a declared choice set, non-numeric input for a numeric
    field, and values outside a declared integer/float range.
    """
    errors: list[str] = []
    for field_ in form.fields:
        present = field_.name in values and values[field_.name] not in (None, "", [])
        if field_.required and not present:
            errors.append(f"{field_.name}: required")
            continue
        if not present:
            continue
        raw = values[field_.name]
        entries = raw if isinstance(raw, list) else [raw]
        for entry in entries:
            errors.extend(_validate_entry(field_, entry))
    return errors


def _validate_entry(field_: FormField, entry: object) -> list[str]:
    errors: list[str] = []
    if field_.kind is FieldKind.CHOICE and str(entry) not in field_.choices:
        errors.append(f"{field_.name}: {entry!r} is not one of {', '.join(field_.choices)}")
    elif field_.kind in (FieldKind.INTEGER, FieldKind.NUMBER):
        try:
            number = int(str(entry)) if field_.kind is FieldKind.INTEGER else float(str(entry))
        except (TypeError, ValueError):
            errors.append(f"{field_.name}: {entry!r} is not a valid {field_.kind.value}")
            return errors
        if field_.minimum is not None and number < field_.minimum:
            errors.append(f"{field_.name}: {number} is below the minimum {field_.minimum}")
        if field_.maximum is not None and number > field_.maximum:
            errors.append(f"{field_.name}: {number} is above the maximum {field_.maximum}")
    return errors


__all__ = [
    "CommandForm",
    "FieldKind",
    "FormField",
    "form_for",
    "forms_for_app",
    "validate_values",
]
