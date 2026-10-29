"""Keyboard-first Norton-inspired terminal UI for every Olympus tool."""

from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, ClassVar

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Checkbox, Input, Label, OptionList, RichLog, Select, Static
from textual.widgets.option_list import Option

from olympus import __version__
from olympus.cli_forms import CommandForm, FieldKind, FormField, form_for, validate_values
from olympus.tui.catalog import TOOLS, CommandSpec, ToolSpec, commands_for

TOP_BAR = " Menu     Configuration     Operations     Quit!"
STATUS_HINT = " Enter: select/run   Tab: next panel   F1: help   F5: run   Esc: back   Q: quit"

#: The flag every Olympus command uses to gate a real authorized active operation.
#: Its presence in the built argv is the signal for a proportionate confirmation.
AUTHORIZATION_FLAG = "--i-am-authorized"


class HelpScreen(ModalScreen[None]):
    """Compact keyboard reference."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "dismiss", "Close"),
        Binding("f1", "dismiss", "Close"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Static(" OLYMPUS HELP ", classes="dialog-title")
            yield Static(
                "Arrow keys choose a module or command.\n"
                "Tab moves between panels. Enter opens the selected command.\n"
                "Type only that command's arguments; Olympus never invokes a shell.\n"
                "F5 executes, Ctrl+C requests cancellation, Esc returns.\n\n"
                "Network-active operations still require their normal scope and\n"
                "authorization flags. The interface does not bypass policy gates.",
                id="help-copy",
            )
            yield Button("CLOSE", id="close-help", variant="primary")

    @on(Button.Pressed, "#close-help")
    def close_help(self) -> None:
        self.dismiss()


class ConfirmRunScreen(ModalScreen[bool]):
    """Proportionate confirmation before an authorized active operation (UX-B).

    Dismissed with ``True`` to proceed or ``False`` to cancel. It names the exact
    invocation and the target so the operator sees what will run against whom
    before anything starts; passive and local commands never reach this screen.
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("escape", "deny", "Cancel"),
        Binding("enter", "confirm", "Confirm"),
    ]

    def __init__(self, path: tuple[str, ...], arguments: list[str], target: str | None) -> None:
        super().__init__()
        self._invocation = " ".join(("olympus", *path, *arguments))
        self._target = target

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static(" CONFIRM ACTIVE OPERATION ", classes="dialog-title")
            target_line = f"Target:     {self._target}\n" if self._target else ""
            yield Static(
                "This command performs an authorized active operation.\n\n"
                f"{target_line}"
                f"Command:    {self._invocation}\n\n"
                "It runs only against systems you are authorized to test. Proceed?",
                id="confirm-copy",
            )
            with Horizontal(id="confirm-actions"):
                yield Button("CONFIRM (Enter)", id="confirm-run", variant="primary")
                yield Button("CANCEL (Esc)", id="deny-run")

    @on(Button.Pressed, "#confirm-run")
    def confirm_pressed(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#deny-run")
    def deny_pressed(self) -> None:
        self.dismiss(False)

    def action_confirm(self) -> None:
        self.dismiss(True)

    def action_deny(self) -> None:
        self.dismiss(False)


class CommandScreen(Screen[None]):
    """Run one real Olympus command and stream its output."""

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("f1", "help", "Help"),
        Binding("f5", "run_command", "Run", priority=True),
        Binding("ctrl+c", "cancel_command", "Cancel", priority=True),
        Binding("escape", "go_back", "Back"),
    ]

    def __init__(self, command: CommandSpec) -> None:
        super().__init__()
        self.command = command
        self.process: asyncio.subprocess.Process | None = None
        # The guided form is derived from the same interface-agnostic schema the
        # web UI consumes (UX-A); a group or a schema we cannot derive degrades to
        # the raw-arguments box rather than failing to open the screen.
        try:
            self.form: CommandForm | None = form_for(command.path)
        except (KeyError, ValueError):
            self.form = None

    @staticmethod
    def field_widget_id(field: FormField) -> str:
        return f"field-{field.name}"

    def compose(self) -> ComposeResult:
        yield Static(TOP_BAR, id="menu-bar")
        yield Static("F1=Help", id="help-key")
        with Vertical(id="command-frame"):
            yield Static(
                f" Olympus Security {__version__} :: {' '.join(self.command.path).upper()} ",
                id="brand",
            )
            with Vertical(id="command-details", classes="pane"):
                yield Label(self.command.description, id="command-description")
                yield Label(self.command.usage, id="command-usage")
            fields = self.form.fields if self.form is not None else ()
            with VerticalScroll(id="fields", classes="pane"):
                for field in fields:
                    yield from self._compose_field(field)
                if not fields:
                    yield Label(
                        "This command takes no options; press F5 to run.", classes="field-hint"
                    )
            # Raw-arguments mode: a clearly-separated expert path. When enabled the
            # typed fields are ignored and the string is split without a shell.
            yield Checkbox("Raw arguments mode (expert)", id="raw-toggle")
            yield Label("Raw arguments", classes="field-label", id="arguments-label")
            yield Input(placeholder="Options and arguments for this command", id="arguments")
            with Horizontal(id="actions"):
                yield Button("RUN (F5)", id="run", variant="primary")
                yield Button("CANCEL (Ctrl+C)", id="cancel")
                yield Button("BACK (Esc)", id="back")
            yield RichLog(id="output", wrap=True, markup=False, max_lines=5_000)
        yield Static(" Ready. Fill the fields, then press F5. ", id="status-bar")

    def _compose_field(self, field: FormField) -> ComposeResult:
        marker = " *" if field.required else ""
        repeat = " (repeatable: space-separated)" if field.multiple else ""
        label = f"{field.flags[0] if field.flags else field.name}{marker}"
        detail = " ".join(part for part in (field.help, repeat) if part).strip()
        yield Label(f"{label}  {detail}".rstrip(), classes="field-label")
        widget_id = self.field_widget_id(field)
        if field.kind is FieldKind.BOOLEAN:
            yield Checkbox(value=field.default == "True", id=widget_id)
        elif field.kind is FieldKind.CHOICE and field.choices:
            options = [(choice, choice) for choice in field.choices]
            initial = field.default if field.default in field.choices else Select.BLANK
            yield Select(options, value=initial, allow_blank=True, id=widget_id)
        else:
            placeholder = self._placeholder(field)
            yield Input(value=field.default or "", placeholder=placeholder, id=widget_id)

    @staticmethod
    def _placeholder(field: FormField) -> str:
        bits: list[str] = [field.kind.value]
        if field.minimum is not None or field.maximum is not None:
            bits.append(f"range {field.minimum}..{field.maximum}")
        if field.default:
            bits.append(f"default {field.default}")
        return ", ".join(bits)

    def on_mount(self) -> None:
        first = self.query("#fields Input, #fields Select, #fields Checkbox")
        if first:
            first.first().focus()
        else:
            self.query_one("#arguments", Input).focus()

    @on(Input.Submitted, "#arguments")
    def submitted(self) -> None:
        self.action_run_command()

    @on(Button.Pressed, "#run")
    def run_pressed(self) -> None:
        self.action_run_command()

    @on(Button.Pressed, "#cancel")
    def cancel_pressed(self) -> None:
        self.action_cancel_command()

    @on(Button.Pressed, "#back")
    def back_pressed(self) -> None:
        self.action_go_back()

    def action_help(self) -> None:
        self.app.push_screen(HelpScreen())

    def action_go_back(self) -> None:
        if self.process is None:
            self.app.pop_screen()
        else:
            self.notify("Cancel the running command before leaving.", severity="warning")

    def action_run_command(self) -> None:
        if self.process is not None:
            self.notify("A command is already running.", severity="warning")
            return
        arguments = self._prepare_arguments()
        if arguments is None:
            return
        # Proportionate friction (UX-B): an authorized active operation asks for an
        # explicit confirmation naming the target; passive and local commands run
        # straight away. The authorization flag is the product's universal
        # active-operation gate, so it is the honest signal in a generic launcher.
        if AUTHORIZATION_FLAG in arguments:
            self.app.push_screen(
                ConfirmRunScreen(self.command.path, arguments, self._target_hint(arguments)),
                self._resume_after_confirm,
            )
            return
        self._start(arguments)

    def _prepare_arguments(self) -> list[str] | None:
        """Return the argv to run, or ``None`` after notifying about a problem."""
        form = self.form
        raw_mode = form is None or self.query_one("#raw-toggle", Checkbox).value
        if form is None or raw_mode:
            try:
                return shlex.split(self.query_one("#arguments", Input).value)
            except ValueError as exc:
                self.notify(f"Invalid arguments: {exc}", severity="error")
                return None
        values = self._collect_values(form)
        errors = validate_values(form, values)
        if errors:
            self.notify("\n".join(errors[:6]), severity="error", title="Fix these fields")
            return None
        return self._build_argv(form, values)

    def _resume_after_confirm(self, confirmed: bool | None) -> None:
        if confirmed:
            arguments = self._prepare_arguments()
            if arguments is not None:
                self._start(arguments)
        else:
            self.query_one("#status-bar", Static).update(" Operation cancelled before launch. ")

    @staticmethod
    def _target_hint(arguments: list[str]) -> str | None:
        """Best-effort target shown in the confirmation: the value after a target flag."""
        target_flags = ("--target", "--host", "--url", "--domain", "--base-url")
        for index, token in enumerate(arguments[:-1]):
            if token in target_flags:
                return arguments[index + 1]
        return None

    def _start(self, arguments: list[str]) -> None:
        output = self.query_one("#output", RichLog)
        output.clear()
        invoked = " ".join((*self.command.path, *arguments))
        output.write(Text(f"$ olympus {invoked}", style="bold yellow"))
        self._execute(arguments)

    def _collect_values(self, form: CommandForm) -> dict[str, object]:
        """Read the rendered widgets into a {field name: value} map for validation."""
        values: dict[str, object] = {}
        for field in form.fields:
            widget = self.query_one(f"#{self.field_widget_id(field)}")
            if isinstance(widget, Checkbox):
                values[field.name] = widget.value
            elif isinstance(widget, Select):
                selected = widget.value
                if selected is not Select.BLANK:
                    values[field.name] = str(selected)
            elif isinstance(widget, Input):
                text = widget.value.strip()
                if not text:
                    continue
                values[field.name] = text.split() if field.multiple else text
        return values

    @staticmethod
    def _build_argv(form: CommandForm, values: dict[str, object]) -> list[str]:
        """Turn validated field values into a safe argv list (never a shell string).

        Options are emitted as ``--flag value`` (a boolean only when true); a
        positional parameter (no leading ``-`` in its flags) is emitted as a bare
        value, in declaration order, so the argv matches what the CLI expects.
        """
        argv: list[str] = []
        for field in form.fields:
            if field.name not in values:
                continue
            value = values[field.name]
            flag = next((item for item in field.flags if item.startswith("--")), None)
            if flag is None and field.flags and field.flags[0].startswith("-"):
                flag = field.flags[0]
            if field.kind is FieldKind.BOOLEAN:
                if value is True and flag is not None:
                    argv.append(flag)
                continue
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                if flag is None:  # positional parameter: a bare value, in order
                    argv.append(str(entry))
                else:
                    argv.extend([flag, str(entry)])
        return argv

    def action_cancel_command(self) -> None:
        if self.process is None:
            self.notify("No command is running.")
            return
        self.process.terminate()
        self.query_one("#status-bar", Static).update(" Cancellation requested… ")

    @work(exclusive=True, group="olympus-command")
    async def _execute(self, arguments: list[str]) -> None:
        status_bar = self.query_one("#status-bar", Static)
        output = self.query_one("#output", RichLog)
        status_bar.update(" Running… Ctrl+C cancels the process. ")
        argv = [sys.executable, "-m", "olympus.cli", *self.command.path, *arguments]
        try:
            self.process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=Path.cwd(),
                env=os.environ.copy(),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stream = self.process.stdout
            if stream is None:
                raise RuntimeError("subprocess output stream is unavailable")
            while line := await stream.readline():
                output.write(line.decode("utf-8", "replace").rstrip("\n"))
            return_code = await self.process.wait()
            style = "green" if return_code == 0 else "red"
            output.write(Text(f"Process exited with code {return_code}.", style=f"bold {style}"))
            status_bar.update(f" Completed with exit code {return_code}. ")
        except (OSError, subprocess.SubprocessError) as exc:
            output.write(Text(f"Unable to start command: {exc}", style="bold red"))
            status_bar.update(" Execution failed to start. ")
        finally:
            self.process = None


class OlympusTui(App[None]):
    """Unified interface over the complete Click/Typer command tree."""

    TITLE = "Olympus Security"
    SUB_TITLE = "Professional Security Operations Console"
    CSS_PATH = "olympus.tcss"
    ENABLE_COMMAND_PALETTE = False
    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("f1", "help", "Help"),
        Binding("f10", "focus_tools", "Menu"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, root: Any) -> None:
        # A Click/Typer command group (duck-typed: used only for its ``commands``
        # mapping). Typed ``Any`` because Typer's vendored ``TyperGroup`` does not
        # subclass the stdlib ``click.Group``.
        super().__init__()
        self.root_command = root
        self.current_tool = TOOLS[0]
        self.current_commands: tuple[CommandSpec, ...] = ()

    def compose(self) -> ComposeResult:
        yield Static(TOP_BAR, id="menu-bar")
        yield Static("F1=Help", id="help-key")
        with Vertical(id="workspace"):
            yield Static(f" Olympus Security {__version__} ", id="brand")
            with Horizontal(id="browser"):
                with Vertical(id="tools-pane", classes="pane"):
                    yield Static("Tools", classes="pane-title")
                    yield OptionList(
                        *(
                            Option(f"{tool.title:<10} {tool.category}", id=tool.command)
                            for tool in TOOLS
                        ),
                        id="tools",
                    )
                with Vertical(id="commands-pane", classes="pane"):
                    yield Static("Commands", classes="pane-title")
                    yield OptionList(id="commands")
                with Vertical(id="description-pane", classes="pane"):
                    yield Static("Description", classes="pane-title")
                    yield Static(id="tool-title")
                    yield Static(id="description")
                    yield Static(id="usage")
        yield Static(STATUS_HINT, id="status-bar")

    def on_mount(self) -> None:
        tools = self.query_one("#tools", OptionList)
        tools.highlighted = 0
        tools.focus()
        self._show_tool(TOOLS[0])

    @on(OptionList.OptionHighlighted, "#tools")
    def tool_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_id is None:
            return
        tool = next(item for item in TOOLS if item.command == event.option_id)
        self._show_tool(tool)

    @on(OptionList.OptionSelected, "#tools")
    def tool_selected(self) -> None:
        commands = self.query_one("#commands", OptionList)
        if commands.option_count:
            commands.highlighted = 0
            commands.focus()

    @on(OptionList.OptionHighlighted, "#commands")
    def command_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option_id is None:
            return
        index = int(event.option_id.removeprefix("command-"))
        self._show_command(self.current_commands[index])

    @on(OptionList.OptionSelected, "#commands")
    def command_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_id is None:
            return
        index = int(event.option_id.removeprefix("command-"))
        self.push_screen(CommandScreen(self.current_commands[index]))

    def _show_tool(self, tool: ToolSpec) -> None:
        self.current_tool = tool
        self.current_commands = commands_for(self.root_command, tool)
        commands = self.query_one("#commands", OptionList)
        commands.clear_options()
        commands.add_options(
            [
                Option(command.title, id=f"command-{index}")
                for index, command in enumerate(self.current_commands)
            ]
        )
        self.query_one("#tool-title", Static).update(
            Text(f"{tool.title}  [{tool.category}]", style="bold yellow")
        )
        self.query_one("#description", Static).update(tool.description)
        self.query_one("#usage", Static).update(
            f"{len(self.current_commands)} executable command(s).\n\n"
            "Select a command to inspect its exact usage."
        )
        if self.current_commands:
            commands.highlighted = 0

    def _show_command(self, command: CommandSpec) -> None:
        self.query_one("#tool-title", Static).update(
            Text(" ".join(command.path).upper(), style="bold yellow")
        )
        self.query_one("#description", Static).update(command.description)
        self.query_one("#usage", Static).update(
            f"\n{command.usage}\n\nEnter opens the execution view."
        )

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_focus_tools(self) -> None:
        self.query_one("#tools", OptionList).focus()
