"""Keyboard-first Norton-inspired terminal UI for every Olympus tool."""

from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import click
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Input, Label, OptionList, RichLog, Static
from textual.widgets.option_list import Option

from olympus import __version__
from olympus.tui.catalog import TOOLS, CommandSpec, ToolSpec, commands_for

TOP_BAR = " Menu     Configuration     Operations     Quit!"
STATUS_HINT = " Enter: select/run   Tab: next panel   F1: help   F5: run   Esc: back   Q: quit"


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
            yield Label("Arguments", classes="field-label")
            yield Input(placeholder="Options and arguments for this command", id="arguments")
            with Horizontal(id="actions"):
                yield Button("RUN (F5)", id="run", variant="primary")
                yield Button("CANCEL (Ctrl+C)", id="cancel")
                yield Button("BACK (Esc)", id="back")
            yield RichLog(id="output", wrap=True, markup=False, max_lines=5_000)
        yield Static(" Ready. Enter arguments, then press F5. ", id="status-bar")

    def on_mount(self) -> None:
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
        raw = self.query_one("#arguments", Input).value
        try:
            arguments = shlex.split(raw)
        except ValueError as exc:
            self.notify(f"Invalid arguments: {exc}", severity="error")
            return
        output = self.query_one("#output", RichLog)
        output.clear()
        invoked = " ".join((*self.command.path, *arguments))
        output.write(Text(f"$ olympus {invoked}", style="bold yellow"))
        self._execute(arguments)

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

    def __init__(self, root: click.Group) -> None:
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
