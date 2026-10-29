from __future__ import annotations

import asyncio

from textual.widgets import Checkbox, Input, RichLog
from typer.main import get_command

from olympus.cli import app
from olympus.tui.app import CommandScreen, HelpScreen, OlympusTui
from olympus.tui.catalog import TOOLS, commands_for


def test_catalog_exposes_every_tool_and_real_leaf_commands() -> None:
    root = get_command(app)
    inventory = {tool.command: commands_for(root, tool) for tool in TOOLS}
    assert set(inventory) == {
        "themis",
        "apollo",
        "argus",
        "artemis",
        "athena",
        "core",
        "helios",
        "hermes",
        "metis",
        "minerva",
        "proteus",
        "vulcan",
    }
    assert all(inventory.values())
    assert ("argus", "pipeline") in {item.path for item in inventory["argus"]}
    assert ("themis", "jobs", "status") in {item.path for item in inventory["themis"]}
    assert ("metis", "case", "report") in {item.path for item in inventory["metis"]}


def test_tui_keyboard_navigation_and_help() -> None:
    async def scenario() -> None:
        interface = OlympusTui(get_command(app))
        async with interface.run_test(size=(140, 42)) as pilot:
            await pilot.pause()
            assert interface.query_one("#tools").option_count == len(TOOLS)
            assert interface.query_one("#commands").option_count == 16
            await pilot.press("f1")
            await pilot.pause()
            assert isinstance(interface.screen, HelpScreen)
            await pilot.press("escape")
            await pilot.press("tab", "enter")
            await pilot.pause()
            assert isinstance(interface.screen, CommandScreen)
            # The guided form renders typed fields derived from the CLI (UX-A), and
            # the first field is focused instead of a single free-text box.
            assert interface.screen.query("#fields Input, #fields Select, #fields Checkbox")
            assert interface.screen.query_one("#field-username").has_focus
            # The raw-arguments expert path stays available alongside the form.
            assert interface.screen.query_one("#raw-toggle")
            assert interface.screen.query_one("#arguments")
            await pilot.press("escape")
            assert not isinstance(interface.screen, CommandScreen)

    asyncio.run(scenario())


def test_command_screen_executes_real_cli_without_shell() -> None:
    async def scenario() -> None:
        root = get_command(app)
        core = next(tool for tool in TOOLS if tool.command == "core")
        command = commands_for(root, core)[0]
        interface = OlympusTui(root)
        async with interface.run_test(size=(140, 42)) as pilot:
            interface.push_screen(CommandScreen(command))
            await pilot.pause()
            await pilot.press("f5")
            # The command runs a real subprocess (python -m olympus.cli ...), whose
            # cold-interpreter startup can exceed a couple of seconds when the full
            # test suite saturates the CPU. Wait generously for completion so the
            # assertion reflects the command's real outcome, not scheduling latency.
            for _ in range(1500):
                screen = interface.screen
                if isinstance(screen, CommandScreen) and screen.process is None:
                    status = str(screen.query_one("#status-bar").render())
                    if "Completed" in status:
                        break
                await asyncio.sleep(0.02)
            assert "exit code 0" in str(interface.screen.query_one("#status-bar").render())

    asyncio.run(scenario())


def _screen_for(path: tuple[str, ...]) -> CommandScreen:
    root = get_command(app)
    tool = next(t for t in TOOLS if t.command == path[0])
    command = next(c for c in commands_for(root, tool) if c.path == path)
    return CommandScreen(command)


def test_build_argv_turns_typed_values_into_safe_arguments() -> None:
    """A guided form value becomes '--flag value' / bare positional, never a shell string."""
    screen = _screen_for(("vulcan", "report"))
    assert screen.form is not None
    values: dict[str, object] = {"findings": ["a.json", "b.json"], "min_severity": "high"}
    argv = CommandScreen._build_argv(screen.form, values)
    # Repeatable option is emitted once per entry; the choice is a --flag value pair.
    assert argv.count("--findings") == 2
    assert "a.json" in argv and "b.json" in argv
    assert "--min-severity" in argv and "high" in argv
    # No value is ever concatenated into a single shell token.
    assert all(" " not in token for token in argv)


def test_build_argv_emits_boolean_flag_only_when_true() -> None:
    screen = _screen_for(("argus", "accounts"))
    assert screen.form is not None
    on = CommandScreen._build_argv(screen.form, {"i_am_authorized": True})
    off = CommandScreen._build_argv(screen.form, {"i_am_authorized": False})
    assert "--i-am-authorized" in on
    assert "--i-am-authorized" not in off


def test_guided_form_blocks_run_on_invalid_value() -> None:
    """Local validation (UX-A) stops a run before any subprocess when a field is bad."""

    async def scenario() -> None:
        screen = _screen_for(("argus", "accounts"))
        interface = OlympusTui(get_command(app))
        async with interface.run_test(size=(140, 42)) as pilot:
            interface.push_screen(screen)
            await pilot.pause()
            screen.query_one("#field-concurrency", Input).value = "not-a-number"
            await pilot.pause()
            screen.action_run_command()
            await pilot.pause()
            # The run never started: no process, and the output log stayed empty.
            assert screen.process is None
            assert screen.query_one("#output", RichLog).lines == []

    asyncio.run(scenario())


def test_raw_mode_falls_back_to_shlex_arguments() -> None:
    """With raw mode enabled the expert free-text box is split without a shell."""

    async def scenario() -> None:
        screen = _screen_for(("core", "export-schemas"))
        interface = OlympusTui(get_command(app))
        async with interface.run_test(size=(140, 42)) as pilot:
            interface.push_screen(screen)
            await pilot.pause()
            screen.query_one("#raw-toggle", Checkbox).value = True
            screen.query_one("#arguments", Input).value = "--help"
            await pilot.pause()
            screen.action_run_command()
            await pilot.pause()
            log = screen.query_one("#output", RichLog)
            assert any("export-schemas --help" in str(line) for line in log.lines)

    asyncio.run(scenario())
