from __future__ import annotations

import asyncio

from typer.main import get_command

from olympus.cli import app
from olympus.tui.app import CommandScreen, HelpScreen, OlympusTui
from olympus.tui.catalog import TOOLS, commands_for


def test_catalog_exposes_every_tool_and_real_leaf_commands() -> None:
    root = get_command(app)
    inventory = {tool.command: commands_for(root, tool) for tool in TOOLS}
    assert set(inventory) == {
        "aegis",
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
    assert ("aegis", "jobs", "status") in {item.path for item in inventory["aegis"]}
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
            assert interface.screen.query_one("#arguments").has_focus
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
            for _ in range(100):
                screen = interface.screen
                if isinstance(screen, CommandScreen) and screen.process is None:
                    status = str(screen.query_one("#status-bar").render())
                    if "Completed" in status:
                        break
                await asyncio.sleep(0.02)
            assert "exit code 0" in str(interface.screen.query_one("#status-bar").render())

    asyncio.run(scenario())
