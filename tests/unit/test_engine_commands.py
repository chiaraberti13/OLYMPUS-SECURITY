"""The command→engine requirement map (``required_for_commands``) is real and fail-closed.

Covers TOOLS-4.1: a manifest may require an engine *for a command*, but only for a
command that (a) exists in the Olympus CLI and (b) is one the preflight actually
honours. Without this, a free-form identifier could name a command that does not
exist, leaving the engine required for nothing and silently unchecked on the path
that needs it (fail-open on a governance path).
"""

from __future__ import annotations

import re

import pytest

from olympus.cli import app
from olympus.engines.commands import (
    COMMAND_IDS,
    THEMIS_RUN,
    UnknownCommandError,
    is_known_command,
    require_known,
)
from olympus.engines.doctor import Environment
from olympus.engines.preflight import (
    PreflightVerdict,
    preflight,
    preflight_for_command,
    required_engines,
)
from olympus.engines.schema import EngineManifest

pytestmark = pytest.mark.unit

_DOTTED = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")


def _cli_command_ids() -> set[str]:
    """Every registered CLI command as a dotted ``group.subcommand`` id."""
    ids: set[str] = set()

    def walk(typer_app: object, prefix: str) -> None:
        for command in typer_app.registered_commands:  # type: ignore[attr-defined]
            name = command.name or (command.callback.__name__ if command.callback else "")
            ids.add(prefix + name)
        for group in typer_app.registered_groups:  # type: ignore[attr-defined]
            walk(group.typer_instance, prefix + (group.name or "") + ".")

    walk(app, "")
    return ids


def test_vocabulary_is_non_empty_and_well_formed() -> None:
    assert COMMAND_IDS, "the command vocabulary must name at least one command"
    for command_id in COMMAND_IDS:
        assert _DOTTED.fullmatch(command_id), f"{command_id!r} is not a dotted group.command id"
    assert THEMIS_RUN in COMMAND_IDS


def test_every_command_id_is_a_real_cli_command() -> None:
    # The map cannot drift from the product: a vocabulary id that no longer names a
    # registered command fails here, so a renamed/removed command is caught.
    registered = _cli_command_ids()
    missing = sorted(COMMAND_IDS - registered)
    assert not missing, f"command ids with no matching CLI command: {missing}"


def test_require_known_rejects_an_unknown_command() -> None:
    assert require_known(THEMIS_RUN) == THEMIS_RUN
    assert is_known_command(THEMIS_RUN) and not is_known_command("themis.rnu")
    with pytest.raises(UnknownCommandError, match=r"unknown command 'themis\.rnu'"):
        require_known("themis.rnu")


def _synthetic_manifest(required_for: list[str]) -> EngineManifest:
    """A minimal governed engine that is required only for the given command(s)."""
    from olympus.engines.loader import parse_manifest

    extra = f"required_for_commands = {required_for!r}".replace("'", '"')
    toml = f"""
[engine]
name = "demo"
category = "web"
upstream = "https://github.com/example/demo"
language = "Go"
license = "MIT"
distribution = "go"
pinned_version = "v1.2.3"
update_policy = "minor"
presence_probe = ["demo", "-version"]
capability = "web.scan"
{extra}
[engine.source]
module = "github.com/example/demo/cmd/demo"
[adapter]
entrypoint = "olympus.themis.adapters.nuclei:NucleiAdapter"
timeout_seconds = 600
resource_profile = "network-heavy"
"""
    return parse_manifest(toml)


def test_required_engines_demands_an_engine_only_for_its_command() -> None:
    manifests = {"demo": _synthetic_manifest([THEMIS_RUN])}
    # No command running → the command-scoped engine is not required.
    assert required_engines(manifests, named=()) == ()
    # The command running → it is required, without the caller naming it.
    assert required_engines(manifests, named=(), commands=(THEMIS_RUN,)) == ("demo",)
    # An unrelated command (not this engine's) → still not required.
    assert required_engines(manifests, named=(), commands=("other.command",)) == ()


def _env_missing_everything() -> Environment:
    """An Environment whose host inspection finds nothing installed (offline, no I/O)."""
    return Environment(
        which=lambda _name: None,
        probe=lambda _argv: (127, ""),
        git_head=lambda _d: None,
    )


def test_preflight_for_command_rejects_an_unknown_command() -> None:
    with pytest.raises(UnknownCommandError):
        preflight_for_command(_env_missing_everything(), "themis.rnu")


def test_preflight_for_command_blocks_when_a_commands_engine_is_absent() -> None:
    # themis.run pulls in the mandatory engines (nmap/nuclei/httpx); with nothing
    # installed the governed command preflight must block, fail-closed.
    verdict = preflight_for_command(_env_missing_everything(), THEMIS_RUN)
    assert isinstance(verdict, PreflightVerdict)
    assert not verdict.ok
    assert set(verdict.required) >= {"nmap", "nuclei", "httpx"}


def test_preflight_accepts_a_commands_sequence() -> None:
    verdict = preflight(_env_missing_everything(), commands=(THEMIS_RUN,))
    assert not verdict.ok  # mandatory engines are absent in this synthetic environment
