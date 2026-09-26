"""Contract tests keeping the ARGUS parity manifest aligned with the public CLI."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from typer.main import get_command

from olympus.argus.cli import app

MANIFEST = Path("docs/parity/argus.json")
SHA1 = re.compile(r"^[0-9a-f]{40}$")


def _manifest() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(MANIFEST.read_text(encoding="utf-8")))


def test_manifest_has_pinned_provenance_and_no_external_cli_dependency() -> None:
    manifest = _manifest()
    source = manifest["source"]

    assert manifest["schema_version"] == 1
    assert SHA1.fullmatch(source["implementation_revision"])
    assert SHA1.fullmatch(source["implementation_tree"])
    assert source["license"] == "MIT"
    assert Path(source["license_file"]).is_file()
    assert manifest["runtime_external_cli_dependencies"] == []


def test_manifest_covers_every_command_and_option() -> None:
    # Typer returns a Click group at runtime. Keep the contract test typed as
    # ``Any`` so strict mypy does not require Click's optional type metadata or
    # a direct Click dependency merely to introspect Typer's generated command.
    click_app = cast(Any, get_command(app))
    manifest_commands = _manifest()["commands"]

    assert set(manifest_commands) == set(click_app.commands)
    for name, command in click_app.commands.items():
        actual_options = {
            option
            for parameter in command.params
            for option in getattr(parameter, "opts", (parameter.name,))
            if option != "--help"
        }
        assert set(manifest_commands[name]["options"]) == actual_options
        assert manifest_commands[name]["capabilities"]
        for relative_path in manifest_commands[name]["mapping"]:
            assert (Path("src/olympus/argus") / relative_path).is_file()


def test_manifest_security_and_integration_entries_are_complete() -> None:
    manifest = _manifest()

    assert len(manifest["security_contract"]) >= 7
    assert manifest["external_integrations"]
    assert all(
        set(item) == {"name", "purpose", "mandatory"} for item in manifest["external_integrations"]
    )
    assert all(item["name"] and item["purpose"] for item in manifest["external_integrations"])
    assert manifest["data_models"]
    assert manifest["outputs"]
