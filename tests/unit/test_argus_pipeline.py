"""Offline tests for the bounded Argus event pipeline."""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus.pipeline import (
    BUILTIN_MODULES,
    EmittedEvent,
    EventPipeline,
    PipelinePreset,
    ReconEvent,
    ReconEventType,
    export_pipeline,
    load_preset,
)
from olympus.cli import app
from olympus.core.execution import AuthorizationRequiredError

runner = CliRunner()


def _preset(**updates: object) -> PipelinePreset:
    payload: dict[str, object] = {
        "name": "fixture",
        "seeds": [{"type": "url", "value": "https://a.b.example.test/x", "tags": []}],
        "modules": ["url-host", "domain-parent"],
        "blacklist": [],
        "max_depth": 4,
        "max_events": 20,
    }
    payload.update(updates)
    return PipelinePreset.model_validate(payload)


def test_builtin_pipeline_recurses_deduplicates_and_tracks_edges() -> None:
    document = EventPipeline(BUILTIN_MODULES).run(_preset())
    values = [event.value for event in document.events]
    assert values == [
        "https://a.b.example.test/x",
        "a.b.example.test",
        "b.example.test",
        "example.test",
    ]
    assert len(document.edges) == 3
    assert document.truncated is False


def test_pipeline_blacklist_and_bounds() -> None:
    blocked = EventPipeline(BUILTIN_MODULES).run(_preset(blacklist=["b.example.test"]))
    assert "b.example.test" not in {event.value for event in blocked.events}
    assert blocked.blocked == ("blacklist:domain:b.example.test",)
    truncated = EventPipeline(BUILTIN_MODULES).run(_preset(max_events=2))
    assert len(truncated.events) == 2 and truncated.truncated is True


@dataclass(frozen=True)
class ActiveModule:
    name: str = "active-fixture"
    consumes: frozenset[ReconEventType] = frozenset({ReconEventType.DOMAIN})
    active: bool = True

    def expand(self, event: ReconEvent) -> tuple[EmittedEvent, ...]:
        return (EmittedEvent(ReconEventType.HOST, f"api.{event.value}"),)


def test_active_modules_require_authorization_and_scope_for_every_pivot() -> None:
    preset = _preset(
        seeds=[{"type": "domain", "value": "example.test", "tags": []}],
        modules=["active-fixture"],
    )
    pipeline = EventPipeline({"active-fixture": ActiveModule()}, scope_gate=lambda event: False)
    with pytest.raises(AuthorizationRequiredError):
        pipeline.run(preset)
    document = pipeline.run(preset, authorized=True)
    assert len(document.events) == 1
    assert document.blocked == ("scope:domain:example.test",)


def test_preset_io_cli_and_private_outputs(tmp_path: Path) -> None:
    source = Path("examples/input/argus-pipeline.json")
    preset = load_preset(source)
    document = EventPipeline(BUILTIN_MODULES).run(preset)
    output = tmp_path / "pipeline.json"
    export_pipeline(document, output)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text())["schema_name"] == "olympus.argus-pipeline"

    cli_output = tmp_path / "cli.json"
    result = runner.invoke(
        app,
        ["argus", "pipeline", "--preset", str(source), "--output", str(cli_output)],
    )
    assert result.exit_code == 0
    assert cli_output.exists()


def test_preset_rejects_unknown_fields_and_symlinks(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "x", "seeds": [], "modules": [], "extra": True}))
    with pytest.raises(ValueError, match="invalid Argus pipeline preset"):
        load_preset(bad)
    link = tmp_path / "link.json"
    link.symlink_to(Path("examples/input/argus-pipeline.json").resolve())
    with pytest.raises(OSError, match="symlink"):
        load_preset(link)
