"""Versioned, machine-readable engine inventory for ``engines list`` (TOOLS-4).

``engines list`` is consumed by operators and automation to see what Olympus
governs, at which pin, with which maturity. Like the doctor and preflight
reports, its ``--format json`` output is a versioned Olympus contract
(``olympus.engine-list``) rather than a bare list, so a consumer can pin
``schema_name``/``schema_version`` and reject an incompatible inventory instead
of guessing. The builder is pure (no I/O beyond loading the shipped manifests)
and is shared by the CLI's table and JSON renderings.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from olympus.core.models import OlympusModel
from olympus.engines.loader import load_all
from olympus.integrations.maturity import record_for
from olympus.integrations.scanners import by_name


class EngineListEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    engine: str
    category: str
    maturity: str
    mandatory: bool
    distribution: str
    pinned_version: str | None
    commit: str | None
    adapter: bool
    in_scanner_image: bool


class EngineListReport(OlympusModel):
    schema_name: Literal["olympus.engine-list"] = "olympus.engine-list"
    schema_version: Literal["1.0.0"] = "1.0.0"
    engines: list[EngineListEntry]


def build_list_report() -> EngineListReport:
    """Build the versioned inventory from the shipped manifests (sorted by name)."""
    manifests = load_all()
    entries = [
        EngineListEntry(
            engine=name,
            category=manifest.engine.category,
            maturity=record_for(name).stage.value,
            mandatory=manifest.engine.mandatory,
            distribution=manifest.engine.distribution,
            pinned_version=manifest.engine.pinned_version,
            commit=manifest.engine.source.commit,
            adapter=manifest.adapter is not None,
            in_scanner_image=bool((spec := by_name(name)) and spec.in_scanner_image),
        )
        for name, manifest in sorted(manifests.items())
    ]
    return EngineListReport(engines=entries)
