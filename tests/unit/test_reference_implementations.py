"""Contracts for independently reviewed external reference implementations."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/parity/reference-implementations.json"
EXPECTED = {
    "0xSteph/pentest-ai-agents",
    "7onez/cti-expert",
    "mukul975/Anthropic-Cybersecurity-Skills",
    "CarterPerez-dev/Cybersecurity-Projects",
    "blacklanternsecurity/bbot",
    "HunxByts/GhostTrack",
}


def test_reference_manifest_is_pinned_complete_and_native() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["schema_name"] == "olympus.reference-implementations"
    assert manifest["schema_version"] == "1.0.0"
    assert manifest["policy"] == "independent-native-implementation"
    entries = manifest["references"]
    assert {entry["repository"] for entry in entries} == EXPECTED
    for entry in entries:
        assert re.fullmatch(r"[a-f0-9]{40}", entry["revision"])
        assert entry["license"]
        assert entry["reviewed_concepts"]
        assert entry["native_mappings"]
        for relative in entry["native_mappings"]:
            path = ROOT / relative
            assert path.is_file()
            assert path.is_relative_to(ROOT / "src/olympus")


def test_restrictive_or_unlicensed_references_are_not_vendored() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    restricted = {
        entry["repository"]
        for entry in manifest["references"]
        if entry["license"] in {"AGPL-3.0-only", "NOASSERTION"}
    }
    assert restricted == {
        "CarterPerez-dev/Cybersecurity-Projects",
        "blacklanternsecurity/bbot",
        "HunxByts/GhostTrack",
    }
    vendor_root = ROOT / "vendor"
    vendor_names: set[str] = set()
    if vendor_root.is_dir():
        vendor_names = {path.name.casefold() for path in vendor_root.iterdir()}
    assert not {"cybersecurity-projects", "bbot", "ghosttrack"} & vendor_names
