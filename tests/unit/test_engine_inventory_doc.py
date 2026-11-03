"""``docs/engines/INVENTORY.md`` must match the manifests, the registry and the ledger."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from olympus.engines.inventory import (
    BLOCK_BEGIN,
    BLOCK_END,
    pin_vs_evidence,
    render_inventory_block,
)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "engines" / "INVENTORY.md"


def test_inventory_tables_match_the_repository() -> None:
    document = DOC.read_text(encoding="utf-8")
    start = document.index(BLOCK_BEGIN)
    end = document.index(BLOCK_END) + len(BLOCK_END)
    assert document[start:end] == render_inventory_block(), (
        "docs/engines/INVENTORY.md is stale; run "
        "'python scripts/generate_engine_inventory.py --write'"
    )


def test_generator_script_check_mode_agrees() -> None:
    spec = importlib.util.spec_from_file_location(
        "generate_engine_inventory", ROOT / "scripts" / "generate_engine_inventory.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module.main(["--check"]) == 0


def test_inventory_states_the_promotion_criteria_and_the_api_split() -> None:
    text = DOC.read_text(encoding="utf-8")
    for needle in (
        "Manifest completo",
        "SBOM",
        "Test offline verdi",
        "Test live opzionale",
        "Presence probe",
        "Evidence manifest",
        "prodotto esterno",
    ):
        assert needle in text


@pytest.mark.parametrize(
    ("pinned", "evidence", "verdict"),
    [
        ("v3.11.1", "v3.11.1", "match"),
        ("2.4.2", "2.x", "compatible"),
        ("3.2.4", "3.x", "compatible"),
        ("1.10.11", "1.10.8", "RECONFIRM"),
        ("v7.992", "7.94SVN", "RECONFIRM"),
        ("2.6.1", "2.5", "RECONFIRM"),
        ("0.5", None, "-"),
        (None, "1.x", "RECONFIRM"),
        ("3.0.1", "2.x", "RECONFIRM"),
    ],
)
def test_pin_vs_evidence_verdicts(pinned: str | None, evidence: str | None, verdict: str) -> None:
    assert pin_vs_evidence(pinned, evidence) == verdict
