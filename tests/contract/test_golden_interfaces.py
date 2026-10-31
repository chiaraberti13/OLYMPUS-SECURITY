"""Golden tests for stable machine-readable Olympus interfaces."""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.update_contract_goldens import GOLDEN_NAMES, generate_goldens

FIXTURES = Path("tests/fixtures/contracts")


@pytest.fixture(scope="module")
def generated_goldens(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    return generate_goldens(tmp_path_factory.mktemp("contract-goldens"))


@pytest.mark.parametrize("name", GOLDEN_NAMES)
def test_public_interface_matches_golden(name: str, generated_goldens: dict[str, str]) -> None:
    expected = (FIXTURES / name).read_text(encoding="utf-8")
    assert generated_goldens[name] == expected, (
        f"public contract changed: {name}; review compatibility and run "
        "`python scripts/update_contract_goldens.py` deliberately"
    )
