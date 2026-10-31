"""Unit tests for the traceable ID generator."""

from __future__ import annotations

import re

import pytest

from olympus.core.ids import IdGenerator, new_id

ID_PATTERN = re.compile(r"^[A-Z]{3}-\d{4}-\d{5}$")


def test_id_format_and_sequence() -> None:
    gen = IdGenerator(year=2026)
    first = gen.next_id("asset")
    second = gen.next_id("asset")
    assert first == "AST-2026-00001"
    assert second == "AST-2026-00002"
    assert ID_PATTERN.match(first)


def test_counters_are_independent_per_kind() -> None:
    gen = IdGenerator(year=2026)
    assert gen.next_id("asset") == "AST-2026-00001"
    assert gen.next_id("finding") == "FND-2026-00001"


def test_unknown_kind_raises() -> None:
    gen = IdGenerator(year=2026)
    with pytest.raises(ValueError, match="unknown id kind"):
        gen.next_id("banana")


def test_module_level_new_id_matches_pattern() -> None:
    assert ID_PATTERN.match(new_id("asset"))
