"""Canonical evidence-reference recognition (ROADMAP ``VAL-2``/``CORR-1``).

``core.references.evidence_reference`` is the single place that decides whether a
string names a real evidence artifact — an ``olympus.evidence`` custody id or a
SHA-256 digest — so no boundary accepts prose where a reference is required.
"""

from __future__ import annotations

import pytest

from olympus.core.references import evidence_reference, is_evidence_reference


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("EVD-2026-00001", "EVD-2026-00001"),
        ("  EVD-2026-00001  ", "EVD-2026-00001"),  # surrounding whitespace ignored
        ("A" * 64, "a" * 64),  # SHA-256 folded to lower-case
        ("deadBEEF" * 8, "deadbeef" * 8),
    ],
)
def test_real_references_are_recognised_and_normalised(value: str, expected: str) -> None:
    assert evidence_reference(value) == expected
    assert is_evidence_reference(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "tool=sqlmap",
        "service=http",
        "EVD-123",  # malformed custody id
        "EVD-2026-001",  # too few digits
        "A" * 63,  # too short for a SHA-256
        "A" * 65,  # too long
        "g" * 64,  # non-hex
        "we retested and it is gone",
    ],
)
def test_free_text_and_malformed_values_are_not_references(value: str) -> None:
    assert evidence_reference(value) is None
    assert is_evidence_reference(value) is False
