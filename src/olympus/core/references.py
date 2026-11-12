"""Canonical recognition of a *real* evidence reference (ROADMAP ``VAL-2``/``CORR-1``).

Across Olympus, several boundaries must tell an **artifact reference** — a thing
that points at stored, verifiable evidence — apart from incidental free text. A
finding's ``evidence`` entries are usually scanner diagnostics (``tool=sqlmap``,
``service=http``); a retest justification may be any sentence. Neither is proof
that evidence exists. The single, tested definition of "this string names a real
evidence artifact" lives here so every caller agrees and none accepts prose where
a reference is required (the same single-source discipline the contracts follow).

A real reference is either an ``olympus.evidence`` custody id (``EVD-YYYY-NNNNN``,
as minted by :func:`olympus.core.ids.new_id`) or a SHA-256 digest (64 hex
characters). SHA-256 digests are compared case-insensitively and returned folded
to lower-case; a custody id is already in a fixed canonical case.
"""

from __future__ import annotations

import re

#: An ``olympus.evidence`` custody id, e.g. ``EVD-2026-00001``.
_EVIDENCE_ID_RE = re.compile(r"EVD-[0-9]{4}-[0-9]{5}")
#: A SHA-256 digest: 64 hexadecimal characters.
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}")


def evidence_reference(value: str) -> str | None:
    """Return the normalised evidence reference, or ``None`` if ``value`` is not one.

    ``value`` is a real reference only when it is exactly an ``olympus.evidence``
    custody id (``EVD-YYYY-NNNNN``) or a 64-character SHA-256 digest; surrounding
    whitespace is ignored. A digest is returned lower-cased so two spellings of the
    same hash compare equal; anything else — free text, a partial id, an empty
    string — returns ``None``.
    """
    candidate = value.strip()
    if _EVIDENCE_ID_RE.fullmatch(candidate):
        return candidate
    if _SHA256_RE.fullmatch(candidate):
        return candidate.lower()
    return None


def is_evidence_reference(value: str) -> bool:
    """Return ``True`` if ``value`` names a real evidence artifact (custody id/digest)."""
    return evidence_reference(value) is not None
