"""Traceable, stable identifier generation (e.g. ``AST-2026-00001``).

Every object that travels across the ecosystem carries an ID with the shape
``PREFIX-YYYY-NNNNN``. The same object keeps the same ID through discovery,
verification, detection, response and reporting.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime

# Map a logical object kind to its stable prefix.
_PREFIXES: dict[str, str] = {
    "asset": "AST",
    "finding": "FND",
    "event": "EVT",
    "alert": "ALT",
    "incident": "INC",
    "risk": "RSK",
    "evidence": "EVD",
    "engagement": "ENG",
    "assessment": "ASM",
    "job": "JOB",
    "observation": "OBS",
    "finding_transition": "FTR",
}


class IdGenerator:
    """Thread-safe, monotonic generator of traceable Olympus IDs.

    A generator is scoped to a single calendar year and keeps an independent
    counter per object kind. It is deterministic given the same call order,
    which makes it easy to test.
    """

    def __init__(self, year: int | None = None) -> None:
        self._year: int = year if year is not None else datetime.now(UTC).year
        self._counters: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def year(self) -> int:
        """Return the calendar year embedded in every generated ID."""
        return self._year

    def next_id(self, kind: str) -> str:
        """Return the next ID for ``kind`` (e.g. ``"asset"`` -> ``AST-2026-00001``)."""
        prefix = _PREFIXES.get(kind)
        if prefix is None:
            allowed = ", ".join(sorted(_PREFIXES))
            raise ValueError(f"unknown id kind {kind!r}; allowed: {allowed}")
        with self._lock:
            counter = self._counters.get(kind, 0) + 1
            self._counters[kind] = counter
        return f"{prefix}-{self._year}-{counter:05d}"


# Process-wide default generator used by the models' default factories.
_default_generator = IdGenerator()


def new_id(kind: str) -> str:
    """Return the next ID for ``kind`` using the process-wide generator."""
    return _default_generator.next_id(kind)
