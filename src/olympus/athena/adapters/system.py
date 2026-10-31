"""Concrete Clock and IdProvider adapters for Athena."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from olympus.core.ids import new_id


class SystemClock:
    """Production :class:`~olympus.athena.ports.Clock`."""

    def monotonic(self) -> float:
        return time.monotonic()

    def now_iso(self) -> str:
        return datetime.now(UTC).isoformat()


class CoreIdProvider:
    """Production :class:`~olympus.athena.ports.IdProvider` using core ids."""

    def new_id(self, prefix: str) -> str:
        return new_id(prefix)
