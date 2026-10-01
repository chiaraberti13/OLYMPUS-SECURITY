"""Explicit execution states for THEMIS scanner adapters.

These states make the difference between a real scan, a missing dependency, a
failure, an intentionally-off scanner, and an explicitly-requested simulation
unambiguous — so the normal scan path can never present fabricated findings as
real scanner output.
"""

from __future__ import annotations

from enum import StrEnum


class ExecutionState(StrEnum):
    """The outcome kind of one scanner invocation."""

    #: The real scanner binary/API/service was invoked and produced output.
    LIVE = "live"
    #: The required dependency/service is missing; no findings produced.
    UNAVAILABLE = "unavailable"
    #: A real execution was attempted but failed (crash, timeout, bad exit).
    FAILED = "failed"
    #: Live execution is intentionally switched off (no simulation requested).
    DISABLED = "disabled"
    #: Findings are illustrative and were produced ONLY because simulation was
    #: explicitly requested (``--simulate`` / ``AEGIS_SIMULATION_MODE=true``).
    SIMULATION = "simulation"
