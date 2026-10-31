"""Canonical process exit codes shared across every Olympus command.

A single, documented convention so scripts and CI can branch on *why* a
command stopped, not just whether it failed:

===  ==========================================================================
0    success: full coverage, nothing to report
1    a finding/condition the caller may want to act on (e.g. secrets found)
2    usage or input error (bad flag, unreadable/invalid file, malformed scope)
3    blocked: the target is out of the authorized scope (and was logged)
4    refused: an authorization/consent flag was required but not given
5    partial: the run lost coverage; findings (if any) are not exhaustive
6    failed: nothing completed, so the result carries no information
7    cancelled: the run stopped on request before finishing
===  ==========================================================================

Codes 5 and 6 exist so a caller can tell "we looked everywhere and found
nothing" from "we could not look". A run that both produced findings and lost
coverage exits 5, not 1: the findings are still printed, but the run must not
be read as exhaustive. See :mod:`olympus.core.coverage` for how modules derive
that status.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Canonical Olympus CLI exit codes (see module docstring)."""

    OK = 0
    FINDINGS = 1
    USAGE = 2
    OUT_OF_SCOPE = 3
    NOT_AUTHORIZED = 4
    PARTIAL = 5
    FAILED = 6
    CANCELLED = 7


def normalize_exit_code(code: int | None) -> ExitCode:
    """Return a canonical code, mapping unknown external failures to ``FAILED``.

    Legacy Click applications and vendored subprocesses may return arbitrary
    integers. Those values must not leak through the public Olympus CLI because
    callers rely on the stable 0-7 contract.
    """
    candidate = ExitCode.OK if code is None else code
    try:
        return ExitCode(candidate)
    except ValueError:
        return ExitCode.FAILED
