"""Mutation fuzzing of scanner parsers seeded from the real captured corpus (SEC-H).

The hostile-input fuzzer in ``test_themis_parser_fuzz.py`` generates output from
scratch. This suite complements it with the "initial corpus from real fixtures"
the roadmap calls for: it starts from the genuine scanner output captured under
``tests/fixtures/themis/live/`` and applies byte-level mutations (truncation,
control/ANSI insertion, slice deletion, line duplication, single-character
replacement). Starting from valid output drives the mutations deep into the
parser's real code paths, and the invariant is the same — a list of ``Finding``
or a handled ``ParseError``/``ValueError``, never an unhandled crash. No scanner
runs; only the parser and the fixture files on disk are used.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from olympus.core.models import Finding
from olympus.themis.adapters.nmap import NmapAdapter
from olympus.themis.adapters.testssl import TestsslAdapter
from olympus.themis.adapters.wafw00f import Wafw00fAdapter
from olympus.themis.adapters.wapiti import WapitiAdapter
from olympus.themis.adapters.whatweb import WhatwebAdapter
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_LIVE = Path(__file__).resolve().parents[1] / "fixtures" / "themis" / "live"

# Each registered adapter that has a committed real-output fixture.
_PAIRS = [
    (NmapAdapter, "nmap_open.xml"),
    (Wafw00fAdapter, "wafw00f.json"),
    (TestsslAdapter, "testssl.json"),
    (WapitiAdapter, "wapiti.json"),
    (WhatwebAdapter, "whatweb.txt"),
]

_control_blob = st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x2FFF), max_size=48)


def _req() -> ScanRequest:
    return ScanRequest(scanner="x", target="127.0.0.1", allowed=("127.0.0.1",))


def _out(text: str) -> CommandOutput:
    return CommandOutput(exit_code=0, stdout=text, stderr="")


def _mutate(base: str, op: str, a: int, b: int, blob: str) -> str:
    if op == "truncate":
        return base[: a % (len(base) + 1)]
    if op == "insert":
        cut = a % (len(base) + 1)
        return base[:cut] + blob + base[cut:]
    if op == "delete":
        lo, hi = sorted((a % (len(base) + 1), b % (len(base) + 1)))
        return base[:lo] + base[hi:]
    if op == "dup":
        lines = base.splitlines()
        if lines:
            i = a % len(lines)
            lines.insert(i, lines[i])
        return "\n".join(lines)
    if op == "replace" and base:
        i = a % len(base)
        return base[:i] + (blob[:1] or "X") + base[i + 1 :]
    return base


def _assert_invariant(adapter: ScannerAdapter, stdout: str) -> None:
    try:
        findings = adapter.parse(_out(stdout), "127.0.0.1", _req())
    except (ParseError, ValueError):
        return
    assert isinstance(findings, list)
    assert all(isinstance(item, Finding) for item in findings)


@pytest.mark.parametrize(("adapter_cls", "fixture"), _PAIRS)
def test_real_fixture_parses_without_unhandled_error(
    adapter_cls: type[ScannerAdapter], fixture: str
) -> None:
    """The unmutated seed itself must satisfy the invariant (sanity anchor)."""
    _assert_invariant(adapter_cls(), (_LIVE / fixture).read_text(encoding="utf-8"))


@pytest.mark.parametrize(("adapter_cls", "fixture"), _PAIRS)
@given(
    op=st.sampled_from(["truncate", "insert", "delete", "dup", "replace"]),
    a=st.integers(min_value=0, max_value=1_000_000),
    b=st.integers(min_value=0, max_value=1_000_000),
    blob=_control_blob,
)
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_mutated_real_fixture_never_crashes(
    adapter_cls: type[ScannerAdapter], fixture: str, op: str, a: int, b: int, blob: str
) -> None:
    base = (_LIVE / fixture).read_text(encoding="utf-8")
    _assert_invariant(adapter_cls(), _mutate(base, op, a, b, blob))
