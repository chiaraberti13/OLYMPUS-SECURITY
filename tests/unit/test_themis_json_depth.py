"""Shared JSON-nesting bound for every THEMIS JSON/JSONL adapter (SEC-H).

Scanner output is untrusted input. CPython's ``json`` decoder recurses on
nested containers, so an adversarial report with thousands of nested arrays or
objects can exhaust the interpreter stack or burn CPU before a finding is
produced. ``olympus.themis.base.check_json_depth`` rejects such payloads ahead
of :func:`json.loads`; this suite proves the helper and that every JSON adapter
enforces it, without running any scanner.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from olympus.themis.adapters.dalfox import DalfoxAdapter
from olympus.themis.adapters.httpx import HttpxAdapter
from olympus.themis.adapters.katana import KatanaAdapter
from olympus.themis.adapters.nuclei import NucleiAdapter
from olympus.themis.adapters.testssl import TestsslAdapter
from olympus.themis.adapters.wafw00f import Wafw00fAdapter
from olympus.themis.adapters.wapiti import WapitiAdapter
from olympus.themis.base import MAX_JSON_DEPTH, ParseError, check_json_depth
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_DEEP = MAX_JSON_DEPTH + 1


def _out(stdout: str) -> CommandOutput:
    return CommandOutput(exit_code=0, stdout=stdout, stderr="")


def _req() -> ScanRequest:
    return ScanRequest(scanner="x", target="127.0.0.1", allowed=("127.0.0.1",))


# --- the shared helper ----------------------------------------------------- #


def test_check_json_depth_accepts_shallow_structures() -> None:
    check_json_depth('{"a":[1,[2,[3]]]}', scanner="unit")  # well within the bound


def test_check_json_depth_rejects_excessive_nesting() -> None:
    with pytest.raises(ParseError, match="depth limit"):
        check_json_depth("[" * _DEEP + "]" * _DEEP, scanner="unit")


def test_check_json_depth_ignores_brackets_inside_strings() -> None:
    # A string value full of brackets is not structural nesting.
    check_json_depth('{"name":"' + "[{" * 500 + '"}', scanner="unit")


def test_check_json_depth_honours_a_custom_limit() -> None:
    check_json_depth("[" * 8 + "]" * 8, limit=8, scanner="unit")
    with pytest.raises(ParseError, match="depth limit"):
        check_json_depth("[" * 9 + "]" * 9, limit=8, scanner="unit")


@given(
    value=st.recursive(
        st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=8)),
        lambda children: st.lists(children, max_size=3),
        max_leaves=20,
    )
)
def test_check_json_depth_never_rejects_within_the_bound(value: object) -> None:
    text = json.dumps(value)
    # Hypothesis strategy keeps nesting far below the bound, so this must pass.
    check_json_depth(text, scanner="unit")


# --- every JSON adapter enforces the bound --------------------------------- #

# Each payload reaches the adapter's json.loads call site: object-first for the
# JSONL and object-report parsers, array-first for the array parsers. The deep
# nesting trips the shared guard before Python's decoder ever recurses.
_OBJECT_DEEP = '{"a":' + "[" * _DEEP + "0" + "]" * _DEEP + "}"
_ARRAY_DEEP = "[" * _DEEP + "0" + "]" * _DEEP

_CASES = [
    pytest.param(KatanaAdapter(), _OBJECT_DEEP, id="katana"),
    pytest.param(HttpxAdapter(), _OBJECT_DEEP, id="httpx"),
    pytest.param(NucleiAdapter(), _OBJECT_DEEP, id="nuclei"),
    pytest.param(WapitiAdapter(), _OBJECT_DEEP, id="wapiti"),
    pytest.param(DalfoxAdapter(), _ARRAY_DEEP, id="dalfox"),
    pytest.param(Wafw00fAdapter(), _ARRAY_DEEP, id="wafw00f"),
    pytest.param(TestsslAdapter(), _ARRAY_DEEP, id="testssl"),
]


@pytest.mark.parametrize(("adapter", "payload"), _CASES)
def test_adapter_rejects_excessive_json_nesting(adapter: object, payload: str) -> None:
    with pytest.raises(ParseError, match="depth limit"):
        adapter.parse(_out(payload), "127.0.0.1", _req())  # type: ignore[attr-defined]
