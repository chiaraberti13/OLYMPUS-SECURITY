"""Property-based fuzzing of every native THEMIS scanner-output parser (SEC-H).

Scanner stdout is attacker-influenced: banners, titles, hostnames and tool
reports are shaped by the target. A parser must therefore treat any byte
sequence as hostile and, whatever it receives, either return a list of
``Finding`` objects or raise a *handled* parse error (``ParseError`` /
``ValueError``) that :meth:`ScannerAdapter.run` turns into a clean FAILED state.
An unhandled exception (``KeyError``, ``TypeError``, ``AttributeError``,
``RecursionError`` …) would instead crash the job, so this suite asserts that
invariant across hostile JSON, JSONL and free-text output. It never executes a
scanner — only the pure parsing layer runs.

The adapter list is taken from the registry, so a newly registered scanner is
fuzzed automatically without editing this file.
"""

from __future__ import annotations

import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from olympus.core.models import Finding
from olympus.themis.base import ParseError
from olympus.themis.model import ScanRequest
from olympus.themis.registry import get_adapter, implemented
from olympus.themis.runner import CommandOutput

_ADAPTERS = implemented()


def _req() -> ScanRequest:
    return ScanRequest(scanner="x", target="127.0.0.1", allowed=("127.0.0.1",))


# Arbitrary JSON values, including deliberately wrong-typed roots and nesting.
_json_values = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(max_size=24),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=16), children, max_size=4),
    ),
    max_leaves=18,
)

# Free text spanning control characters, ANSI/OSC bytes and assorted unicode.
_free_text = st.text(
    alphabet=st.characters(min_codepoint=0, max_codepoint=0x2FFF),
    max_size=400,
)


@st.composite
def _scanner_output(draw: st.DrawFn) -> str:
    """Produce one hostile stdout blob: JSON, JSONL or raw text."""
    shape = draw(st.sampled_from(("json", "jsonl", "text")))
    if shape == "text":
        return draw(_free_text)
    if shape == "jsonl":
        rows = draw(st.lists(_json_values, min_size=1, max_size=5))
        return "\n".join(json.dumps(row) for row in rows)
    return json.dumps(draw(_json_values))


@pytest.mark.parametrize("name", _ADAPTERS)
@given(stdout=_scanner_output())
@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_parser_never_crashes_on_hostile_output(name: str, stdout: str) -> None:
    adapter = get_adapter(name)
    output = CommandOutput(exit_code=0, stdout=stdout, stderr="")
    try:
        findings = adapter.parse(output, "127.0.0.1", _req())
    except (ParseError, ValueError):
        return  # a handled parse failure is the documented, acceptable outcome
    assert isinstance(findings, list)
    assert all(isinstance(item, Finding) for item in findings)


def test_registry_exposes_every_adapter_to_the_fuzzer() -> None:
    """Guard against the parametrization silently collapsing to an empty set."""
    assert len(_ADAPTERS) >= 15
    for name in _ADAPTERS:
        assert hasattr(get_adapter(name), "parse")
