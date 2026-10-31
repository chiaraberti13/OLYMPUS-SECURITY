"""Property-based fuzzing of the remaining untrusted-file parsers (SEC-H).

Beyond the scanner adapters and CTI ingest parsers, Olympus loads two further
documents from outside its trust boundary: Metis portable case files
(``load_case_document``) and Apollo detection-rule files (``load_rule``). Both
must map any input to a valid model or a *handled* error (``ValueError`` — which
``SigmaImportError`` and the contract/migration errors subclass — or a Pydantic
``ValidationError``), never an unhandled exception. This suite drives them with
hostile JSON objects and free text (C0/C1 controls, ANSI/OSC, unicode),
completing the parser-fuzz coverage. Nothing network-active runs.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from olympus.apollo.rules import DetectionRule, load_rule
from olympus.metis.models import IntelCaseDocument, load_case_document

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

_free_text = st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x2FFF), max_size=300)


@given(raw=_json_values)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_load_case_document_never_crashes(raw: object) -> None:
    try:
        document = load_case_document(raw)
    except (ValueError, ValidationError):
        return  # the documented hostile-input outcomes
    assert isinstance(document, IntelCaseDocument)


@given(text=_free_text)
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_load_rule_never_crashes(text: str) -> None:
    descriptor, name = tempfile.mkstemp(suffix=".yaml")
    path = Path(name)
    try:
        os.write(descriptor, text.encode("utf-8", "surrogatepass"))
        os.close(descriptor)
        try:
            rule = load_rule(path)
        except (ValueError, ValidationError):
            return  # SigmaImportError / contract / migration errors all subclass ValueError
        assert isinstance(rule, DetectionRule)
    finally:
        path.unlink(missing_ok=True)
