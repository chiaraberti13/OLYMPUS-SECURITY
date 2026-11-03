"""Backward compatibility of ``olympus.themis-result`` when ``partial`` is added.

The pilot (TOOLS-4) needs a live result to say "the engine ran but covered less than
requested". The contract change is deliberately the smallest one that can carry it:

* a result that is **not** partial is emitted exactly as before - schema ``1.2.0``
  with no new keys - so every existing reader (``extra="forbid"`` included) keeps
  working;
* only a **partial** result is emitted as ``1.3.0`` with ``partial`` and
  ``partial_reason``; new readers accept both versions.

``themis-result-1.2.0.json`` is a document produced by the code *before* this change.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from olympus.themis.jobs import JobState, classify_result
from olympus.themis.model import ScanResult, ThemisResultDocument
from olympus.themis.outcome import OutcomeKind, from_mapping, from_result, summarize
from olympus.themis.runner import TerminationCause, TerminationReport
from olympus.themis.states import ExecutionState
from olympus.vulcan.provenance import _load_result

pytestmark = pytest.mark.contract

FIXTURE = Path(__file__).parents[1] / "fixtures" / "contracts" / "themis-result-1.2.0.json"
COMPLETED = TerminationReport(cause=TerminationCause.COMPLETED, exit_code=0)


def _live(**extra: object) -> ScanResult:
    return ScanResult(
        scanner="nuclei",
        state=ExecutionState.LIVE,
        target="http://127.0.0.1:8099",
        resolved_addresses=("127.0.0.1",),
        version="Nuclei Engine Version: v3.11.1",
        exit_code=0,
        termination=COMPLETED,
        duration_seconds=0.123,
        **extra,  # type: ignore[arg-type]
    )


def _partial() -> ScanResult:
    return _live(partial=True, partial_reason="2 output records could not be parsed")


def test_a_document_written_before_the_change_still_validates_unchanged() -> None:
    text = FIXTURE.read_text(encoding="utf-8")
    document = ThemisResultDocument.model_validate_json(text)
    assert document.schema_version == "1.2.0"
    assert document.partial is False and document.partial_reason is None
    assert document.model_dump(mode="json") == json.loads(text)  # no new keys leak out


def test_a_non_partial_result_is_still_emitted_as_1_2_0_with_no_new_keys() -> None:
    emitted = _live().to_dict()
    assert emitted == json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert "partial" not in emitted and "partial_reason" not in emitted
    assert emitted["schema_version"] == "1.2.0"


def test_a_partial_result_is_emitted_as_1_3_0_and_round_trips() -> None:
    emitted = _partial().to_dict()
    assert emitted["schema_version"] == "1.3.0"
    assert emitted["partial"] is True
    assert emitted["partial_reason"] == "2 output records could not be parsed"
    again = ThemisResultDocument.model_validate(emitted)
    assert again.partial is True and again.model_dump(mode="json") == emitted


def test_the_strict_old_reader_contract_holds_for_every_non_partial_document() -> None:
    old_keys = set(json.loads(FIXTURE.read_text(encoding="utf-8")))
    assert set(_live().to_dict()) == old_keys  # an old extra="forbid" reader sees nothing new


def test_1_2_0_must_not_carry_partial_and_unknown_versions_are_rejected() -> None:
    base = json.loads(FIXTURE.read_text(encoding="utf-8"))
    with pytest.raises(ValidationError, match=r"1\.2\.0"):
        ThemisResultDocument.model_validate({**base, "partial": True, "partial_reason": "x"})
    with pytest.raises(ValidationError):
        ThemisResultDocument.model_validate({**base, "schema_version": "1.4.0"})


def test_partial_needs_a_live_state_and_a_reason() -> None:
    base = {**_partial().to_dict()}
    with pytest.raises(ValidationError, match="reason"):
        ThemisResultDocument.model_validate({**base, "partial_reason": None})
    with pytest.raises(ValidationError, match="live"):
        ThemisResultDocument.model_validate(
            {**base, "state": "failed", "real_execution": False, "error": "x"}
        )
    with pytest.raises(ValidationError, match="requires partial"):
        ThemisResultDocument.model_validate({**base, "partial": False})


def test_vulcan_provenance_reads_both_versions(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    old.write_text(FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    new = tmp_path / "new.json"
    new.write_text(json.dumps(_partial().to_dict()), encoding="utf-8")
    assert _load_result(old).partial is False
    assert _load_result(new).partial is True


def test_a_partial_live_result_is_a_partial_outcome_and_a_partial_job() -> None:
    result = _partial()
    assert from_result(result).kind is OutcomeKind.PARTIAL
    assert from_result(result).trustworthy_empty is False
    assert from_mapping(result.to_dict()).kind is OutcomeKind.PARTIAL
    assert from_mapping(json.loads(FIXTURE.read_text(encoding="utf-8"))).kind is OutcomeKind.CLEAN
    assert summarize(state=ExecutionState.LIVE, finding_count=0, partial=True).kind is (
        OutcomeKind.PARTIAL
    )
    assert classify_result(result) == (JobState.PARTIAL, "2 output records could not be parsed")
    assert classify_result(_live()) == (JobState.SUCCEEDED, None)
