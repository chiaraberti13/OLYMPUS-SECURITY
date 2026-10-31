"""Unit tests for structured, dual-format validation errors."""

from __future__ import annotations

from pydantic import ValidationError

from olympus.core.errors import format_validation_error
from olympus.core.models import Finding


def _make_error() -> ValidationError:
    try:
        Finding(asset_id="AST-2026-00001", source="helios", title="")  # type: ignore[arg-type]
    except ValidationError as exc:
        return exc
    raise AssertionError("expected a ValidationError")


def test_report_machine_readable() -> None:
    report = format_validation_error(_make_error(), schema="olympus.finding", source="demo.json")
    payload = report.to_dict()
    assert payload["error"] == "schema_validation_error"
    assert payload["schema"] == "olympus.finding"
    assert payload["source"] == "demo.json"
    assert payload["count"] >= 1
    assert isinstance(payload["details"], list)


def test_report_human_readable() -> None:
    report = format_validation_error(_make_error(), schema="olympus.finding")
    text = report.to_human()
    assert "Olympus Schema Validation Error" in text
    assert "invalid field" in text
