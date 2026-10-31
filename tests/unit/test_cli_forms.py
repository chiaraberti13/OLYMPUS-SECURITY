"""Form schemas derived from the Typer command tree (ROADMAP ``UX-A``).

Pin that each command parameter becomes a typed field (text/integer/number/
checkbox/select/path, with required, choices, range and repeatable), that the
same schema is produced for every runnable command (one source for TUI and web),
and that local validation catches missing required fields, bad choices and
out-of-range numbers before anything runs. The TUI consumes these schemas now;
the interface-agnostic shape is also suitable for a future web consumer.
"""

from __future__ import annotations

from olympus.cli_forms import (
    CommandForm,
    FieldKind,
    form_for,
    forms_for_app,
    validate_values,
)


def _field(form: CommandForm, name: str):
    return next(field for field in form.fields if field.name == name)


def test_scan_form_marks_required_text_and_boolean_flag() -> None:
    form = form_for("themis scan")
    assert form.path == "olympus themis scan"
    assert _field(form, "target").kind is FieldKind.TEXT
    assert _field(form, "target").required is True
    flag = _field(form, "i_am_authorized")
    assert flag.kind is FieldKind.BOOLEAN and flag.required is False


def test_enum_options_become_choice_fields() -> None:
    form = form_for("vulcan notify")
    severity = _field(form, "min_severity")
    assert severity.kind is FieldKind.CHOICE
    assert severity.choices == ("info", "low", "medium", "high", "critical")


def test_path_and_ranged_integer_fields() -> None:
    form = form_for("apollo run")
    assert _field(form, "rules").kind is FieldKind.PATH
    ranged = _field(form, "max_input_error_details")
    assert ranged.kind is FieldKind.INTEGER
    assert ranged.minimum == 0 and ranged.maximum == 10000


def test_repeatable_option_is_flagged_multiple() -> None:
    form = form_for("vulcan notify")
    assert _field(form, "findings").multiple is True


def test_defaults_never_embed_a_path_separator_for_determinism() -> None:
    # Computed/absolute path defaults differ per machine; the schema must not
    # embed any path separator (same discipline as the CLI reference), while
    # stable relative filenames and scalars are kept.
    for form in forms_for_app().values():
        for field in form.fields:
            if field.default is not None:
                assert "/" not in field.default and "\\" not in field.default, (
                    f"{form.path} {field.name} default leaks a path: {field.default!r}"
                )


def test_group_path_is_rejected() -> None:
    import pytest

    with pytest.raises(KeyError, match="command group"):
        form_for("vulcan")  # a group, not a runnable command


def test_validation_reports_missing_required() -> None:
    form = form_for("themis scan")
    errors = validate_values(form, {})
    assert any(error.startswith("target: required") for error in errors)


def test_validation_accepts_a_complete_valid_payload() -> None:
    form = form_for("themis scan")
    errors = validate_values(
        form,
        {"target": "lab.internal", "scanner": "nmap", "scope_id": "ENG-2026-00001"},
    )
    assert errors == []


def test_validation_rejects_bad_choice_and_out_of_range() -> None:
    notify = form_for("vulcan notify")
    choice_errors = validate_values(
        notify, {"findings": ["f.json"], "min_severity": "catastrophic"}
    )
    assert any("not one of" in error for error in choice_errors)

    run = form_for("apollo run")
    range_errors = validate_values(run, {"rules": "./r", "max_input_error_details": "99999"})
    assert any("above the maximum" in error for error in range_errors)

    type_errors = validate_values(run, {"rules": "./r", "max_rules": "not-a-number"})
    assert any("not a valid integer" in error for error in type_errors)


def test_every_runnable_command_has_a_form() -> None:
    forms = forms_for_app()
    assert "themis scan" in forms and "apollo run" in forms
    # Deterministic and sorted, and every form carries a non-empty path.
    assert list(forms) == sorted(forms)
    assert all(form.path.startswith("olympus ") for form in forms.values())
