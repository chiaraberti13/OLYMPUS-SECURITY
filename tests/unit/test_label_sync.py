from __future__ import annotations

import json
from pathlib import Path

import pytest
from tools.sync_labels import Label, LabelSyncError, load_manifest, plan_changes


def _manifest(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_repository_manifest_is_valid() -> None:
    labels = load_manifest(Path(".github/labels.json"))

    assert {label.name for label in labels} == {
        "area:security",
        "area:dev",
        "area:ux",
        "area:ops",
        "P0",
        "P1",
        "P2",
        "P3",
        "roadmap",
        "bug",
    }


@pytest.mark.parametrize(
    "payload, message",
    [
        ([], "non-empty JSON array"),
        ([{"name": "P0", "color": "red", "description": "bad"}], "hexadecimal"),
        (
            [
                {"name": "P0", "color": "B60205", "description": "one"},
                {"name": "p0", "color": "B60205", "description": "two"},
            ],
            "duplicate",
        ),
    ],
)
def test_manifest_rejects_ambiguous_or_invalid_entries(
    tmp_path: Path, payload: object, message: str
) -> None:
    path = _manifest(tmp_path / "labels.json", payload)

    with pytest.raises(LabelSyncError, match=message):
        load_manifest(path)


def test_plan_is_minimal_and_never_deletes_unmanaged_labels() -> None:
    desired = (
        Label("roadmap", "5319E7", "Tracks ROADMAP.md"),
        Label("P0", "B60205", "Blocks safe use"),
    )
    existing = (
        Label("ROADMAP", "5319e7", "Tracks ROADMAP.md"),
        Label("P0", "FFFFFF", "old description"),
        Label("keep-me", "000000", "unmanaged"),
    )

    plan = plan_changes(desired, existing)

    assert plan.create == ()
    assert plan.update == (desired[1],)


def test_plan_creates_only_missing_labels() -> None:
    desired = (
        Label("roadmap", "5319E7", "Tracks ROADMAP.md"),
        Label("area:security", "D73A4A", "Security"),
    )

    plan = plan_changes(desired, ())

    assert plan.create == desired
    assert plan.update == ()
