"""Legacy artifacts migrate explicitly, deterministically, and fail closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.aegis.application import load_scope
from olympus.aegis.jobs import load_job_document
from olympus.athena.domain.contracts import load_plan
from olympus.cli import app
from olympus.core.migrations import (
    ContractMigrationError,
    migrate_document,
    migration_manifest,
)
from olympus.metis.models import load_case_document
from olympus.minerva.application import load_evidence

FIXTURE = Path("tests/fixtures/migrations/legacy-documents.json")
runner = CliRunner()


@pytest.fixture(scope="module")
def legacy_documents() -> dict[str, dict[str, object]]:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_migration_manifest_covers_every_required_family() -> None:
    names = {entry["schema_name"] for entry in migration_manifest()}
    assert names == {
        "olympus.aegis-job",
        "olympus.aegis-scope",
        "olympus.athena.plan",
        "olympus.evidence",
        "olympus.metis-case",
    }


def test_cli_exposes_the_versioned_migration_manifest() -> None:
    result = runner.invoke(app, ["core", "migrations"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["schema_name"] == "olympus.migration-manifest"
    assert payload["schema_version"] == "1.0.0"
    assert payload["migrations"] == list(migration_manifest())


def test_scope_plan_job_evidence_and_case_migrate_through_real_loaders(
    tmp_path: Path, legacy_documents: dict[str, dict[str, object]]
) -> None:
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps(legacy_documents["aegis_scope"]), encoding="utf-8")
    scope = load_scope(scope_path)
    assert scope.schema_version == "1.0.0"
    assert scope.allowed_domains == ("example.test",)

    plan = load_plan(legacy_documents["athena_plan"])
    assert plan.schema_version == "1.0.0"

    job = load_job_document(legacy_documents["aegis_job"])
    assert job.schema_version == "2.0.0"
    assert job.scope_name == "lab.json"
    assert "scope_path" not in job.model_dump()

    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(json.dumps(legacy_documents["evidence"]), encoding="utf-8")
    evidence = load_evidence(evidence_path)
    assert evidence.schema_version == "1.0.0"

    case = load_case_document(legacy_documents["metis_case"])
    assert case.schema_version == "1.0.0"


def test_current_documents_are_idempotent(legacy_documents: dict[str, dict[str, object]]) -> None:
    migrated = migrate_document(
        legacy_documents["aegis_job"],
        schema_name="olympus.aegis-job",
        current_version="2.0.0",
    )
    assert (
        migrate_document(
            migrated,
            schema_name="olympus.aegis-job",
            current_version="2.0.0",
        )
        == migrated
    )


def test_migrations_refuse_ambiguous_future_and_incomplete_evidence(
    tmp_path: Path, legacy_documents: dict[str, dict[str, object]]
) -> None:
    ambiguous = dict(legacy_documents["aegis_scope"])
    ambiguous["allowed_domains"] = ["other.test"]
    with pytest.raises(ContractMigrationError, match="both allowed"):
        migrate_document(
            ambiguous,
            schema_name="olympus.aegis-scope",
            current_version="1.0.0",
        )

    with pytest.raises(ContractMigrationError, match="no unambiguous migration"):
        migrate_document(
            {"schema_name": "olympus.evidence", "schema_version": "2.0.0"},
            schema_name="olympus.evidence",
            current_version="1.0.0",
        )

    incomplete = dict(legacy_documents["evidence"])
    incomplete.pop("sha256")
    evidence_path = tmp_path / "incomplete-evidence.json"
    evidence_path.write_text(json.dumps(incomplete), encoding="utf-8")
    with pytest.raises(ValueError, match="sha256"):
        load_evidence(evidence_path)


def test_partial_contract_header_is_never_guessed() -> None:
    with pytest.raises(ContractMigrationError, match="partial header"):
        migrate_document(
            {"schema_name": "olympus.metis-case"},
            schema_name="olympus.metis-case",
            current_version="1.0.0",
        )
