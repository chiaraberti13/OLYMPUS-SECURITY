"""Compatibility and identity tests for versioned shared contracts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from olympus.core.contracts import (
    ContractCompatibilityError,
    ContractVersion,
    validate_contract_header,
)
from olympus.core.enums import Source
from olympus.core.models import Observation, ScanJob, SecurityReport


def test_semver_parser_is_strict() -> None:
    assert ContractVersion.parse("1.2.3") == ContractVersion(1, 2, 3)
    for invalid in (1, "1", "1.0", "01.0.0", "v1.0.0"):
        with pytest.raises(ContractCompatibilityError):
            ContractVersion.parse(invalid)


def test_header_accepts_older_minor_and_patch_but_rejects_newer_minor() -> None:
    document = {"schema_name": "olympus.test", "schema_version": "1.1.99"}
    assert (
        validate_contract_header(document, schema_name="olympus.test", supported_version="1.2.0")
        is document
    )

    with pytest.raises(ContractCompatibilityError, match="unsupported"):
        validate_contract_header(
            {**document, "schema_version": "1.3.0"},
            schema_name="olympus.test",
            supported_version="1.2.0",
        )


@pytest.mark.parametrize(
    "document",
    [
        {"schema_name": "wrong", "schema_version": "1.0.0"},
        {"schema_name": "olympus.test", "schema_version": "2.0.0"},
        {"schema_name": "olympus.test", "schema_version": 1},
    ],
)
def test_header_rejects_wrong_identity_major_or_non_semver(document: object) -> None:
    with pytest.raises(ContractCompatibilityError):
        validate_contract_header(document, schema_name="olympus.test")


def test_shared_contracts_are_self_describing_and_strict() -> None:
    observation = Observation(
        observation_type="tcp.open-port",
        source=Source.HELIOS,
        attributes={"host": "192.0.2.1", "port": "443"},
    )
    job = ScanJob(
        job_id="JOB-1",
        assessment_id="ASM-1",
        adapter="helios",
        target_kind="ip",
        target_value="192.0.2.1",
    )
    report = SecurityReport(
        engagement="ENG-1",
        summary={
            "assets": 0,
            "findings": 0,
            "alerts": 0,
            "severity_breakdown": {},
        },
    )

    assert observation.schema_name == "olympus.observation"
    assert job.schema_name == "olympus.scan-job"
    assert report.schema_name == "olympus.security-report"
    assert {observation.schema_version, job.schema_version, report.schema_version} == {"1.0.0"}

    with pytest.raises(ValidationError):
        ScanJob.model_validate({**job.model_dump(), "schema_name": "olympus.not-a-job"})
    with pytest.raises(ValidationError):
        Observation.model_validate({**observation.model_dump(), "schema_version": "2.0.0"})
