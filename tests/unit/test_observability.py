"""Observability must be useful without turning telemetry into a data leak."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from olympus.core.observability import (
    Correlation,
    InMemoryExporter,
    Observability,
    ObservabilityConfigurationError,
    observability_from_config,
)
from olympus.themis.api import ApiSettings, create_app


class _ScrapeExporter(InMemoryExporter):
    def prometheus_payload(self) -> tuple[bytes, str] | None:
        return b"olympus_test 1\n", "text/plain; version=0.0.4"


def test_metrics_are_bounded_and_never_contain_correlation_or_secrets() -> None:
    exporter = InMemoryExporter()
    telemetry = Observability(exporter, cardinality_limit=8)

    for index in range(10):
        telemetry.job_finished(
            "athena",
            f"adapter-{index}",
            "succeeded",
            0.25,
        )
    telemetry.artifact_created("athena", "evidence", "json")
    with telemetry.span(
        "athena.evidence",
        Correlation(
            assessment_id="ASM-1",
            job_id="JOB-1",
            evidence_id="EVD-1",
            report_id="secret/../../report",
        ),
    ):
        pass

    metric_text = repr(exporter.records)
    assert "ASM-1" not in metric_text
    assert "JOB-1" not in metric_text
    assert "EVD-1" not in metric_text
    assert "secret" not in metric_text
    adapters = {
        dict(record.attributes)["adapter"]
        for record in exporter.records
        if record.name == "olympus_jobs_total"
    }
    assert "other" in adapters
    assert len(adapters) == 9  # eight admitted values plus the overflow bucket

    span_attributes = dict(exporter.spans[-1][1])
    assert span_attributes == {
        "olympus.assessment.id": "ASM-1",
        "olympus.evidence.id": "EVD-1",
        "olympus.job.id": "JOB-1",
    }


def test_observability_configuration_is_explicit_and_fail_closed() -> None:
    assert isinstance(observability_from_config({}), Observability)
    with pytest.raises(ObservabilityConfigurationError, match="backend"):
        observability_from_config({"observability": {"backend": "unknown"}})
    with pytest.raises(ValueError, match="cardinality_limit"):
        observability_from_config({"observability": {"cardinality_limit": 7}})


def test_authenticated_metrics_endpoint_and_templated_api_route(tmp_path: Path) -> None:
    scopes = tmp_path / "scopes"
    scopes.mkdir()
    (scopes / "engagement.json").write_text(
        json.dumps(
            {
                "schema_name": "olympus.aegis-scope",
                "schema_version": "1.0.0",
                "allowed_hosts": ["127.0.0.1"],
                "allowed_cidrs": ["127.0.0.0/8"],
            }
        ),
        encoding="utf-8",
    )
    exporter = _ScrapeExporter()
    telemetry = Observability(exporter)
    api_key = "a" * 32
    client = TestClient(
        create_app(
            ApiSettings(
                database=tmp_path / "jobs.sqlite3",
                scope_directory=scopes,
                api_key=api_key,
            ),
            telemetry,
        )
    )

    assert client.get("/metrics").status_code == 401
    scraped = client.get("/metrics", headers={"X-Olympus-API-Key": api_key})
    assert scraped.status_code == 200
    assert scraped.text == "olympus_test 1\n"

    request_records = [
        record for record in exporter.records if record.name == "olympus_api_requests_total"
    ]
    assert request_records
    labels = dict(request_records[-1].attributes)
    assert labels["route"] == "metrics"
    assert api_key not in repr(exporter.records)
