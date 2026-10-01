"""Unit tests for the core Pydantic models and their strict contract."""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from olympus.core.enums import AssetType, Confidence, Severity, Source
from olympus.core.models import Asset, Finding

ASSET_ID = re.compile(r"^AST-\d{4}-\d{5}$")
FINDING_ID = re.compile(r"^FND-\d{4}-\d{5}$")


def test_asset_autogenerates_traceable_id() -> None:
    asset = Asset(asset_type=AssetType.WEB_SERVER)
    assert ASSET_ID.match(asset.asset_id)
    assert asset.schema_name == "olympus.asset"
    assert asset.schema_version == "1.0.0"


def test_asset_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        Asset(asset_type=AssetType.HOST, not_a_field=True)  # type: ignore[call-arg]


def test_finding_requires_asset_id_and_title() -> None:
    finding = Finding(asset_id="AST-2026-00001", source=Source.HELIOS, title="Open port 22")
    assert FINDING_ID.match(finding.finding_id)
    assert finding.severity is Severity.MEDIUM


def test_finding_rejects_empty_title() -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.HELIOS, title="")


def test_finding_cvss_out_of_range_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.ARTEMIS, title="XSS", cvss=42.0)


def test_finding_json_round_trip() -> None:
    original = Finding(
        asset_id="AST-2026-00001",
        source=Source.ARTEMIS,
        title="Reflected XSS",
        severity=Severity.HIGH,
        cvss=7.4,
    )
    restored = Finding.model_validate_json(original.model_dump_json())
    assert restored == original


# --- WEB-C: structured vulnerability intelligence on Finding ----------------- #


def test_finding_structured_fields_default_empty() -> None:
    """A finding without structured intel keeps the additive fields empty/unset."""
    finding = Finding(asset_id="AST-2026-00001", source=Source.THEMIS, title="x")
    assert finding.cve == []
    assert finding.cwe == []
    assert finding.epss is None
    assert finding.epss_percentile is None
    assert finding.kev is False
    assert finding.confidence is None
    # The schema stays at 1.0.0: the new fields are additive and backward-compatible.
    assert finding.schema_version == "1.0.0"


def test_finding_normalizes_and_validates_cve_cwe() -> None:
    finding = Finding(
        asset_id="AST-2026-00001",
        source=Source.THEMIS,
        title="Log4Shell",
        cve=["cve-2021-44228"],
        cwe=["cwe-502"],
    )
    assert finding.cve == ["CVE-2021-44228"]
    assert finding.cwe == ["CWE-502"]


@pytest.mark.parametrize("bad_cve", ["NOT-A-CVE", "CVE-21-1", "2021-44228"])
def test_finding_rejects_malformed_cve(bad_cve: str) -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.THEMIS, title="x", cve=[bad_cve])


@pytest.mark.parametrize("bad_cwe", ["CWE-", "79", "WEAK-79"])
def test_finding_rejects_malformed_cwe(bad_cwe: str) -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.THEMIS, title="x", cwe=[bad_cwe])


@pytest.mark.parametrize("field", ["epss", "epss_percentile"])
@pytest.mark.parametrize("value", [-0.1, 1.5])
def test_finding_rejects_epss_out_of_range(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        Finding(asset_id="AST-2026-00001", source=Source.THEMIS, title="x", **{field: value})


def test_finding_cves_prefers_structured_field() -> None:
    finding = Finding(
        asset_id="AST-2026-00001",
        source=Source.THEMIS,
        title="mentions CVE-2000-1111 in text",
        cve=["CVE-2021-44228"],
    )
    # The structured field wins; the free-text id is ignored when cve is set.
    assert finding.cves() == ["CVE-2021-44228"]


def test_finding_cves_falls_back_to_free_text() -> None:
    finding = Finding(
        asset_id="AST-2026-00001",
        source=Source.THEMIS,
        title="Log4Shell CVE-2021-44228",
        description="related to cwe-502 deserialization",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"],
    )
    assert finding.cves() == ["CVE-2021-44228", "CVE-2021-45046"]
    assert finding.cwes() == ["CWE-502"]


def test_finding_structured_intel_round_trips() -> None:
    original = Finding(
        asset_id="AST-2026-00001",
        source=Source.THEMIS,
        title="Log4Shell",
        severity=Severity.CRITICAL,
        cvss=10.0,
        cve=["CVE-2021-44228"],
        cwe=["CWE-502"],
        epss=0.97,
        epss_percentile=0.99,
        kev=True,
        confidence=Confidence.HIGH,
    )
    restored = Finding.model_validate_json(original.model_dump_json())
    assert restored == original
    assert restored.confidence is Confidence.HIGH


def test_finding_accepts_legacy_document_without_structured_fields() -> None:
    """A finding persisted before WEB-C still validates (fields default)."""
    legacy = {
        "schema_name": "olympus.finding",
        "schema_version": "1.0.0",
        "finding_id": "FND-2024-00001",
        "asset_id": "AST-2024-00001",
        "source": "helios",
        "title": "Open port 22",
    }
    finding = Finding.model_validate(legacy)
    assert finding.cve == []
    assert finding.kev is False
    assert finding.engagement_id is None


# --- WEB-B slice 2: optional engagement linkage ------------------------------ #


def test_scoped_models_default_engagement_id_to_none() -> None:
    """Every engagement-scoped contract leaves the link unset by default."""
    asset = Asset(asset_type=AssetType.HOST)
    finding = Finding(asset_id="AST-2026-00001", source=Source.THEMIS, title="x")
    assert asset.engagement_id is None
    assert finding.engagement_id is None


def test_engagement_id_is_normalized_to_upper_case() -> None:
    asset = Asset(asset_type=AssetType.HOST, engagement_id="eng-2026-00001")
    assert asset.engagement_id == "ENG-2026-00001"


@pytest.mark.parametrize("bad_id", ["ENG-26-1", "ENGAGEMENT", "ENG-2026-1", "ENG-2026-000001"])
def test_engagement_id_rejects_malformed_values(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        Asset(asset_type=AssetType.HOST, engagement_id=bad_id)


def test_engagement_id_round_trips() -> None:
    original = Finding(
        asset_id="AST-2026-00001",
        source=Source.THEMIS,
        title="x",
        engagement_id="ENG-2026-00042",
    )
    restored = Finding.model_validate_json(original.model_dump_json())
    assert restored == original
    assert restored.engagement_id == "ENG-2026-00042"


def test_scoped_model_accepts_legacy_document_without_engagement_id() -> None:
    """A pre-WEB-B asset (no engagement_id) still validates."""
    legacy = {
        "schema_name": "olympus.asset",
        "schema_version": "1.0.0",
        "asset_id": "AST-2024-00001",
        "asset_type": "host",
    }
    asset = Asset.model_validate(legacy)
    assert asset.engagement_id is None
