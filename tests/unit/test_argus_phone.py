"""Unit tests for Argus offline phone intelligence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.argus.enrichment import MessagingPresence, PhoneEnrichment
from olympus.argus.phone import (
    PhoneIntel,
    PhoneParseError,
    analyze_phone,
    build_phone_asset,
    build_phone_findings,
    export_phone_intel,
)
from olympus.core.enums import AssetType, Severity, Source

DEMO_NUMBER = "+16505550123"  # reserved fictional NANP number


def test_analyze_valid_number_offline() -> None:
    report = analyze_phone(DEMO_NUMBER)
    assert report.is_valid is True
    assert report.e164 == DEMO_NUMBER
    assert report.country_code == 1
    assert report.region_code == "US"
    assert report.location == "California"
    assert "America/Los_Angeles" in report.timezones


def test_analyze_national_number_with_region() -> None:
    report = analyze_phone("650 555 0123", default_region="US")
    assert report.is_valid is True
    assert report.e164 == DEMO_NUMBER


def test_analyze_invalid_number_has_no_e164() -> None:
    report = analyze_phone("+1 123", default_region=None)
    assert report.is_valid is False
    assert report.e164 is None


def test_analyze_unparseable_raises() -> None:
    with pytest.raises(PhoneParseError):
        analyze_phone("not-a-number")


def test_report_to_dict_is_serializable() -> None:
    payload = json.dumps(analyze_phone(DEMO_NUMBER).to_dict())
    assert DEMO_NUMBER in payload


def test_build_phone_asset_carries_metadata() -> None:
    asset = build_phone_asset(analyze_phone(DEMO_NUMBER))
    assert asset.asset_type is AssetType.PHONE
    assert asset.source is Source.ARGUS
    assert asset.metadata["e164"] == DEMO_NUMBER
    assert asset.metadata["region_code"] == "US"


def test_findings_flag_invalid_number() -> None:
    report = analyze_phone("+1 123")
    findings = build_phone_findings("AST-2026-00001", report)
    assert any(f.title == "Number failed validation" for f in findings)
    assert findings[0].severity is Severity.INFO


def test_findings_report_breach_and_messaging() -> None:
    report = analyze_phone(DEMO_NUMBER)
    enrichment = PhoneEnrichment(breach_count=2, breach_sources=("Redline", "Raccoon"))
    messaging = MessagingPresence(
        platform="whatsapp", registered=True, has_public_photo=True, is_business=False
    )
    findings = build_phone_findings("AST-2026-00002", report, enrichment, messaging)
    titles = {f.title for f in findings}
    assert "Number appears in known data breaches" in titles
    assert any("Registered on messaging platform" in t for t in titles)
    breach = next(f for f in findings if "breaches" in f.title)
    assert breach.severity is Severity.HIGH
    assert breach.remediation


def test_asset_and_intel_preserve_authorized_enrichment() -> None:
    report = analyze_phone(DEMO_NUMBER)
    enrichment = PhoneEnrichment(
        carrier="Example Mobile",
        line_type="mobile",
        breach_count=1,
        breach_sources=("Example",),
    )
    messaging = MessagingPresence(platform="example", registered=True)
    asset = build_phone_asset(report, enrichment, messaging)
    intel = PhoneIntel(
        report=report,
        asset=asset,
        enrichment=enrichment,
        messaging=messaging,
    )

    payload = intel.to_dict()
    assert asset.metadata["enrichment_carrier"] == "Example Mobile"
    enrichment_payload = payload["enrichment"]
    messaging_payload = payload["messaging"]
    assert isinstance(enrichment_payload, dict)
    assert isinstance(messaging_payload, dict)
    assert enrichment_payload["breach_count"] == 1
    assert messaging_payload["platform"] == "example"


def test_no_findings_for_clean_valid_number() -> None:
    findings = build_phone_findings("AST-2026-00003", analyze_phone(DEMO_NUMBER))
    assert findings == []


def test_export_phone_intel_roundtrips(tmp_path: Path) -> None:
    report = analyze_phone(DEMO_NUMBER)
    asset = build_phone_asset(report)
    intel = PhoneIntel(report=report, asset=asset, findings=[])
    out = tmp_path / "intel.json"
    export_phone_intel(intel, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["asset"]["asset_type"] == "phone"
    assert loaded["report"]["e164"] == DEMO_NUMBER
