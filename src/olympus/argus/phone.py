"""Offline phone-number intelligence for Argus.

Parses and validates a phone number entirely offline using the bundled
``phonenumbers`` metadata (Google's libphonenumber): no network, no API key,
no third-party call. This is a real, immediately usable OSINT primitive —
country, region, carrier and line type are derived from the number itself.

Optional *enrichment* (carrier/breach/messaging lookups that DO hit third
parties) lives in :mod:`olympus.argus.enrichment` and is layered on top of
this offline core; it is always opt-in and authorization-gated.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import phonenumbers
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone

from olympus.argus.enrichment import MessagingPresence, PhoneEnrichment
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.models import Asset, Finding

_LINE_TYPE_NAMES: dict[int, str] = {
    PhoneNumberType.FIXED_LINE: "fixed_line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST: "shared_cost",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "uan",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


class PhoneParseError(ValueError):
    """Raised when the input cannot be parsed as a phone number at all."""


@dataclass(frozen=True)
class PhoneReport:
    """Offline metadata derived from a single phone number."""

    raw_input: str
    e164: str | None
    is_valid: bool
    is_possible: bool
    country_code: int | None
    region_code: str | None
    location: str
    carrier_name: str
    line_type: str
    timezones: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the report."""
        return {
            "raw_input": self.raw_input,
            "e164": self.e164,
            "is_valid": self.is_valid,
            "is_possible": self.is_possible,
            "country_code": self.country_code,
            "region_code": self.region_code,
            "location": self.location,
            "carrier": self.carrier_name,
            "line_type": self.line_type,
            "timezones": list(self.timezones),
        }


def analyze_phone(raw_number: str, default_region: str | None = None) -> PhoneReport:
    """Parse ``raw_number`` fully offline and return a :class:`PhoneReport`.

    ``default_region`` (an ISO country code such as ``"US"``) lets national
    numbers without a ``+`` prefix be interpreted; E.164 input needs none.
    """
    try:
        parsed = phonenumbers.parse(raw_number, default_region)
    except phonenumbers.NumberParseException as exc:
        raise PhoneParseError(f"could not parse {raw_number!r}: {exc}") from exc

    is_valid = phonenumbers.is_valid_number(parsed)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    return PhoneReport(
        raw_input=raw_number,
        e164=e164 if is_valid else None,
        is_valid=is_valid,
        is_possible=phonenumbers.is_possible_number(parsed),
        country_code=parsed.country_code,
        region_code=phonenumbers.region_code_for_number(parsed),
        location=geocoder.description_for_number(parsed, "en"),
        carrier_name=carrier.name_for_number(parsed, "en"),
        line_type=_LINE_TYPE_NAMES.get(phonenumbers.number_type(parsed), "unknown"),
        timezones=tuple(timezone.time_zones_for_number(parsed)),
    )


def build_phone_asset(
    report: PhoneReport,
    enrichment: PhoneEnrichment | None = None,
    messaging: MessagingPresence | None = None,
) -> Asset:
    """Convert offline and authorized enrichment data into a shared asset."""
    metadata: dict[str, str] = {
        "line_type": report.line_type,
        "is_valid": str(report.is_valid).lower(),
    }
    if report.e164 is not None:
        metadata["e164"] = report.e164
    if report.country_code is not None:
        metadata["country_code"] = str(report.country_code)
    if report.region_code:
        metadata["region_code"] = report.region_code
    if report.location:
        metadata["location"] = report.location
    if report.carrier_name:
        metadata["carrier"] = report.carrier_name
    if enrichment is not None:
        if enrichment.carrier:
            metadata["enrichment_carrier"] = enrichment.carrier
        if enrichment.line_type:
            metadata["enrichment_line_type"] = enrichment.line_type
        metadata["breach_count"] = str(enrichment.breach_count)
    if messaging is not None:
        metadata["messaging_platform"] = messaging.platform
        metadata["messaging_registered"] = str(messaging.registered).lower()

    return Asset(
        asset_type=AssetType.PHONE,
        hostname=report.e164 or report.raw_input,
        source=Source.ARGUS,
        tags=["argus", "phone-osint"],
        metadata=metadata,
    )


def build_phone_findings(
    asset_id: str,
    report: PhoneReport,
    enrichment: PhoneEnrichment | None = None,
    messaging: MessagingPresence | None = None,
) -> list[Finding]:
    """Derive findings from the offline report plus any opt-in enrichment/messaging data."""
    findings: list[Finding] = []

    if not report.is_valid:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title="Number failed validation",
                description="The supplied value is not a valid dialable number for its region.",
                severity=Severity.INFO,
                evidence=[f"raw_input={report.raw_input!r}", f"is_possible={report.is_possible}"],
            )
        )

    if enrichment is not None and enrichment.breach_count > 0:
        sources = ", ".join(enrichment.breach_sources) or "undisclosed sources"
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title="Number appears in known data breaches",
                description=(
                    f"Third-party breach intelligence reports this number in "
                    f"{enrichment.breach_count} exposure(s)."
                ),
                severity=Severity.HIGH,
                evidence=[f"breach_count={enrichment.breach_count}", f"sources={sources}"],
                remediation=(
                    "Treat the number as compromised for identity purposes; prefer app-based "
                    "MFA over SMS and monitor for SIM-swap/account-takeover attempts."
                ),
            )
        )

    if messaging is not None and messaging.registered:
        details = []
        if messaging.has_public_photo:
            details.append("public profile photo")
        if messaging.is_business:
            details.append("business account")
        detail_text = ", ".join(details) or "account present"
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title=f"Registered on messaging platform ({messaging.platform})",
                description=(
                    "The number is registered on a messaging platform and exposes "
                    f"public metadata ({detail_text}), useful for pretext/social-engineering "
                    "risk assessment during an authorized engagement."
                ),
                severity=Severity.MEDIUM,
                evidence=[f"platform={messaging.platform}", f"exposed={detail_text}"],
                remediation=(
                    "Advise the number's owner to tighten messaging-app privacy settings "
                    "(hide profile photo / last seen / about from unknown contacts)."
                ),
            )
        )

    return findings


@dataclass(frozen=True)
class PhoneIntel:
    """Bundle of everything Argus learned about one number, for export."""

    report: PhoneReport
    asset: Asset
    enrichment: PhoneEnrichment | None = None
    messaging: MessagingPresence | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole bundle."""
        return {
            "report": self.report.to_dict(),
            "asset": json.loads(self.asset.model_dump_json()),
            "enrichment": (
                {
                    "carrier": self.enrichment.carrier,
                    "line_type": self.enrichment.line_type,
                    "breach_count": self.enrichment.breach_count,
                    "breach_sources": list(self.enrichment.breach_sources),
                }
                if self.enrichment is not None
                else None
            ),
            "messaging": (
                {
                    "platform": self.messaging.platform,
                    "registered": self.messaging.registered,
                    "has_public_photo": self.messaging.has_public_photo,
                    "is_business": self.messaging.is_business,
                }
                if self.messaging is not None
                else None
            ),
            "findings": [json.loads(f.model_dump_json()) for f in self.findings],
        }


def export_phone_intel(intel: PhoneIntel, path: Path) -> None:
    """Write a phone-intel bundle (report + asset + findings) as JSON to ``path``."""
    atomic_write_text(
        path, json.dumps(intel.to_dict(), indent=2, sort_keys=True), mode=0o600
    )
