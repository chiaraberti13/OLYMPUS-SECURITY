"""MAC-address analysis for Argus: offline classification + opt-in vendor lookup.

The offline core validates and normalizes a MAC address and reads the two
administration bits of the first octet — whether the address is locally
administered (often a randomized/virtual NIC) and whether it is a multicast
address — entirely with the standard library. Optional vendor identification
resolves the 24-bit OUI against the public ``macvendors.com`` registry through
the shared injected :class:`~olympus.core.http.HttpClient`, so tests stay
offline. No key is required and the lookup concerns a hardware registry, not a
person or a target host.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.http import HttpClient, HttpRequestError
from olympus.core.models import Asset, Finding

_MACVENDORS_URL = "https://api.macvendors.com/{oui}"
_HEX_ONLY = re.compile(r"[^0-9A-Fa-f]")


class MacParseError(ValueError):
    """Raised when the input is not a valid 48-bit MAC address."""


def _hex_only(mac: str) -> str:
    return _HEX_ONLY.sub("", mac).upper()


def is_valid_mac(mac: str) -> bool:
    """Return ``True`` if ``mac`` normalizes to exactly 12 hexadecimal digits."""
    return len(_hex_only(mac)) == 12


@dataclass(frozen=True)
class MacReport:
    """Offline classification of a single MAC address."""

    mac: str
    oui: str
    locally_administered: bool
    multicast: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the report."""
        return {
            "mac": self.mac,
            "oui": self.oui,
            "locally_administered": self.locally_administered,
            "multicast": self.multicast,
        }


def analyze_mac(raw_mac: str) -> MacReport:
    """Validate and classify ``raw_mac`` entirely offline."""
    if not is_valid_mac(raw_mac):
        raise MacParseError(f"not a valid MAC address: {raw_mac!r}")
    digits = _hex_only(raw_mac)
    mac = ":".join(digits[i : i + 2] for i in range(0, 12, 2))
    oui = ":".join(digits[i : i + 2] for i in range(0, 6, 2))
    first_octet = int(digits[0:2], 16)
    # Bit 1 of the first octet marks a locally administered address; bit 0
    # marks a multicast (group) address. Both are read purely from the value.
    return MacReport(
        mac=mac,
        oui=oui,
        locally_administered=bool(first_octet & 0b10),
        multicast=bool(first_octet & 0b01),
    )


def lookup_vendor(report: MacReport, http: HttpClient) -> str | None:
    """Resolve the OUI to a registered vendor name, or ``None`` if unknown."""
    oui = report.oui.replace(":", "")
    try:
        response = http.get(_MACVENDORS_URL.format(oui=oui))
    except HttpRequestError:
        return None
    if response.status_code != 200:
        return None
    vendor = response.body.strip()
    return vendor or None


def build_mac_asset(report: MacReport, vendor: str | None = None) -> Asset:
    """Convert a :class:`MacReport` (+ optional vendor) into a ``core.Asset``."""
    metadata: dict[str, str] = {
        "oui": report.oui,
        "locally_administered": str(report.locally_administered).lower(),
        "multicast": str(report.multicast).lower(),
    }
    if vendor:
        metadata["vendor"] = vendor
    return Asset(
        asset_type=AssetType.OTHER,
        hostname=report.mac,
        source=Source.ARGUS,
        tags=["argus", "mac-lookup"],
        metadata=metadata,
    )


def build_mac_findings(asset_id: str, report: MacReport) -> list[Finding]:
    """Derive an informational finding when the address is locally administered."""
    findings: list[Finding] = []
    if report.locally_administered:
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.ARGUS,
                title="Locally administered MAC address",
                description=(
                    "The address is locally administered rather than assigned from a vendor "
                    "OUI block. This commonly indicates MAC randomization or a virtual "
                    "interface, so vendor attribution is unreliable."
                ),
                severity=Severity.INFO,
                evidence=[f"mac={report.mac}", "locally_administered=true"],
            )
        )
    return findings


@dataclass(frozen=True)
class MacIntel:
    """Bundle of everything Argus learned about one MAC address, for export."""

    report: MacReport
    asset: Asset
    vendor: str | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole bundle."""
        return {
            "report": self.report.to_dict(),
            "vendor": self.vendor,
            "asset": json.loads(self.asset.model_dump_json()),
            "findings": [json.loads(f.model_dump_json()) for f in self.findings],
        }


def export_mac_intel(intel: MacIntel, path: Path) -> None:
    """Write a MAC-intel bundle (report + asset + findings) as JSON to ``path``."""
    atomic_write_text(
        path, json.dumps(intel.to_dict(), indent=2, sort_keys=True), mode=0o600
    )
