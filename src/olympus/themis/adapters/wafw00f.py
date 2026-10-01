"""Real wafw00f adapter: parses wafw00f JSON WAF-detection output."""

from __future__ import annotations

import json

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput


class Wafw00fAdapter(ScannerAdapter):
    name = "wafw00f"
    binary = "wafw00f"
    version_expected = "2.x"
    install = "pip install wafw00f"

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.WEB_SERVER,
            hostname=host,
            source=Source.THEMIS,
            tags=["themis", self.name],
        )

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        url = request.target if request.target_kind == "url" else f"http://{host}"
        return [self.binary, "-o", "-", "-f", "json", url]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        text = output.stdout.strip()
        start = text.find("[")
        if start == -1:
            raise ParseError("wafw00f produced no JSON array")
        try:
            entries = json.loads(text[start:])
        except json.JSONDecodeError as exc:
            raise ParseError(f"wafw00f JSON unparseable: {exc}") from exc
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict) or not entry.get("detected"):
                continue
            firewall = str(entry.get("firewall", "unknown"))
            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.THEMIS,
                    title=f"WAF detected: {firewall}",
                    description=f"wafw00f identified a Web Application Firewall ({firewall}).",
                    severity=Severity.INFO,
                    evidence=[f"firewall={firewall}", f"url={entry.get('url')}"],
                ),
                request,
            )
        return findings
