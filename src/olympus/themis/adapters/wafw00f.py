"""Real wafw00f adapter: parses wafw00f JSON WAF-detection output."""

from __future__ import annotations

import json

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter, check_json_depth
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput


class Wafw00fAdapter(ScannerAdapter):
    name = "wafw00f"
    binary = "wafw00f"
    version_expected = "2.x"

    #: Array elements the last :meth:`parse` call had to discard (not a detection
    #: object). A ``detected: false`` row is a legitimate "no WAF" result and is
    #: not counted. Per-run state; :meth:`coverage_loss` reports it as partial.
    _skipped_records: int = 0

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
        check_json_depth(text[start:], scanner="wafw00f")
        try:
            entries = json.loads(text[start:])
        except json.JSONDecodeError as exc:
            raise ParseError(f"wafw00f JSON unparseable: {exc}") from exc
        if not isinstance(entries, list):
            # A JSON value that is not the expected array must not read as a clean
            # "no WAF" result: fail closed, like a missing array (TOOLS-4.4).
            raise ParseError("wafw00f JSON root is not an array")
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        skipped = 0
        self._skipped_records = 0
        for entry in entries:
            if not isinstance(entry, dict):
                # not a detection record: unexpected grammar, counted not dropped
                skipped += 1
                continue
            if not entry.get("detected"):
                # a legitimate "no WAF detected" result, not a discarded record
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
        self._skipped_records = skipped
        return findings

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Report discarded array elements: part of the output was not a WAF record."""
        if self._skipped_records:
            return (
                f"{self._skipped_records} wafw00f output record(s) could not be parsed and "
                "were skipped; findings are not exhaustive"
            )
        return None
