"""Real sqlmap adapter: parses sqlmap text output for injectable parameters."""

from __future__ import annotations

import re

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_VULN = re.compile(
    r"parameter '([^']+)'.*(is vulnerable|is injectable|appears to be injectable)", re.I
)


class SqlmapAdapter(ScannerAdapter):
    name = "sqlmap"
    binary = "sqlmap"
    version_expected = "1.x"
    install = "pip install sqlmap (or apt-get install sqlmap)"

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.URL,
            hostname=host,
            source=Source.THEMIS,
            tags=["themis", self.name],
        )

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        # sqlmap needs a URL with a parameter; require a url target.
        url = request.target if "://" in request.target else f"http://{request.target}"
        return [
            self.binary,
            "-u",
            url,
            "--batch",
            "--level=1",
            "--risk=1",
            "--technique=B",
            "--flush-session",
            "--disable-coloring",
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for match in _VULN.finditer(output.stdout):
            param = match.group(1)
            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.THEMIS,
                    title=f"SQL injection in parameter '{param}'",
                    description=f"sqlmap reports GET/POST parameter '{param}' is injectable.",
                    severity=Severity.CRITICAL,
                    evidence=[f"parameter={param}", "tool=sqlmap"],
                    remediation="Use parameterized queries / prepared statements.",
                ),
                request,
            )
        # No injectable parameter found is a valid 'no findings' outcome (LIVE).
        return findings
