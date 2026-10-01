"""Real whatweb adapter: parses whatweb's ``[plugin[detail]]`` fingerprint line."""

from __future__ import annotations

import re

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

# Plugins worth surfacing as technology-disclosure findings.
_INTERESTING = {
    "HTTPServer",
    "X-Powered-By",
    "PHP",
    "Apache",
    "nginx",
    "WordPress",
    "Microsoft-IIS",
    "OpenSSL",
    "Server",
}
_PLUGIN = re.compile(r"([A-Za-z0-9\-]+)(?:\[([^\]]*)\])?")


class WhatwebAdapter(ScannerAdapter):
    name = "whatweb"
    binary = "whatweb"
    version_expected = "0.5.x"
    install = "apt-get install whatweb (requires a working Ruby environment)"

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
        return [self.binary, "--color=never", "--quiet", url]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        line = next((ln for ln in output.stdout.splitlines() if "[" in ln), "")
        if not line:
            raise ParseError("whatweb produced no fingerprint line")
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for name, detail in _PLUGIN.findall(line):
            if name not in _INTERESTING or not detail:
                continue
            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.THEMIS,
                    title=f"Technology disclosed: {name} ({detail})",
                    description=f"whatweb fingerprinted {name} = {detail}.",
                    severity=Severity.INFO,
                    evidence=[f"{name}={detail}"],
                ),
                request,
            )
        return findings
