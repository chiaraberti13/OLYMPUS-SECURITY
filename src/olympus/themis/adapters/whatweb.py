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
        # whatweb prints one fingerprint line per target, and a redirect (301 -> 200)
        # produces several. Reading only the first line would drop the fingerprint of
        # the final page and could read as "no technology" when the target actually
        # discloses plenty. Every fingerprint line is parsed, and identical
        # disclosures are de-duplicated so a plugin repeated across lines (e.g. the
        # server banner on both the redirect and the final page) is reported once
        # (TOOLS-4.4: complete coverage, never a silently clean read).
        lines = [ln for ln in output.stdout.splitlines() if "[" in ln]
        if not lines:
            raise ParseError("whatweb produced no fingerprint line")
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for line in lines:
            for name, detail in _PLUGIN.findall(line):
                if name not in _INTERESTING or not detail or (name, detail) in seen:
                    continue
                seen.add((name, detail))
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
