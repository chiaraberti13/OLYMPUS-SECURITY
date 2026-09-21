"""Real wapiti adapter: parses wapiti's JSON web-vulnerability report.

wapiti writes a JSON report (``-f json``) whose ``vulnerabilities`` map holds one
list of findings per category (Cross Site Scripting, SQL Injection, ...). The
report is emitted to ``/dev/stdout`` so it reaches the adapter through the same
bounded stdout channel every other adapter uses; wapiti's own progress banner is
plain text with no ``{``, so the JSON object is located from the first brace
(the same technique the testssl adapter uses for its preamble).
"""

from __future__ import annotations

import json

from olympus.aegis.base import ParseError, ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

#: wapiti severity levels (1..4) mapped onto the shared Severity scale.
_LEVEL = {4: Severity.CRITICAL, 3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW}


class WapitiAdapter(ScannerAdapter):
    name = "wapiti"
    binary = "wapiti"
    version_expected = "3.x"
    install = "apt-get install wapiti (or pip install wapiti3)"

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.WEB_SERVER,
            hostname=host,
            source=Source.AEGIS,
            tags=["aegis", self.name],
        )

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        url = request.target if request.target_kind == "url" else f"http://{host}"
        # Bounded crawl+attack; JSON to stdout so the runner captures it. The
        # overall scan time is capped from the request's own timeout budget.
        budget = int(max(request.timeout_seconds - 5, 30))
        return [
            self.binary,
            "-u",
            url,
            "-d",
            "1",
            "--max-scan-time",
            str(budget),
            "--flush-session",
            "--no-bugreport",
            "--verify-ssl",
            "0",
            "-v",
            "0",
            "-f",
            "json",
            "-o",
            "/dev/stdout",
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        text = output.stdout
        start = text.find("{")
        if start == -1:
            raise ParseError("wapiti produced no JSON report")
        try:
            report = json.loads(text[start:])
        except json.JSONDecodeError as exc:
            raise ParseError(f"wapiti JSON unparseable: {exc.msg}") from exc
        vulnerabilities = report.get("vulnerabilities")
        if not isinstance(vulnerabilities, dict):
            raise ParseError("wapiti report has no 'vulnerabilities' object")

        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for category, items in vulnerabilities.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, dict):
                    continue
                severity = _LEVEL.get(int(item.get("level", 1) or 1), Severity.INFO)
                method = str(item.get("method", ""))
                path = str(item.get("path", ""))
                parameter = str(item.get("parameter", ""))
                info = str(item.get("info", "")).strip()
                evidence = [f"category={category}", f"location={method} {path}".strip()]
                if parameter:
                    evidence.append(f"parameter={parameter}")
                self.add_finding(
                    findings,
                    Finding(
                        asset_id=asset_id,
                        source=Source.AEGIS,
                        title=f"wapiti: {category}"
                        + (f" in parameter {parameter}" if parameter else ""),
                        description=info or f"wapiti reported a {category} issue.",
                        severity=severity,
                        evidence=evidence,
                        remediation="Validate and encode the affected input; retest.",
                    ),
                    request,
                )
        return findings
