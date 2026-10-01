"""Real testssl.sh adapter: parses testssl JSON severity findings (TLS/SSL)."""

from __future__ import annotations

import json

from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARN": Severity.LOW,
}


class TestsslAdapter(ScannerAdapter):
    name = "testssl"
    binary = "testssl.sh"
    version_expected = "3.x"
    install = "git clone https://github.com/drwetter/testssl.sh"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        target = request.target if ":" in request.target else f"{host}:443"
        return [
            self.binary,
            "--quiet",
            "--color",
            "0",
            "--jsonfile",
            "/dev/stdout",
            "--severity",
            "LOW",
            "--fast",
            target,
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        text = output.stdout.strip()
        start = text.find("[")
        if start == -1:
            raise ParseError("testssl produced no JSON output")
        try:
            entries = json.loads(text[start:])
        except json.JSONDecodeError as exc:
            raise ParseError(f"testssl JSON unparseable: {exc}") from exc
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            sev = _SEVERITY.get(str(entry.get("severity", "")).upper())
            if sev is None:
                continue
            fid = str(entry.get("id", "tls"))
            finding_text = str(entry.get("finding", ""))
            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.THEMIS,
                    title=f"TLS issue ({fid}): {finding_text[:100]}",
                    description=finding_text,
                    severity=sev,
                    evidence=[f"id={fid}", f"severity={entry.get('severity')}"],
                ),
                request,
            )
        return findings
