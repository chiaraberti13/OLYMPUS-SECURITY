"""Real testssl.sh adapter: parses testssl JSON severity findings (TLS/SSL)."""

from __future__ import annotations

import json

from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.themis.base import ParseError, ScannerAdapter, check_json_depth
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARN": Severity.LOW,
}

#: testssl's informational rows for checks that passed or carry context. They are
#: not findings and not errors: expected noise that is ignored, never counted as a
#: discarded record. Any other non-finding level (FATAL, a scan error, an unknown
#: level) is unexpected and must make the run partial (TOOLS-4.4).
_INFORMATIONAL = {"OK", "INFO", "DEBUG"}


class TestsslAdapter(ScannerAdapter):
    name = "testssl"
    binary = "testssl.sh"
    version_expected = "3.x"

    #: Records the last :meth:`parse` call had to discard (a non-object element, or
    #: a non-finding level that is not informational — e.g. FATAL). Per-run state;
    #: :meth:`coverage_loss` reports it as partial (TOOLS-4.4).
    _skipped_records: int = 0

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
        check_json_depth(text[start:], scanner="testssl")
        try:
            entries = json.loads(text[start:])
        except json.JSONDecodeError as exc:
            raise ParseError(f"testssl JSON unparseable: {exc}") from exc
        if not isinstance(entries, list):
            # A JSON value that is not the expected array must not read as a clean
            # TLS result: fail closed, like a missing array (TOOLS-4.4).
            raise ParseError("testssl JSON root is not an array")
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        skipped = 0
        self._skipped_records = 0
        for entry in entries:
            if not isinstance(entry, dict):
                skipped += 1
                continue
            level = str(entry.get("severity", "")).upper()
            sev = _SEVERITY.get(level)
            if sev is None:
                # OK/INFO/DEBUG are passed-check rows: expected noise, ignored.
                # Anything else (FATAL, a scan error, an unknown level) is not a
                # clean non-finding — count it so the run reads as partial.
                if level not in _INFORMATIONAL:
                    skipped += 1
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
        self._skipped_records = skipped
        return findings

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Report discarded rows: a non-object element or a non-informational error level."""
        if self._skipped_records:
            return (
                f"{self._skipped_records} testssl output record(s) could not be parsed and "
                "were skipped; findings are not exhaustive"
            )
        return None
