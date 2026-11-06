"""Real sqlmap adapter: parses sqlmap text output for injectable parameters."""

from __future__ import annotations

import re

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

_VULN = re.compile(
    r"parameter '([^']+)'.*(is vulnerable|is injectable|appears to be injectable)", re.I
)

#: sqlmap logs fatal connection/access problems at CRITICAL: the target was never
#: actually tested, so zero findings must not read as "no SQL injection". The
#: *other* CRITICAL line sqlmap emits — "all tested parameters do not appear to be
#: injectable" — is a legitimate clean outcome and is deliberately NOT matched
#: here, so a safe target is never turned into a false failure (TOOLS-4.4).
_CONNECT_ERROR = re.compile(
    r"\[CRITICAL\][^\n]*?("
    r"unable to connect|connection timed out|unable to retrieve|unable to establish|"
    r"does not exist|name or service not known|connection refused|unable to resolve"
    r")",
    re.I,
)


class SqlmapAdapter(ScannerAdapter):
    name = "sqlmap"
    binary = "sqlmap"
    version_expected = "1.x"

    #: Why a parsed run may be incomplete (a CRITICAL connection error logged while
    #: some findings were still produced). Per-run state, reset on every parse;
    #: :meth:`coverage_loss` reports it as partial (TOOLS-4.4).
    _coverage_reason: str | None = None

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
        self._coverage_reason = None
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
        # A fatal connection/access error means sqlmap never actually tested the
        # target, so zero findings is NOT "no SQL injection": with nothing found it
        # is a failed scan, and with findings its coverage is not guaranteed
        # (TOOLS-4.4). "No injectable parameter" without such an error stays a valid
        # clean outcome (LIVE).
        if _CONNECT_ERROR.search(output.stdout):
            if not findings:
                raise ParseError(
                    "sqlmap logged a CRITICAL connection/access error and found nothing; "
                    "the target was not conclusively tested, so this is not a clean result"
                )
            self._coverage_reason = (
                "sqlmap logged a CRITICAL connection/access error; scan coverage is not guaranteed"
            )
        return findings

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Report a CRITICAL connection error logged alongside findings (partial run)."""
        return self._coverage_reason
