"""Real nikto adapter: parses nikto's ``+`` finding lines from a web scan."""

from __future__ import annotations

import re

from olympus.core.enums import Severity, Source
from olympus.core.models import Finding
from olympus.themis.base import ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

# Lines that are scan metadata / summary rather than findings.
_METADATA = re.compile(
    r"^(Target IP|Target Hostname|Target Port|Start Time|End Time|"
    r"\d+ items checked|No CGI Directories|.*items? reported on remote host)",
)


class NiktoAdapter(ScannerAdapter):
    name = "nikto"
    binary = "nikto"
    version_expected = "2.x"
    install = "apt-get install nikto"

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        # nikto takes -host and -port; keep it bounded with -maxtime.
        is_https = request.target_kind == "url" and request.target.startswith("https")
        port = "443" if is_https else "80"
        return [
            self.binary,
            "-host",
            host,
            "-port",
            port,
            "-maxtime",
            f"{max(request.timeout_seconds - 5, 30)}s",
            "-nointeractive",
            "-ask",
            "no",
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for raw in output.stdout.splitlines():
            line = raw.strip()
            if not line.startswith("+ "):
                continue
            body = line[2:].strip()
            if _METADATA.match(body) or body.startswith("Server:"):
                continue
            osvdb = re.match(r"^(OSVDB-\d+):", body)
            severity = Severity.MEDIUM if osvdb else Severity.LOW
            title = body if len(body) <= 120 else body[:117] + "..."
            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.THEMIS,
                    title=f"nikto: {title}",
                    description=body,
                    severity=severity,
                    evidence=[f"nikto_line={body}"],
                ),
                request,
            )
        return findings
