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

#: nikto's end-of-run summary reports how many requests errored. A non-zero count
#: means some probes never completed, so the finding list is not exhaustive.
_ERROR_COUNT = re.compile(r"(\d+)\s+error\(s\)")


class NiktoAdapter(ScannerAdapter):
    name = "nikto"
    binary = "nikto"
    version_expected = "2.x"

    #: Why a parsed run may be incomplete (request errors in the summary, or an
    #: early termination such as a -maxtime cutoff). Per-run state, reset on every
    #: parse; :meth:`coverage_loss` reports it as partial (TOOLS-4.4).
    _coverage_reason: str | None = None

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
        self._coverage_reason = None
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
        # nikto exits 0 even when probes failed or it was cut short by -maxtime, so
        # "no findings" is only trustworthy when the scan actually completed. Request
        # errors in the summary, or an early termination, mean coverage is not
        # exhaustive -> partial, never a silently clean target (TOOLS-4.4).
        reasons: list[str] = []
        errors = _ERROR_COUNT.search(output.stdout)
        if errors is not None and int(errors.group(1)) > 0:
            reasons.append(f"nikto reported {errors.group(1)} request error(s)")
        if "scan terminated" in output.stdout.lower():
            reasons.append("nikto scan terminated early (e.g. -maxtime cutoff)")
        self._coverage_reason = "; ".join(reasons) if reasons else None
        return findings

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Report request errors or an early termination: the scan was not exhaustive."""
        return self._coverage_reason
