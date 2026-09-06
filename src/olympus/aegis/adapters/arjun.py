"""Real arjun adapter: parses arjun's ``[✓] parameter detected`` result lines.

arjun finds *hidden* HTTP parameters — query or body names a server honours but
does not advertise. Like dirsearch and commix it writes its JSON only to a file
(``-o``), so this adapter parses the decisive lines it prints to stdout::

    [✓] parameter detected: id, based on: body length
    [+] Parameters found: id, debug

The per-parameter ``[✓]`` line is the one worth parsing: it carries both the
name and *why* arjun believes it, which the summary ``[+]`` line drops. Two
guards matter. arjun colours its output and streams a ``\\r``-based progress
counter, so the parser strips ANSI first and ignores everything that is not a
detection line. And a hidden parameter is attack surface, not a vulnerability:
each one is reported at INFO, because "the server honours an undocumented
parameter" is a lead for further testing, not a finding in itself.
"""

from __future__ import annotations

import re

from olympus.aegis.base import ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

#: Strips SGR colour escapes so a coloured build parses like a plain one.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

#: "[✓] parameter detected: id, based on: body length"
_DETECTED = re.compile(
    r"parameter detected:\s*(?P<name>[^,]+?)\s*,\s*based on:\s*(?P<reason>.+?)\s*$"
)

#: Valid HTTP parameter names, so a garbled line never becomes a finding.
_NAME = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,128}$")


class ArjunAdapter(ScannerAdapter):
    name = "arjun"
    binary = "arjun"
    version_expected = "2.x"
    install = "pip install arjun"

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.WEB_SERVER,
            hostname=host,
            ip_addresses=list(request.resolved_addresses),
            source=Source.AEGIS,
            tags=["aegis", self.name],
        )

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        target = request.target if request.target_kind == "url" else f"http://{host}"
        return [
            self.binary,
            "-u", target,
            "-t", "10",       # bounded concurrency; the policy owns the deadline
            "--disable-redirects",
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        seen: set[str] = set()

        for raw in output.stdout.splitlines():
            line = _ANSI.sub("", raw).strip()
            match = _DETECTED.search(line)
            if match is None:
                continue
            name = match.group("name").strip()
            if not _NAME.match(name) or name in seen:
                continue
            seen.add(name)
            reason = match.group("reason").strip()

            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.AEGIS,
                    title=f"Hidden HTTP parameter: {name}",
                    description=(
                        f"arjun found that the target honours the undocumented parameter "
                        f"{name!r} ({reason}). It is attack surface worth testing further."
                    ),
                    severity=Severity.INFO,
                    evidence=[f"parameter={name}", f"detected_by={reason}"],
                ),
                request,
            )
        # arjun on a target with no hidden parameters simply prints no detection
        # line; that is a real empty result, so there is nothing to reject here.
        return findings
