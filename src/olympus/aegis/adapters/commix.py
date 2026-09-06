"""Real commix adapter: parses commix's ``[info]`` result lines.

commix has a ``--report-json`` option, but like dirsearch it only ever writes it
to a file, never to stdout. Its console stream, however, states the verdict in a
fixed, release-stable sentence per confirmed technique::

    [21:16:14] [info] GET parameter 'addr' appears to be injectable via classic
                      results-based technique.

and, for a clean parameter::

    [warning] GET parameter 'addr' does not seem to be injectable.
    [critical] All tested parameters do not appear to be injectable.

So this adapter parses those lines. A confirmed OS command injection is about as
serious as a web finding gets, so each distinct injectable parameter/technique
becomes one CRITICAL finding. The technique payloads commix prints are omitted:
they carry the injected commands, and the finding — "parameter X is injectable" —
stands on its own without shipping a working exploit string as evidence.

``--batch`` is mandatory, not a convenience: commix is interactive by default and
would block forever waiting for a human under the sandbox. ``--ignore-session``
keeps a run reproducible instead of resuming a stored one.
"""

from __future__ import annotations

import re

from olympus.aegis.base import ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

#: "GET parameter 'addr' appears to be injectable via classic ... technique."
_INJECTABLE = re.compile(
    r"\[info\]\s+(?P<method>GET|POST|\(?\w+\)?)\s+parameter\s+'(?P<param>[^']+)'\s+"
    r"appears to be injectable via\s+(?P<technique>.+?)\s+technique",
    re.IGNORECASE,
)


class CommixAdapter(ScannerAdapter):
    name = "commix"
    binary = "commix"
    version_expected = "3.x-4.x"
    install = "pip install commix (or clone commixproject/commix)"

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
            "--batch",            # never prompt; the sandbox has no interactive user
            "--ignore-session",   # a reproducible run, not a resumed one
            "--disable-coloring",
            "--random-agent",
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        # commix repeats the injectable line for every confirming request; one
        # finding per (parameter, technique) pair is enough.
        seen: set[tuple[str, str]] = set()

        for line in output.stdout.splitlines():
            match = _INJECTABLE.search(line)
            if match is None:
                continue
            param = match.group("param")
            technique = match.group("technique").strip().lower()
            key = (param, technique)
            if key in seen:
                continue
            seen.add(key)

            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.AEGIS,
                    title=f"OS command injection in parameter {param}",
                    description=(
                        f"commix confirmed parameter {param!r} is injectable via the "
                        f"{technique} technique. This allows execution of operating-system "
                        "commands on the target."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=[
                        f"parameter={param}",
                        f"method={match.group('method')}",
                        f"technique={technique}",
                    ],
                ),
                request,
            )
        return findings
