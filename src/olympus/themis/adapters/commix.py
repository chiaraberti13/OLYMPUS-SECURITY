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

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

#: "GET parameter 'addr' appears to be injectable via classic ... technique."
_INJECTABLE = re.compile(
    r"\[info\]\s+(?P<method>GET|POST|\(?\w+\)?)\s+parameter\s+'(?P<param>[^']+)'\s+"
    r"appears to be injectable via\s+(?P<technique>.+?)\s+technique",
    re.IGNORECASE,
)

#: commix (sqlmap-derived) logs fatal connection/access problems at CRITICAL: the
#: target was never actually tested, so zero findings must not read as "no command
#: injection". commix's *other* CRITICAL line — "All tested parameters do not
#: appear to be injectable" — is a legitimate clean outcome and is deliberately
#: NOT matched here, so a safe target is never turned into a false failure
#: (TOOLS-4.4), exactly as for the sqlmap adapter.
_CONNECT_ERROR = re.compile(
    r"\[critical\][^\n]*?("
    r"unable to connect|connection timed out|unable to retrieve|unable to establish|"
    r"does not exist|name or service not known|connection refused|unable to resolve"
    r")",
    re.IGNORECASE,
)


class CommixAdapter(ScannerAdapter):
    name = "commix"
    binary = "commix"
    version_expected = "3.x-4.x"

    #: Why a parsed run may be incomplete (a CRITICAL connection error logged while
    #: some findings were still produced). Per-run state, reset on every parse;
    #: :meth:`coverage_loss` reports it as partial (TOOLS-4.4).
    _coverage_reason: str | None = None

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=AssetType.WEB_SERVER,
            hostname=host,
            ip_addresses=list(request.resolved_addresses),
            source=Source.THEMIS,
            tags=["themis", self.name],
        )

    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        target = request.target if request.target_kind == "url" else f"http://{host}"
        return [
            self.binary,
            "-u",
            target,
            "--batch",  # never prompt; the sandbox has no interactive user
            "--ignore-session",  # a reproducible run, not a resumed one
            "--disable-coloring",
            "--random-agent",
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        self._coverage_reason = None
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
                    source=Source.THEMIS,
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
        # A fatal connection/access error means commix never actually tested the
        # target, so zero findings is NOT "no command injection": with nothing
        # found it is a failed scan, and with findings its coverage is not
        # guaranteed (TOOLS-4.4). "Not injectable" without such an error stays a
        # valid clean outcome.
        if _CONNECT_ERROR.search(output.stdout):
            if not findings:
                raise ParseError(
                    "commix logged a CRITICAL connection/access error and found nothing; "
                    "the target was not conclusively tested, so this is not a clean result"
                )
            self._coverage_reason = (
                "commix logged a CRITICAL connection/access error; scan coverage is not guaranteed"
            )
        return findings

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Report a CRITICAL connection error logged alongside findings (partial run)."""
        return self._coverage_reason
