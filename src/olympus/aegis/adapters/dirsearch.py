"""Real dirsearch adapter: parses dirsearch's plain result stream.

**Why the text stream and not the JSON report.** dirsearch can emit JSON, XML,
CSV and more — but only ever *to a file*, chosen with ``-o``. It has no
stdout-JSON mode, and ``-o /dev/stdout`` hangs because the reporter seeks in the
file it opens. Reading a report back would mean giving every adapter a writable
scratch path, a temp-file lifecycle and a cleanup guarantee, for one tool.

So this adapter parses the line stream dirsearch prints with ``-q --no-color``,
which is short, stable across releases, and exactly what the tool is designed to
show a human::

    [09:50:25] 301 -     0B - http://127.0.0.1:8099/admin  ->  /admin/
    [09:50:25] 200 -    64B - http://127.0.0.1:8099/private/.env

A path that exists is only interesting in proportion to what it exposes, so a
reachable path that looks like configuration, a backup or an admin surface is
elevated; a 403 is reported separately, because "forbidden" still proves the
resource is there.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from olympus.aegis.base import ParseError, ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

#: ``[HH:MM:SS] <status> - <size> - <url>`` with an optional ``  ->  <redirect>``.
_RESULT = re.compile(
    r"^\[\d{2}:\d{2}:\d{2}\]\s+"
    r"(?P<status>\d{3})\s+-\s+"
    r"(?P<size>\S+)\s+-\s+"
    r"(?P<url>\S+)"
    r"(?:\s+->\s+(?P<redirect>\S+))?\s*$"
)

#: Paths whose mere existence is a finding, not an inventory entry.
_SENSITIVE_SEGMENTS = (
    ".env",
    ".git",
    ".htpasswd",
    ".svn",
    "admin",
    "backup",
    "config",
    "console",
    "dump",
    "id_rsa",
    "phpinfo",
    "phpmyadmin",
    "wp-config",
)


class DirsearchAdapter(ScannerAdapter):
    name = "dirsearch"
    binary = "dirsearch"
    version_expected = "0.4.x-0.5.x"
    install = "pip install dirsearch (or clone maurosoria/dirsearch)"
    #: dirsearch exits 1 when the user interrupts; a completed run exits 0.
    success_exit_codes = frozenset({0})

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
            "-q",             # results only: no banner, no progress bar
            "--no-color",
            "--random-agent",
            "-t", "10",       # bounded concurrency; the policy owns the deadline
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        saw_line = False

        for raw in output.stdout.splitlines():
            line = raw.strip()
            if not line:
                continue
            match = _RESULT.match(line)
            if match is None:
                continue
            saw_line = True

            url = match.group("url")
            status = int(match.group("status"))
            size = match.group("size")
            redirect = match.group("redirect")

            evidence = [f"url={url}", f"status={status}", f"size={size}"]
            if redirect:
                evidence.append(f"redirect={redirect}")

            path = urlsplit(url).path.lower()
            sensitive = next(
                (segment for segment in _SENSITIVE_SEGMENTS if segment in path), None
            )

            if status == 403:
                # A refusal still proves the resource exists, which is the whole
                # point of content discovery — it is a weaker signal, not none.
                title = f"Path exists but is forbidden (403): {url}"
                description = (
                    f"dirsearch received 403 for {url}: the resource is present but "
                    "access is denied."
                )
                severity = Severity.LOW
            elif sensitive and 200 <= status < 400:
                title = f"Sensitive path reachable ({status}): {url}"
                description = (
                    f"dirsearch reached {url} and the server answered {status}. "
                    f"The path contains {sensitive!r}."
                )
                severity = Severity.MEDIUM
            else:
                title = f"Path discovered ({status}): {url}"
                description = f"dirsearch discovered {url} on {host}."
                severity = Severity.INFO

            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.AEGIS,
                    title=title,
                    description=description,
                    severity=severity,
                    evidence=evidence,
                ),
                request,
            )

        # A wordlist that matched nothing is a legitimate empty result. Output
        # that carried no result line at all is a failure wearing exit code 0.
        if output.stdout.strip() and not saw_line:
            raise ParseError("dirsearch produced output but no result line")
        return findings
