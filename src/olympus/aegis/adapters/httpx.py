"""Real httpx adapter: parses ProjectDiscovery httpx's JSONL probe output.

**Name collision, and why it matters.** ``httpx`` is also the console script of
the popular Python HTTP client library. Both install an executable called
``httpx``, so ``shutil.which("httpx")`` cannot tell them apart and a host with
the Python library installed reports this scanner as "available" when the
ProjectDiscovery probe is not there at all. The parser therefore refuses output
that does not look like the probe's JSONL, with an error that names the
collision instead of a generic parse failure — a wrong tool must never be
reported as a clean scan.
"""

from __future__ import annotations

import json

from olympus.aegis.base import ParseError, ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

_WRONG_TOOL = (
    "httpx produced no probe JSONL. The executable named 'httpx' on this host is "
    "probably the Python HTTP client library, not the ProjectDiscovery probe; "
    "install github.com/projectdiscovery/httpx and put it first on PATH"
)

#: Server-side status classes worth surfacing beyond a plain reachability note.
_SERVER_ERROR = range(500, 600)


class HttpxAdapter(ScannerAdapter):
    name = "httpx"
    binary = "httpx"
    version_expected = "1.x (ProjectDiscovery)"
    install = "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"

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
        target = request.target if request.target_kind == "url" else host
        return [
            self.binary,
            "-target",
            target,
            "-json",
            "-silent",
            "-no-color",
            "-title",
            "-web-server",
            "-tech-detect",
            "-status-code",
            "-disable-update-check",
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        saw_probe = False

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ParseError(f"httpx emitted an unparseable JSONL line: {exc}") from exc
            if not isinstance(entry, dict) or "url" not in entry:
                continue
            saw_probe = True
            if entry.get("failed"):
                continue

            url = str(entry.get("url", ""))
            status = entry.get("status_code")
            webserver = str(entry.get("webserver") or "").strip()
            title = str(entry.get("title") or "").strip()
            tech = entry.get("tech")
            tech = [str(item) for item in tech] if isinstance(tech, list) else []

            evidence = [f"url={url}"]
            if status is not None:
                evidence.append(f"status={status}")
            if title:
                evidence.append(f"title={title}")
            if isinstance(status, int) and status in _SERVER_ERROR:
                severity = Severity.LOW
                summary = f"HTTP service responding with a server error ({status})"
            else:
                severity = Severity.INFO
                summary = f"HTTP service reachable ({status if status is not None else 'n/a'})"

            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.AEGIS,
                    title=f"{summary}: {url}",
                    description=f"httpx probed {url} and it answered.",
                    severity=severity,
                    evidence=evidence,
                ),
                request,
            )

            # Disclosed server software and frameworks are separate, actionable
            # facts, not decoration on the reachability finding.
            for label, value in (("Web server", webserver), *((("Technology", t)) for t in tech)):
                if not value:
                    continue
                self.add_finding(
                    findings,
                    Finding(
                        asset_id=asset_id,
                        source=Source.AEGIS,
                        title=f"{label} disclosed: {value}",
                        description=f"httpx fingerprinted {label.lower()} {value} on {url}.",
                        severity=Severity.INFO,
                        evidence=[f"url={url}", f"{label.lower().replace(' ', '_')}={value}"],
                    ),
                    request,
                )

        if not saw_probe:
            raise ParseError(_WRONG_TOOL)
        return findings
