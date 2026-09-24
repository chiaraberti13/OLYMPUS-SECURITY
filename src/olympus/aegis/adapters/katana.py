"""Real katana adapter: parses ProjectDiscovery katana's JSONL crawl output.

katana is a crawler, not a vulnerability scanner: every endpoint it reaches is
attack surface, reported at INFO. What earns a higher severity is a *reachable*
endpoint whose path looks administrative, because "the admin panel answered 200
to an unauthenticated crawler" is a finding an operator wants surfaced rather
than buried in a list of URLs.

``-omit-raw`` and ``-omit-body`` are not an optimisation. Without them katana
embeds the full request and response — headers and body — in every record, and
that stream becomes the run's raw evidence. Response bodies routinely carry
session cookies, tokens and personal data, so the crawler is told not to emit
them in the first place rather than relying on downstream redaction.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from olympus.aegis.base import ParseError, ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

#: Path segments that make a reachable endpoint worth more than a URL listing.
_SENSITIVE_SEGMENTS = (
    "admin",
    "backup",
    "config",
    "console",
    "debug",
    "dump",
    "internal",
    "manage",
    "phpmyadmin",
    "private",
    "server-status",
    ".git",
    ".env",
)

#: A crawler only proves reachability for statuses the server actually served.
_REACHABLE = range(200, 400)


class KatanaAdapter(ScannerAdapter):
    name = "katana"
    binary = "katana"
    version_expected = "1.x"
    install = "go install github.com/projectdiscovery/katana/cmd/katana@latest"

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
            "-u",
            target,
            "-jsonl",
            "-silent",
            "-no-color",
            "-depth",
            "2",
            "-omit-raw",  # keep raw request/response out of evidence
            "-omit-body",  # bodies carry cookies, tokens and PII
            "-disable-update-check",
            "-field-scope",
            "rdn",  # never wander off the target's domain
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        saw_object = False

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ParseError(f"katana emitted an unparseable JSONL line: {exc}") from exc
            if not isinstance(entry, dict):
                continue

            crawl_request = entry.get("request")
            crawl_request = crawl_request if isinstance(crawl_request, dict) else {}
            endpoint = str(crawl_request.get("endpoint") or "").strip()
            if not endpoint:
                continue
            saw_object = True

            response = entry.get("response")
            response = response if isinstance(response, dict) else {}
            status = response.get("status_code")
            method = str(crawl_request.get("method") or "GET")

            evidence = [f"endpoint={endpoint}", f"method={method}"]
            if status is not None:
                evidence.append(f"status={status}")
            if crawl_request.get("source"):
                evidence.append(f"source={crawl_request['source']}")

            path = urlsplit(endpoint).path.lower()
            sensitive = next((segment for segment in _SENSITIVE_SEGMENTS if segment in path), None)
            reachable = isinstance(status, int) and status in _REACHABLE

            if sensitive and reachable:
                title = f"Sensitive endpoint reachable: {endpoint}"
                description = (
                    f"katana crawled {endpoint} unauthenticated and the server answered "
                    f"{status}. The path contains {sensitive!r}."
                )
                severity = Severity.MEDIUM
            else:
                title = f"Endpoint discovered: {endpoint}"
                description = f"katana discovered {endpoint} while crawling {host}."
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

        # A crawl that reached nothing is a legitimate empty result, but output
        # that carried no crawl record at all is a different tool or a failure.
        if output.stdout.strip() and not saw_object:
            raise ParseError("katana produced output but no crawl record")
        return findings
