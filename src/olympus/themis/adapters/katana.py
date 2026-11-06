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

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter, check_json_depth
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

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

    #: Records the last :meth:`parse` call had to discard (non-JSON lines on stdout,
    #: or JSONL that is not a crawl record). Per-run state, reset on every parse;
    #: :meth:`coverage_loss` reports it as a partial result (TOOLS-4.4).
    _skipped_records: int = 0

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
        skipped = 0
        self._skipped_records = 0

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                # katana runs with -jsonl -silent -no-color, so stdout carries crawl
                # JSONL only. A non-JSON line is unexpected output (a diagnostic or an
                # error) and is counted as a discarded record so the run reads as
                # partial, never silently clean (TOOLS-4.4); diagnostics belong on stderr.
                skipped += 1
                continue
            check_json_depth(line, scanner="katana")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ParseError(f"katana emitted an unparseable JSONL line: {exc}") from exc
            if not isinstance(entry, dict):
                skipped += 1
                continue

            crawl_request = entry.get("request")
            crawl_request = crawl_request if isinstance(crawl_request, dict) else {}
            endpoint = str(crawl_request.get("endpoint") or "").strip()
            if not endpoint:
                # Valid JSONL that is not a crawl record (no endpoint): unrecognised
                # grammar, counted as discarded rather than dropped silently.
                skipped += 1
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
                    source=Source.THEMIS,
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
        self._skipped_records = skipped
        return findings

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Report discarded records: some crawl output could not be parsed.

        A crawl that reached nothing is a legitimate empty result; output that
        mixed crawl records with unparseable lines, however, is an incomplete read
        and must read as partial, never silently clean (TOOLS-4.4).
        """
        if self._skipped_records:
            return (
                f"{self._skipped_records} katana output record(s) could not be parsed and "
                "were skipped; findings are not exhaustive"
            )
        return None
