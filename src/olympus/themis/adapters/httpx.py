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

from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding
from olympus.themis.base import ParseError, ScannerAdapter, check_json_depth
from olympus.themis.model import ScanRequest
from olympus.themis.runner import CommandOutput

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

    #: Records the last :meth:`parse` call had to discard (non-JSON lines on stdout,
    #: or JSONL that is not a probe object). An adapter instance serves one run, so
    #: this is per-run state, reset on every parse; :meth:`coverage_loss` reports it
    #: as a partial result (TOOLS-4.4).
    _skipped_records: int = 0

    def recognises(self, version_output: str) -> bool:
        """Only the ProjectDiscovery probe prints ``Current Version``; the Python client does not.

        The Python library answers ``-version`` with a usage error or ``httpx, version X``, so
        the presence probe can refuse it before any scan is attempted.
        """
        lowered = version_output.lower()
        return "current version" in lowered and "httpx, version" not in lowered

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
        skipped = 0
        self._skipped_records = 0

        for line in output.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                # httpx runs with -json -silent -no-color, so stdout carries probe
                # JSONL only. A non-JSON line is unexpected output — a diagnostic or
                # an error — that must not vanish silently, or an unknown error printed
                # on stdout could read as a clean run. Count it as a discarded record
                # so the result is partial, never silently clean (TOOLS-4.4);
                # legitimate diagnostics belong on stderr.
                skipped += 1
                continue
            check_json_depth(line, scanner="httpx")
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ParseError(f"httpx emitted an unparseable JSONL line: {exc}") from exc
            if not isinstance(entry, dict) or "url" not in entry:
                # Valid JSONL that is not a probe object (no 'url'): unrecognised
                # grammar, counted as a discarded record rather than dropped silently.
                skipped += 1
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
                    source=Source.THEMIS,
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
                        source=Source.THEMIS,
                        title=f"{label} disclosed: {value}",
                        description=f"httpx fingerprinted {label.lower()} {value} on {url}.",
                        severity=Severity.INFO,
                        evidence=[f"url={url}", f"{label.lower().replace(' ', '_')}={value}"],
                    ),
                    request,
                )

        if not saw_probe:
            raise ParseError(_WRONG_TOOL)
        self._skipped_records = skipped
        return findings

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Report discarded records: some probe output could not be parsed.

        httpx exits 0 whether or not the target answered, so silence is a real
        result; output that carried a probe *and* unparseable lines, however, is
        an incomplete read and must read as partial, never silently clean.
        """
        if self._skipped_records:
            return (
                f"{self._skipped_records} httpx output record(s) could not be parsed and "
                "were skipped; findings are not exhaustive"
            )
        return None
