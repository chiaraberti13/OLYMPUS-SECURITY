"""Real dalfox adapter: parses dalfox's JSON proof-of-concept output.

dalfox reports XSS proofs of concept. Its ``--format json`` emits a JSON array,
and a clean target produces ``[\\n{}]`` — a one-element array holding an empty
object, not an empty array. That quirk is the whole reason this parser exists in
the shape it does: a naive reader counts one element and reports a finding on a
target where nothing was found. Records without a payload are therefore dropped
before anything is built.

Every dalfox record is an *executed* proof of concept, so the payload it carries
is reflected attacker-controlled input. It is truncated and carried as evidence,
never interpolated into a title.
"""

from __future__ import annotations

import json

from olympus.aegis.base import ParseError, ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.runner import CommandOutput
from olympus.core.enums import AssetType, Severity, Source
from olympus.core.models import Asset, Finding

#: dalfox's severity vocabulary mapped onto the Olympus scale.
_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

#: How much of a reflected payload is worth keeping as evidence.
_MAX_PAYLOAD = 300

#: dalfox's finding types. ``V`` is a verified PoC, ``R`` a reflected parameter,
#: ``G`` a grep-based match; only the first is proof of an exploitable issue.
_VERIFIED = "V"


class DalfoxAdapter(ScannerAdapter):
    name = "dalfox"
    binary = "dalfox"
    version_expected = "2.x"
    install = "go install github.com/hahwul/dalfox/v2@latest"

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
            "url",
            target,
            "--format",
            "json",
            "--silence",
            "--no-color",
            "--skip-mining-all",  # keep the request budget bounded and predictable
            "--no-spinner",
        ]

    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        text = output.stdout.strip()
        start = text.find("[")
        if start == -1:
            raise ParseError("dalfox produced no JSON array")
        try:
            entries = json.loads(text[start:])
        except json.JSONDecodeError as exc:
            raise ParseError(f"dalfox JSON unparseable: {exc}") from exc
        if not isinstance(entries, list):
            raise ParseError("dalfox JSON root is not an array")

        asset_id = self.asset_id(host)
        findings: list[Finding] = []
        for entry in entries:
            # The clean-target case: dalfox emits [{}], so an entry with no
            # payload is padding and must never become a finding.
            if not isinstance(entry, dict) or not entry.get("payload"):
                continue

            poc_type = str(entry.get("type") or "").upper()
            param = str(entry.get("param") or "unknown")
            method = str(entry.get("method") or "GET")
            inject = str(entry.get("inject_type") or "unknown")
            payload = str(entry["payload"])[:_MAX_PAYLOAD]
            cwe = str(entry.get("cwe") or "").strip()

            declared = _SEVERITY.get(str(entry.get("severity", "")).lower())
            if poc_type == _VERIFIED:
                severity = declared or Severity.HIGH
                headline = "Verified XSS"
            else:
                # Reflection without a verified PoC is a lead, not a proof, and
                # is capped so an unverified record cannot claim HIGH.
                severity = Severity.LOW
                headline = "Reflected parameter (unverified)"

            evidence = [
                f"param={param}",
                f"method={method}",
                f"inject_type={inject}",
                f"payload={payload}",
            ]
            if cwe:
                evidence.append(f"cwe={cwe}")

            self.add_finding(
                findings,
                Finding(
                    asset_id=asset_id,
                    source=Source.AEGIS,
                    title=f"{headline} in parameter {param}",
                    description=(
                        f"dalfox reported a {inject} issue on parameter {param} via {method}."
                    ),
                    severity=severity,
                    evidence=evidence,
                ),
                request,
            )
        return findings
