"""Athena adapter wrapping Argus DoH DNS enumeration as an assessment step."""

from __future__ import annotations

from olympus.argus.dns_records import DnsRecordError, build_dns_asset, resolve_records
from olympus.athena.adapters.tools.base import guard_target
from olympus.athena.ports import Cancellation, ToolRequest, ToolResult
from olympus.core.http import HttpClient


class DnsRecordsAdapter:
    """Enumerate DNS records for a target domain over DNS-over-HTTPS."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    @property
    def name(self) -> str:
        return "dns"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("doh-record-enumeration",)

    def run(self, request: ToolRequest, cancellation: Cancellation) -> ToolResult:
        guarded = guard_target(request, cancellation)
        if isinstance(guarded, ToolResult):
            return guarded
        try:
            report = resolve_records(guarded, self._http)
        except DnsRecordError:
            return ToolResult(ok=False, error_code="unreachable")
        return ToolResult(ok=True, assets=[build_dns_asset(report)], findings=[])
