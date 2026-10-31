"""Athena adapter wrapping Argus RDAP/WHOIS lookups as an assessment step."""

from __future__ import annotations

from olympus.argus.whois import WhoisError, build_whois_asset, lookup_domain
from olympus.athena.adapters.tools.base import guard_target
from olympus.athena.ports import Cancellation, ToolRequest, ToolResult
from olympus.core.http import HttpClient


class WhoisAdapter:
    """Fetch registration data for a target domain via RDAP."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    @property
    def name(self) -> str:
        return "whois"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("rdap-registration",)

    def run(self, request: ToolRequest, cancellation: Cancellation) -> ToolResult:
        guarded = guard_target(request, cancellation)
        if isinstance(guarded, ToolResult):
            return guarded
        try:
            report = lookup_domain(guarded, self._http)
        except WhoisError:
            return ToolResult(ok=False, error_code="lookup_failed")
        return ToolResult(ok=True, assets=[build_whois_asset(report)], findings=[])
