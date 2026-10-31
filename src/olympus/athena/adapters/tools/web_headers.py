"""Athena adapter wrapping Argus passive web recon as an assessment step."""

from __future__ import annotations

import socket

from olympus.argus.web import (
    WebPolicyBlockedError,
    WebReconError,
    build_web_asset,
    build_web_findings,
    fetch_web,
)
from olympus.athena.adapters.tools.base import guard_target
from olympus.athena.ports import Cancellation, ToolRequest, ToolResult
from olympus.athena.scope import (
    SsrfBlockedError,
    TargetResolutionError,
    ensure_web_target_allowed,
)
from olympus.core.addresses import AddressResolver
from olympus.core.http import HttpClient


class WebHeadersAdapter:
    """Assess the passive HTTP security-header posture of a target host."""

    def __init__(
        self,
        http: HttpClient,
        *,
        resolver: AddressResolver = socket.getaddrinfo,
    ) -> None:
        self._http = http
        self._resolver = resolver

    @property
    def name(self) -> str:
        return "web-headers"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("passive-http-recon", "security-header-audit")

    def run(self, request: ToolRequest, cancellation: Cancellation) -> ToolResult:
        guarded = guard_target(request, cancellation)
        if isinstance(guarded, ToolResult):
            return guarded
        try:
            ensure_web_target_allowed(
                request.target_kind,
                request.target_value,
                request.allowed_domains,
                resolver=self._resolver,
            )
        except SsrfBlockedError:
            return ToolResult(ok=False, error_code="ssrf_blocked")
        except TargetResolutionError:
            return ToolResult(ok=False, error_code="unreachable")
        try:
            report = fetch_web(request.target_value, self._http)
        except WebPolicyBlockedError:
            # The connect-time policy refused the socket: an out-of-scope
            # redirect hop, or a DNS answer that changed after validation.
            return ToolResult(ok=False, error_code="ssrf_blocked")
        except WebReconError:
            return ToolResult(ok=False, error_code="unreachable")
        asset = build_web_asset(report)
        findings = build_web_findings(asset.asset_id, report)
        return ToolResult(ok=True, assets=[asset], findings=findings)
