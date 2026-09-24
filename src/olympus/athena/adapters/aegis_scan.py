"""Athena adapter that runs an AEGIS scanner as a pipeline step (scope-gated).

This bridges AEGIS's scope-gated scanner engine into an Athena plan, so a single
``athena run`` can chain **recon → scan → enrich → report**. The adapter is a
plain :class:`~olympus.athena.ports.ToolRunner` (no HTTP client): it delegates to
a real AEGIS :class:`~olympus.aegis.base.ScannerAdapter`.

Authorization and scope are never bypassed — they are enforced twice:

* Athena's own :func:`guard_target` validates scope/SSRF for the engagement, and
* the AEGIS adapter re-validates the target with ``ensure_allowed`` and its
  authorization gate before it will run anything.

An Athena plan only runs once ``authorization.confirmed`` is true (the plan
contract refuses otherwise), so the engagement is authorized by construction;
that is what lets this adapter mark the AEGIS request authorized. Whether a
*real* scan runs is still gated by ``AEGIS_ENABLE_LIVE_SCANS``: with live
scanning off (the default, and in CI) the adapter uses AEGIS's own scope-gated
**simulation** mode, which returns clearly-labelled illustrative findings and
never executes a binary.
"""

from __future__ import annotations

from collections.abc import Callable

from olympus.aegis import config
from olympus.aegis.base import ScannerAdapter
from olympus.aegis.model import ScanRequest
from olympus.aegis.registry import get_adapter
from olympus.aegis.states import ExecutionState
from olympus.athena.adapters.tools.base import guard_target
from olympus.athena.ports import Cancellation, ToolRequest, ToolResult

#: Result states that mean the step completed (real scan or labelled simulation).
_OK_STATES = frozenset({ExecutionState.LIVE, ExecutionState.SIMULATION})


class AegisScanAdapter:
    """Run one AEGIS scanner over an engagement target as an Athena step."""

    def __init__(
        self,
        scanner: str = "nmap",
        *,
        adapter_factory: Callable[[str], ScannerAdapter] = get_adapter,
        live_enabled: Callable[[], bool] = config.live_enabled,
    ) -> None:
        self._scanner = scanner
        self._adapter_factory = adapter_factory
        self._live_enabled = live_enabled

    @property
    def name(self) -> str:
        return "aegis"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (f"aegis:{self._scanner}", "scope-gated scanner orchestration")

    def run(self, request: ToolRequest, cancellation: Cancellation) -> ToolResult:
        guarded = guard_target(request, cancellation)
        if isinstance(guarded, ToolResult):
            return guarded  # scope/SSRF/cancellation already turned into a failed result
        host = guarded

        live = self._live_enabled()
        scan_request = ScanRequest(
            scanner=self._scanner,
            target=host,
            target_kind=request.target_kind,
            allowed=(host,),
            allowed_domains=request.allowed_domains,
            authorized=True,  # the Athena plan gate already confirmed authorization
            live_enabled=live,
            simulate=not live,
            timeout_seconds=float(min(max(request.timeout_seconds, 1), 3600)),
            cancellation=cancellation,
        )
        try:
            result = self._adapter_factory(self._scanner).run(scan_request)
        except (RuntimeError, ValueError, OSError):
            # A scanner failure is a failed step, not a coordinator crash. The
            # error stays a stable, redacted code (no scanner text leaks here).
            return ToolResult(ok=False, error_code="scan_failed")

        if result.state in _OK_STATES:
            return ToolResult(ok=True, assets=list(result.assets), findings=list(result.findings))
        return ToolResult(ok=False, error_code=result.state.value)
