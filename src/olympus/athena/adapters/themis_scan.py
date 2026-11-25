"""Athena adapter that runs a Themis scanner as a pipeline step (scope-gated).

This bridges Themis's scope-gated scanner engine into an Athena plan, so a single
``athena run`` can chain **recon → scan → enrich → report**. The adapter is a
plain :class:`~olympus.athena.ports.ToolRunner` (no HTTP client): it delegates to
a real Themis :class:`~olympus.themis.base.ScannerAdapter`.

Authorization and scope are never bypassed — they are enforced twice:

* Athena's own :func:`guard_target` validates scope/SSRF for the engagement, and
* the Themis adapter re-validates the target with ``ensure_allowed`` and its
  authorization gate before it will run anything.

An Athena plan only runs once ``authorization.confirmed`` is true (the plan
contract refuses otherwise), so the engagement is authorized by construction;
that is what lets this adapter mark the Themis request authorized. Whether a
*real* scan runs is still gated by ``THEMIS_ENABLE_LIVE_SCANS``: with live
scanning off (the default, and in CI) the adapter uses Themis's own scope-gated
**simulation** mode, which returns clearly-labelled illustrative findings and
never executes a binary.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

from olympus.athena.adapters.tools.base import guard_target
from olympus.athena.ports import Cancellation, ToolRequest, ToolResult
from olympus.engines.evidence import (
    EvidenceAuthorization,
    EvidenceError,
    Signer,
    build_evidence,
    write_signed,
)
from olympus.engines.preflight import PreflightVerdict
from olympus.themis import config
from olympus.themis.base import ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.registry import get_adapter
from olympus.themis.sandbox import require_scanner_isolation
from olympus.themis.states import ExecutionState

#: Result states that mean the step completed (real scan or labelled simulation).
_OK_STATES = frozenset({ExecutionState.LIVE, ExecutionState.SIMULATION})


def _engine_preflight(scanner: str) -> PreflightVerdict:
    from olympus.engines.cli import system_environment
    from olympus.engines.preflight import preflight_for_scanner

    return preflight_for_scanner(system_environment(), scanner)


class ThemisScanAdapter:
    """Run one Themis scanner over an engagement target as an Athena step."""

    def __init__(
        self,
        scanner: str = "nmap",
        *,
        adapter_factory: Callable[[str], ScannerAdapter] = get_adapter,
        live_enabled: Callable[[], bool] = config.live_enabled,
        engine_preflight: Callable[[str], PreflightVerdict] = _engine_preflight,
        isolation_verifier: Callable[[], None] = require_scanner_isolation,
    ) -> None:
        self._scanner = scanner
        self._adapter_factory = adapter_factory
        self._live_enabled = live_enabled
        self._engine_preflight = engine_preflight
        self._isolation_verifier = isolation_verifier

    @property
    def name(self) -> str:
        return "themis"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (f"themis:{self._scanner}", "scope-gated scanner orchestration")

    def run(self, request: ToolRequest, cancellation: Cancellation) -> ToolResult:
        guarded = guard_target(request, cancellation)
        if isinstance(guarded, ToolResult):
            return guarded  # scope/SSRF/cancellation already turned into a failed result
        host = guarded

        live = self._live_enabled()
        evidence_values = (
            request.evidence_run_id,
            request.evidence_job_id,
            request.evidence_path,
            request.evidence_signer,
        )
        evidence_configured = all(value is not None for value in evidence_values)
        if any(value is not None for value in evidence_values) and not evidence_configured:
            return ToolResult(ok=False, error_code="evidence_configuration_invalid")
        if live:
            # Athena is an orchestration surface, not an authority bypass. A live
            # Themis step must satisfy the same isolation/preflight/evidence
            # gates as direct and worker execution before the adapter is reached.
            if not evidence_configured:
                return ToolResult(ok=False, error_code="evidence_required")
            try:
                self._isolation_verifier()
                if not self._engine_preflight(self._scanner).ok:
                    return ToolResult(ok=False, error_code="engine_missing")
            except (OSError, RuntimeError, ValueError):
                return ToolResult(ok=False, error_code="isolation_required")
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

        evidence_run_id: str | None = None
        evidence_sha256: str | None = None
        if evidence_configured:
            run_id = cast(str, request.evidence_run_id)
            job_id = cast(str, request.evidence_job_id)
            evidence_path = cast(Path, request.evidence_path)
            evidence_signer = cast(Signer, request.evidence_signer)
            try:
                evidence = build_evidence(
                    run_id=run_id,
                    result=result,
                    request=scan_request,
                )
                evidence = evidence.model_copy(
                    update={"authorization": EvidenceAuthorization(job_id=job_id)}
                )
                evidence_sha256 = write_signed(evidence, evidence_signer, evidence_path)
                evidence_run_id = run_id
            except (EvidenceError, OSError, ValueError):
                return ToolResult(ok=False, error_code="evidence_failed")

        if result.state in _OK_STATES:
            return ToolResult(
                ok=True,
                assets=list(result.assets),
                findings=list(result.findings),
                evidence_run_id=evidence_run_id,
                evidence_sha256=evidence_sha256,
            )
        return ToolResult(ok=False, error_code=result.state.value)
