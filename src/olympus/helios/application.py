"""Application boundary for authorized, bounded Helios discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from olympus.core.coverage import Coverage, RunStatus
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.core.models import Finding, Observation
from olympus.helios.export import to_findings, to_observations
from olympus.helios.scanner import (
    Connector,
    PortState,
    ProbeResult,
    discover,
    normalize_ports,
)
from olympus.helios.scope import ScopeDecision, audit_denied_ports, enforce_scope

#: Default overall budget for one scan when the caller does not set one.
DEFAULT_DEADLINE_SECONDS = 300.0


@dataclass(frozen=True)
class SurfaceScanRequest:
    """Command-independent input and policy for one TCP surface scan."""

    target: str
    ports: tuple[int, ...]
    scope_path: Path
    audit_log_path: Path
    asset_id: str
    authorized: bool = False
    timeout_seconds: float = 1.0
    #: Overall budget for the whole scan; ``None`` derives one from the ports.
    deadline_seconds: float | None = None
    max_concurrency: int = 1


@dataclass(frozen=True)
class SurfaceScanOutcome:
    """Every probe of one scan, its derived contracts, and its trustworthiness."""

    probes: tuple[ProbeResult, ...]
    observations: tuple[Observation, ...]
    findings: tuple[Finding, ...]
    coverage: Coverage
    status: RunStatus

    @property
    def open_ports(self) -> tuple[ProbeResult, ...]:
        """Probes that found something listening."""
        return tuple(probe for probe in self.probes if probe.state is PortState.OPEN)


@dataclass(frozen=True)
class SurfaceScanService:
    """Authorize, scope, execute, and normalize Helios without Typer."""

    connector: Connector
    cancellation: Cancellation = field(default_factory=NeverCancelled)

    def run(self, request: SurfaceScanRequest) -> SurfaceScanOutcome:
        ports = normalize_ports(list(request.ports))
        policy = ExecutionPolicy(
            authorized=request.authorized,
            timeout_seconds=request.timeout_seconds,
            deadline_seconds=self._deadline_for(request, len(ports)),
            max_concurrency=request.max_concurrency,
        )
        decisions: list[ScopeDecision] = []

        def authorize(target: str) -> None:
            decisions.append(enforce_scope(target, request.scope_path, request.audit_log_path))

        policy.authorize_target("Helios surface scan", request.target, authorize)
        decision = decisions[0]
        denied = tuple(port for port in ports if not decision.permits(port))
        audit_denied_ports(request.audit_log_path, str(decision.address), denied, str(uuid4()))
        policy.check_cancellation(self.cancellation)
        report = discover(
            request.target,
            list(ports),
            self.connector,
            policy=policy,
            cancellation=self.cancellation,
            allowed_ports=decision.allowed_ports,
        )
        findings = to_findings(request.asset_id, list(report.probes))
        observations = to_observations(request.asset_id, list(report.probes))
        return SurfaceScanOutcome(
            probes=report.probes,
            observations=tuple(observations),
            findings=tuple(findings),
            coverage=report.coverage,
            status=report.coverage.status(len(findings)),
        )

    @staticmethod
    def _deadline_for(request: SurfaceScanRequest, port_count: int) -> float:
        """Derive one overall budget instead of summing per-port timeouts.

        Summing them lets a wide scan run for as long as the port list is long.
        The default spreads the per-port timeout across the configured
        concurrency and caps it at :data:`DEFAULT_DEADLINE_SECONDS`.
        """
        if request.deadline_seconds is not None:
            return request.deadline_seconds
        lanes = max(1, request.max_concurrency)
        estimated = request.timeout_seconds * ((port_count + lanes - 1) // lanes)
        return max(request.timeout_seconds, min(DEFAULT_DEADLINE_SECONDS, estimated))
