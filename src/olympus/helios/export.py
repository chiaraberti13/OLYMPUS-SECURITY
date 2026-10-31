"""Core Observation/Finding export for Helios probe results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from olympus.core.coverage import Coverage, RunStatus
from olympus.core.enums import Severity, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.models import Finding, Observation
from olympus.helios.scanner import PortState, ProbeResult, is_risky

#: Bumped from 1.0.0: results now carry the run status and coverage, and every
#: probe (not only the open ports) is reported.
RESULT_SCHEMA_VERSION = "1.1.0"


def _service_label(probe: ProbeResult) -> str:
    """Render the identified service, including a banner product when known."""
    if probe.product:
        return f"{probe.service} ({probe.product})"
    return probe.service


def to_findings(asset_id: str, probes: list[ProbeResult]) -> list[Finding]:
    """Convert open ports into shared findings, flagging risky exposed services."""
    findings: list[Finding] = []
    for item in probes:
        if item.state is not PortState.OPEN:
            continue
        risky = is_risky(item.service)
        label = _service_label(item)
        evidence = [f"tcp://{item.host}:{item.port} ({label})"]
        if item.product:
            # The banner is the evidence for the product claim, so it travels
            # with the finding rather than only informing the title.
            evidence.append(f"banner identified: {item.product}")
        findings.append(
            Finding(
                asset_id=asset_id,
                source=Source.HELIOS,
                title=f"TCP port {item.port} exposed ({label})",
                description=(
                    f"A bounded TCP handshake succeeded on {item.host}:{item.port} "
                    f"(service: {label})."
                    + (
                        " Exposing this service to untrusted networks is high-risk."
                        if risky
                        else ""
                    )
                ),
                severity=Severity.MEDIUM if risky else Severity.INFO,
                evidence=evidence,
                remediation=(
                    "Restrict access to this service (firewall/VPN) or disable it if unused."
                    if risky
                    else ""
                ),
            )
        )
    return findings


def to_observations(asset_id: str, probes: list[ProbeResult]) -> list[Observation]:
    """Convert every probe into a non-interpretive shared observation.

    Inconclusive probes are observations too: "port 22 was filtered" is a fact
    about the scan that a later run can be compared against, and omitting it is
    what makes a partial scan look complete.
    """
    observations: list[Observation] = []
    for item in probes:
        attributes = {
            "host": item.host,
            "port": str(item.port),
            "service": item.service,
            "state": item.state.value,
        }
        if item.product:
            attributes["product"] = item.product
        if item.detail:
            attributes["detail"] = item.detail
        observations.append(
            Observation(
                observation_type=(
                    "tcp.open-port" if item.state is PortState.OPEN else "tcp.port-probe"
                ),
                source=Source.HELIOS,
                asset_id=asset_id,
                attributes=attributes,
            )
        )
    return observations


def _dump(payload: dict[str, Any], output: Path) -> None:
    """Write a JSON document atomically with owner-only permissions."""
    output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(output, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def export_findings(findings: list[Finding], output: Path) -> None:
    """Write a versioned Helios finding document atomically."""
    _dump(
        {
            "schema_name": "olympus.helios-findings",
            "schema_version": "1.0.0",
            "findings": [item.model_dump(mode="json") for item in findings],
        },
        output,
    )


def export_scan_result(
    observations: list[Observation],
    findings: list[Finding],
    output: Path,
    *,
    status: RunStatus,
    coverage: Coverage,
) -> None:
    """Write the complete versioned Helios result, including status and coverage."""
    _dump(
        {
            "schema_name": "olympus.helios-result",
            "schema_version": RESULT_SCHEMA_VERSION,
            "status": status.value,
            "coverage": coverage.to_dict(),
            "observations": [item.model_dump(mode="json") for item in observations],
            "findings": [item.model_dump(mode="json") for item in findings],
        },
        output,
    )
