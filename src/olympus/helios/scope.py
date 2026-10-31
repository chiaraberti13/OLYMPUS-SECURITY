"""Scope enforcement for authorized Helios network discovery."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from olympus.core.execution import StructuredAuditRecord, append_structured_audit

#: An engagement authorizes a bounded port set; refuse an unbounded one.
MAX_ALLOWED_PORTS = 1024


class ScopeError(ValueError):
    """Raised for invalid scope configuration or targets."""


class OutOfScopeError(PermissionError):
    """Raised after an unauthorized target has been blocked and logged."""


@dataclass(frozen=True)
class ScopeDecision:
    """An authorized target address and the ports the engagement covers."""

    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    #: ``None`` means the engagement did not restrict ports.
    allowed_ports: frozenset[int] | None = None

    def permits(self, port: int) -> bool:
        """Return whether the engagement authorizes probing ``port``."""
        return self.allowed_ports is None or port in self.allowed_ports

    def __str__(self) -> str:
        return str(self.address)


def _parse_allowed_ports(payload: Any) -> frozenset[int] | None:
    """Read the optional ``allowed_ports`` engagement restriction."""
    if not isinstance(payload, dict) or "allowed_ports" not in payload:
        return None
    raw = payload["allowed_ports"]
    if not isinstance(raw, list):
        raise ScopeError("allowed_ports must be a list of TCP port numbers")
    if not raw or len(raw) > MAX_ALLOWED_PORTS:
        raise ScopeError(f"allowed_ports must list 1 to {MAX_ALLOWED_PORTS} ports")
    ports: set[int] = set()
    for item in raw:
        if isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 65535:
            raise ScopeError(f"allowed_ports entry is not a TCP port: {item!r}")
        ports.add(item)
    return frozenset(ports)


def enforce_scope(target: str, scope_path: Path, log_path: Path) -> ScopeDecision:
    """Return the authorized target decision, or block and audit the request."""
    try:
        payload: Any = json.loads(scope_path.read_text(encoding="utf-8"))
        address = ipaddress.ip_address(target)
        networks = [
            ipaddress.ip_network(item, strict=False) for item in payload["allowed_networks"]
        ]
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ScopeError(f"invalid scope or target: {exc}") from exc
    allowed_ports = _parse_allowed_ports(payload)
    if any(address in network for network in networks):
        return ScopeDecision(address, allowed_ports)
    append_structured_audit(
        log_path,
        StructuredAuditRecord(
            timestamp=datetime.now(UTC).isoformat(),
            execution_id=str(uuid4()),
            action="helios.scope",
            outcome="blocked",
            target=str(address),
            metadata={"reason": "address_not_allowed"},
        ),
    )
    raise OutOfScopeError(str(address))


def audit_denied_ports(
    log_path: Path, address: str, denied: tuple[int, ...], execution_id: str
) -> None:
    """Record, once, the ports an engagement's ``allowed_ports`` refused."""
    if not denied:
        return
    append_structured_audit(
        log_path,
        StructuredAuditRecord(
            timestamp=datetime.now(UTC).isoformat(),
            execution_id=execution_id,
            action="helios.scope",
            outcome="blocked",
            target=address,
            metadata={
                "reason": "port_not_allowed",
                "ports": list(denied[:MAX_ALLOWED_PORTS]),
            },
        ),
    )
