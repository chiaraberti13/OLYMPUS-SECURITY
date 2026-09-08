"""Application services for bounded Minerva triage and custody workflows."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from olympus.core.contracts import validate_contract_header
from olympus.core.execution import Cancellation, ExecutionPolicy, NeverCancelled
from olympus.core.fileio import read_regular_text
from olympus.core.models import Evidence, Incident
from olympus.minerva.custody import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_MAX_LEDGER_BYTES,
    CustodyAction,
    CustodyEntry,
    CustodyRecord,
    LedgerInspection,
    append_entry,
    inspect_ledger,
)
from olympus.minerva.triage import (
    DEFAULT_MAX_ALERT_BYTES,
    DEFAULT_MAX_ALERTS,
    load_alerts,
    triage_alerts,
)

DEFAULT_MAX_EVIDENCE_BYTES = 1_000_000


@dataclass(frozen=True)
class MinervaTriageRequest:
    alerts_path: Path
    title: str
    owner: str | None = None
    excluded_paths: tuple[Path, ...] = ()
    max_alert_bytes: int = DEFAULT_MAX_ALERT_BYTES
    max_alerts: int = DEFAULT_MAX_ALERTS
    deadline_seconds: float = 60.0


@dataclass(frozen=True)
class MinervaRecordRequest:
    evidence_path: Path
    ledger_path: Path
    actor: str
    action: CustodyAction
    max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES
    max_ledger_bytes: int = DEFAULT_MAX_LEDGER_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    deadline_seconds: float = 60.0
    key: bytes | None = None


@dataclass(frozen=True)
class MinervaLedgerRequest:
    ledger_path: Path
    max_ledger_bytes: int = DEFAULT_MAX_LEDGER_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    deadline_seconds: float = 60.0
    key: bytes | None = None


@dataclass(frozen=True)
class MinervaLedgerOutcome:
    entries: tuple[CustodyRecord, ...]
    schema_version: str
    evidence_anchored: bool
    signed: bool = False
    signature_verified: bool = False


@dataclass(frozen=True)
class MinervaApplicationService:
    """Coordinate Minerva use cases below the Typer presentation layer."""

    cancellation: Cancellation = field(default_factory=NeverCancelled)

    def triage(self, request: MinervaTriageRequest) -> Incident:
        _ensure_distinct(request.alerts_path, request.excluded_paths, "alert input and output")
        progress = self._progress(request.deadline_seconds, "Minerva triage")
        progress()
        alerts = load_alerts(
            request.alerts_path,
            max_bytes=request.max_alert_bytes,
            max_alerts=request.max_alerts,
            progress_check=progress,
        )
        progress()
        return triage_alerts(alerts, request.title, request.owner)

    def record(self, request: MinervaRecordRequest) -> CustodyEntry:
        if request.evidence_path.resolve() == request.ledger_path.resolve():
            raise ValueError("evidence input and custody ledger paths must differ")
        progress = self._progress(request.deadline_seconds, "Minerva custody append")
        progress()
        evidence = load_evidence(
            request.evidence_path,
            max_bytes=request.max_evidence_bytes,
        )
        progress()
        return append_entry(
            request.ledger_path,
            evidence,
            request.action,
            request.actor,
            max_ledger_bytes=request.max_ledger_bytes,
            max_entries=request.max_entries,
            progress_check=progress,
            key=request.key,
        )

    def inspect(self, request: MinervaLedgerRequest) -> MinervaLedgerOutcome:
        progress = self._progress(request.deadline_seconds, "Minerva custody verification")
        progress()
        inspection: LedgerInspection = inspect_ledger(
            request.ledger_path,
            max_bytes=request.max_ledger_bytes,
            max_entries=request.max_entries,
            progress_check=progress,
            key=request.key,
        )
        return MinervaLedgerOutcome(
            inspection.entries,
            inspection.schema_version,
            inspection.evidence_anchored,
            signed=inspection.signed,
            signature_verified=inspection.signature_verified,
        )

    def _progress(self, deadline_seconds: float, operation: str) -> Callable[[], None]:
        policy = ExecutionPolicy(deadline_seconds=deadline_seconds)
        deadline = time.monotonic() + policy.deadline_seconds

        def check() -> None:
            policy.check_cancellation(self.cancellation)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{operation} deadline exceeded")

        return check


def load_evidence(path: Path, *, max_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES) -> Evidence:
    """Load one strict, bounded, versioned evidence reference."""
    try:
        payload = json.loads(read_regular_text(path, max_bytes=max_bytes, label="evidence input"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid evidence JSON: {exc.msg}") from exc
    validate_contract_header(payload, schema_name="olympus.evidence")
    try:
        return Evidence.model_validate(payload)
    except ValidationError as exc:
        details = exc.errors(include_input=False, include_url=False)
        raise ValueError(f"invalid evidence contract: {details}") from exc


def _ensure_distinct(source: Path, excluded: tuple[Path, ...], label: str) -> None:
    resolved = source.resolve()
    if any(path.resolve() == resolved for path in excluded):
        raise ValueError(f"{label} paths must differ")
