"""Olympus Core — the shared data contract for every module.

Exposes the canonical models, enumerations, traceable ID generator, run
status/coverage vocabulary, exit codes and structured validation errors that
all Olympus tools rely on.
"""

from __future__ import annotations

from olympus.core.coverage import (
    Coverage,
    CoverageTracker,
    FailureKind,
    RunStatus,
    classify_run_status,
    exit_code_for,
    summarize,
)
from olympus.core.enums import (
    AlertStatus,
    AssetType,
    Criticality,
    FindingStatus,
    IncidentStatus,
    Severity,
    Source,
)
from olympus.core.errors import ValidationReport, format_validation_error
from olympus.core.execution import (
    AuthorizationRequiredError,
    CancellationRequested,
    CancellationToken,
    Deadline,
    ExecutionPolicy,
    ExecutionPolicyError,
    StructuredAuditRecord,
    append_structured_audit,
    interruptible_sleep,
)
from olympus.core.exit_codes import ExitCode, normalize_exit_code
from olympus.core.ids import IdGenerator, new_id
from olympus.core.models import (
    Alert,
    Asset,
    Event,
    Evidence,
    Finding,
    Incident,
    Observation,
    OlympusModel,
    ScanJob,
    SecurityReport,
)

__all__ = [
    "Alert",
    "AlertStatus",
    "Asset",
    "AssetType",
    "AuthorizationRequiredError",
    "CancellationRequested",
    "CancellationToken",
    "Coverage",
    "CoverageTracker",
    "Criticality",
    "Deadline",
    "Event",
    "Evidence",
    "ExecutionPolicy",
    "ExecutionPolicyError",
    "ExitCode",
    "FailureKind",
    "Finding",
    "FindingStatus",
    "IdGenerator",
    "Incident",
    "IncidentStatus",
    "Observation",
    "OlympusModel",
    "RunStatus",
    "ScanJob",
    "SecurityReport",
    "Severity",
    "Source",
    "StructuredAuditRecord",
    "ValidationReport",
    "append_structured_audit",
    "classify_run_status",
    "exit_code_for",
    "format_validation_error",
    "interruptible_sleep",
    "new_id",
    "normalize_exit_code",
    "summarize",
]
