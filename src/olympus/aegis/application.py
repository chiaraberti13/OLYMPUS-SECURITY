"""Application boundary for scoped, auditable AEGIS native scanner execution."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from olympus.aegis.base import ScannerAdapter
from olympus.aegis.model import (
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_PROCESS_OUTPUT_BYTES,
    ScanRequest,
    ScanResult,
)
from olympus.aegis.registry import get_adapter
from olympus.aegis.scope import OutOfScopeError, SsrfBlockedError
from olympus.core.contracts import validate_contract_header
from olympus.core.execution import (
    AuthorizationRequiredError,
    Cancellation,
    ExecutionPolicy,
    NeverCancelled,
    StructuredAuditRecord,
    append_structured_audit,
)
from olympus.core.fileio import atomic_write_text, read_regular_text

DEFAULT_MAX_SCOPE_BYTES = 1_000_000


class AegisScope(BaseModel):
    """Exact host/domain/CIDR engagement scope for native AEGIS scans."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["olympus.aegis-scope"] = "olympus.aegis-scope"
    schema_version: Literal["1.0.0"] = "1.0.0"
    allowed_hosts: tuple[str, ...] = Field(default=(), max_length=1_024)
    allowed_domains: tuple[str, ...] = Field(default=(), max_length=1_024)
    allowed_cidrs: tuple[str, ...] = Field(default=(), max_length=1_024)

    @field_validator("allowed_hosts", "allowed_domains", "allowed_cidrs")
    @classmethod
    def _strict_entries(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not value
            or value != value.strip()
            or len(value) > 253
            or any(character in value for character in "\r\n\x00")
            for value in values
        ):
            raise ValueError("scope entries must be trimmed, bounded, and contain no CR/LF/NUL")
        if len(values) != len({value.casefold() for value in values}):
            raise ValueError("scope entries must be unique")
        return values

    @field_validator("allowed_cidrs")
    @classmethod
    def _longer_cidrs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(len(value) > 64 for value in values):
            raise ValueError("CIDR scope entries must contain at most 64 characters")
        return values

    def nonempty(self) -> AegisScope:
        if not (self.allowed_hosts or self.allowed_domains or self.allowed_cidrs):
            raise ValueError("AEGIS scope must authorize at least one host, domain, or CIDR")
        return self


@dataclass(frozen=True)
class AegisRunRequest:
    scanner: str
    target: str
    target_kind: str
    scope_path: Path
    authorized: bool
    live_enabled: bool
    simulate: bool = False
    output_path: Path | None = None
    audit_path: Path | None = None
    timeout_seconds: float = 300.0
    deadline_seconds: float = 600.0
    max_scope_bytes: int = DEFAULT_MAX_SCOPE_BYTES
    max_output_bytes: int = DEFAULT_MAX_PROCESS_OUTPUT_BYTES
    max_findings: int = DEFAULT_MAX_FINDINGS
    cancellation: Cancellation = field(default_factory=NeverCancelled, repr=False, compare=False)


@dataclass(frozen=True)
class AegisApplicationService:
    """Apply authorization before scope and dispatch through a real adapter port."""

    adapter_factory: Callable[[str], ScannerAdapter] = field(default=get_adapter, repr=False)

    def run(self, request: AegisRunRequest) -> ScanResult:
        policy = ExecutionPolicy(
            authorized=request.authorized,
            timeout_seconds=request.timeout_seconds,
            deadline_seconds=request.deadline_seconds,
        )
        _validate_path_conflicts(request)
        execution_id = f"aegis-{uuid4().hex}"
        try:
            if not request.simulate:
                policy.require_authorization(f"AEGIS {request.scanner} live scan")
            scope = load_scope(request.scope_path, max_bytes=request.max_scope_bytes)
            adapter = self.adapter_factory(request.scanner)
            result = adapter.run(
                ScanRequest(
                    scanner=request.scanner,
                    target=request.target,
                    target_kind=request.target_kind,
                    allowed=scope.allowed_hosts,
                    allowed_domains=scope.allowed_domains,
                    allowed_cidrs=scope.allowed_cidrs,
                    timeout_seconds=request.timeout_seconds,
                    deadline_seconds=request.deadline_seconds,
                    max_output_bytes=request.max_output_bytes,
                    max_findings=request.max_findings,
                    authorized=request.authorized,
                    live_enabled=request.live_enabled,
                    simulate=request.simulate,
                    cancellation=request.cancellation,
                )
            )
        except AuthorizationRequiredError:
            self._audit(request, execution_id, "refused", {})
            raise
        except (OutOfScopeError, SsrfBlockedError):
            self._audit(request, execution_id, "blocked", {})
            raise
        except BaseException as exc:
            self._audit(request, execution_id, "failed", {"error_type": type(exc).__name__})
            raise
        self._audit(
            request,
            execution_id,
            result.state.value,
            {
                "scanner": result.scanner,
                "finding_count": len(result.findings),
                "asset_count": len(result.assets),
                "resolved_addresses": list(result.resolved_addresses),
            },
        )
        if request.output_path is not None:
            export_result(result, request.output_path)
        return result

    @staticmethod
    def _audit(
        request: AegisRunRequest,
        execution_id: str,
        outcome: str,
        metadata: dict[str, object],
    ) -> None:
        if request.audit_path is None:
            return
        append_structured_audit(
            request.audit_path,
            StructuredAuditRecord(
                timestamp=datetime.now(UTC).isoformat(),
                execution_id=execution_id,
                action="aegis.native-scan",
                outcome=outcome,
                target=request.target,
                metadata=metadata,
            ),
        )


def load_scope(path: Path, *, max_bytes: int = DEFAULT_MAX_SCOPE_BYTES) -> AegisScope:
    """Load the strict current scope or one unambiguous legacy scope shape."""
    try:
        raw = json.loads(read_regular_text(path, max_bytes=max_bytes, label="AEGIS scope"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid AEGIS scope JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ValueError("AEGIS scope must be a JSON object")
    candidate = dict(raw)
    has_name = "schema_name" in candidate
    has_version = "schema_version" in candidate
    if not has_name and not has_version:
        allowed = candidate.pop("allowed", ())
        if "allowed_domains" not in candidate:
            candidate["allowed_domains"] = allowed
        candidate["schema_name"] = "olympus.aegis-scope"
        candidate["schema_version"] = "1.0.0"
    elif has_name != has_version:
        raise ValueError("AEGIS scope has a partial contract header")
    validate_contract_header(candidate, schema_name="olympus.aegis-scope")
    try:
        return AegisScope.model_validate(candidate).nonempty()
    except ValidationError as exc:
        details = exc.errors(include_input=False, include_url=False)
        raise ValueError(f"invalid AEGIS scope contract: {details}") from exc


def export_result(result: ScanResult, output: Path) -> None:
    """Write one validated versioned result with a unique durable replacement."""
    content = result.to_document().model_dump_json(indent=2) + "\n"
    atomic_write_text(output, content, mode=0o600)


def _validate_path_conflicts(request: AegisRunRequest) -> None:
    scope = request.scope_path.resolve()
    outputs = [
        path.resolve() for path in (request.output_path, request.audit_path) if path is not None
    ]
    if len(outputs) != len(set(outputs)):
        raise ValueError("AEGIS result and audit paths must differ")
    if scope in outputs:
        raise ValueError("AEGIS output paths must not overwrite the scope input")
