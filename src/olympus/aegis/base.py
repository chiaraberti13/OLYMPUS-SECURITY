"""Shared policy and process boundary for real AEGIS scanner adapters."""

from __future__ import annotations

import hashlib
import re
import time
from abc import ABC, abstractmethod
from dataclasses import replace

from olympus.aegis.model import MAX_RAW_EVIDENCE, Dependency, ScanRequest, ScanResult
from olympus.aegis.runner import (
    CommandError,
    CommandOutput,
    CommandTimeout,
    TerminationCause,
    TerminationReport,
    run_command,
    which,
)
from olympus.aegis.scope import ensure_allowed, resolve_and_validate, socket_resolver
from olympus.aegis.states import ExecutionState
from olympus.core.execution import ExecutionPolicy, redact_text, redact_url
from olympus.core.models import Asset, Finding


class NotAuthorizedError(RuntimeError):
    """Raised when a real scan is requested without explicit authorization."""


class ParseError(RuntimeError):
    """Raised by an adapter when the scanner's output cannot be parsed."""


class ScannerAdapter(ABC):
    """Abstract external-CLI scanner adapter."""

    name: str = ""
    binary: str = ""
    version_expected: str = "any"
    install: str = ""
    success_exit_codes: frozenset[int] = frozenset({0})

    @abstractmethod
    def build_argv(self, host: str, request: ScanRequest) -> list[str]:
        """Return the fixed argument vector for a real scan of ``host``."""

    @abstractmethod
    def parse(self, output: CommandOutput, host: str, request: ScanRequest) -> list[Finding]:
        """Parse real scanner output into findings (empty means no findings)."""

    def asset_id(self, host: str) -> str:
        """Return a collision-resistant deterministic ID for the normalized host."""
        digest = hashlib.sha256(host.encode()).hexdigest()[:24].upper()
        return f"AST-AEGIS-{digest}"

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        """Return a shared asset representing the scanned target."""
        from olympus.core.enums import AssetType, Source

        kind = AssetType.URL if request.target_kind == "url" else AssetType.HOST
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=kind,
            hostname=host,
            ip_addresses=list(request.resolved_addresses),
            source=Source.AEGIS,
            tags=["aegis", self.name],
        )

    def resolve(self, host: str) -> tuple[str, ...]:
        """Injected seam for the system DNS resolver."""
        return socket_resolver(host)

    @staticmethod
    def add_finding(
        findings: list[Finding], finding: Finding, request: ScanRequest
    ) -> None:
        """Append without ever allocating beyond the configured finding cap."""
        if len(findings) >= request.max_findings:
            raise ParseError(f"scanner output exceeds the {request.max_findings} finding limit")
        findings.append(finding)

    def version(self, request: ScanRequest, timeout: float) -> str | None:
        """Return a bounded scanner version string, or ``None`` if undetermined."""
        path = which(self.binary)
        if not path:
            return None
        for flag in ("--version", "-version", "-V"):
            try:
                output = run_command(
                    [self.binary, flag],
                    timeout=min(timeout, 15.0),
                    max_output_bytes=min(request.max_output_bytes, 65_536),
                    cancellation=request.cancellation,
                )
            except (CommandError, CommandTimeout):
                continue
            if output.exit_code not in self.success_exit_codes:
                continue
            lines = (output.stdout or output.stderr).strip().splitlines()
            if lines:
                return _safe_line(lines[0], 500)
        return path

    def simulate(self, host: str, request: ScanRequest) -> list[Finding]:
        """Return clearly-labelled illustrative findings (SIMULATION only)."""
        from olympus.core.enums import Severity, Source

        return [
            Finding(
                asset_id=self.asset_id(host),
                source=Source.AEGIS,
                title=f"[SIMULATION] Example {self.name} finding (not a real scan)",
                description=(
                    "Illustrative output produced only because --simulate was explicitly "
                    "requested. It is not a real scanner result."
                ),
                severity=Severity.INFO,
                evidence=[f"scanner={self.name}", f"target={redact_url(host)}", "mode=simulation"],
            )
        ]

    def _dependency(self) -> Dependency:
        return Dependency(
            executable=self.binary,
            install=self.install,
            version_expected=self.version_expected,
            diagnostic=f"olympus aegis deps (checks '{self.binary}' on PATH)",
        )

    def run(self, request: ScanRequest) -> ScanResult:
        """Execute one adapter with authorization, scope, bounds and explicit states."""
        if request.scanner != self.name:
            raise ValueError(
                f"request scanner {request.scanner!r} does not match adapter {self.name!r}"
            )
        if request.simulate:
            host = ensure_allowed(
                request.target_kind,
                request.target,
                request.allowed,
                request.allowed_domains,
                request.allowed_cidrs,
                legacy_suffixes=False,
            )
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.SIMULATION,
                target=request.target,
                findings=self.simulate(host, request),
                assets=[self.build_asset(host, request)],
                raw_evidence="simulation mode: no scanner was executed",
            )

        policy = ExecutionPolicy(
            authorized=request.authorized,
            timeout_seconds=request.timeout_seconds,
            deadline_seconds=request.deadline_seconds,
        )
        try:
            policy.require_authorization(f"AEGIS {self.name} live scan")
        except PermissionError as exc:
            raise NotAuthorizedError(
                f"a real {self.name} scan requires explicit authorization (--i-am-authorized)"
            ) from exc
        host = ensure_allowed(
            request.target_kind,
            request.target,
            request.allowed,
            request.allowed_domains,
            request.allowed_cidrs,
            legacy_suffixes=False,
        )
        policy.check_cancellation(request.cancellation)
        if not request.live_enabled:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.DISABLED,
                target=request.target,
                error=(
                    "live scanning is disabled; set AEGIS_ENABLE_LIVE_SCANS=true for a real "
                    "scan, or pass --simulate explicitly"
                ),
            )
        if which(self.binary) is None:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.UNAVAILABLE,
                target=request.target,
                dependency=self._dependency(),
                error=f"required executable '{self.binary}' is not installed / not on PATH",
            )

        started = time.monotonic()

        def remaining() -> float:
            value = request.deadline_seconds - (time.monotonic() - started)
            if value <= 0:
                raise TimeoutError("AEGIS overall execution deadline exceeded")
            return value

        version = self.version(request, remaining())
        policy.check_cancellation(request.cancellation)
        addresses = resolve_and_validate(
            host,
            allowed=request.allowed,
            allowed_cidrs=request.allowed_cidrs,
            resolver=self.resolve,
            progress_check=lambda: policy.check_cancellation(request.cancellation),
        )
        request_with_addresses = replace(request, resolved_addresses=addresses)
        argv = self.build_argv(host, request_with_addresses)
        try:
            output = run_command(
                argv,
                timeout=min(request.timeout_seconds, remaining()),
                max_output_bytes=request.max_output_bytes,
                cancellation=request.cancellation,
            )
        except (CommandError, CommandTimeout, TimeoutError) as exc:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.FAILED,
                target=request.target,
                resolved_addresses=addresses,
                version=version,
                error=str(exc),
                termination=_termination_of(exc),
                duration_seconds=time.monotonic() - started,
            )
        duration = time.monotonic() - started
        evidence = _evidence(output)
        if output.exit_code not in self.success_exit_codes:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.FAILED,
                target=request.target,
                resolved_addresses=addresses,
                version=version,
                raw_evidence=evidence,
                error=_exit_error(self.name, output),
                exit_code=output.exit_code,
                termination=output.termination,
                duration_seconds=duration,
            )
        try:
            findings = self.parse(output, host, request_with_addresses)
        except (ParseError, ValueError) as exc:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.FAILED,
                target=request.target,
                resolved_addresses=addresses,
                version=version,
                raw_evidence=evidence,
                error=f"parse failed: {exc}",
                exit_code=output.exit_code,
                termination=output.termination,
                duration_seconds=duration,
            )
        if len(findings) > request.max_findings:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.FAILED,
                target=request.target,
                resolved_addresses=addresses,
                version=version,
                error=f"parsed findings exceed the {request.max_findings} finding limit",
                exit_code=output.exit_code,
                termination=output.termination,
                duration_seconds=duration,
            )
        return ScanResult(
            scanner=self.name,
            state=ExecutionState.LIVE,
            target=request.target,
            resolved_addresses=addresses,
            version=version,
            findings=findings,
            assets=[self.build_asset(host, request_with_addresses)],
            raw_evidence=evidence,
            exit_code=output.exit_code,
            termination=output.termination,
            duration_seconds=duration,
        )


def _termination_of(exc: BaseException) -> TerminationReport:
    """Return the structured reason a failed execution carries, or derive one."""
    report = getattr(exc, "report", None)
    if isinstance(report, TerminationReport):
        return report
    # The only remaining case is the adapter's own overall-deadline TimeoutError,
    # raised before the process was started rather than by the runner.
    cause = (
        TerminationCause.TIMEOUT
        if isinstance(exc, TimeoutError)
        else TerminationCause.START_FAILED
    )
    return TerminationReport(cause=cause, detail=str(exc), limit="deadline_seconds")


def _exit_error(scanner: str, output: CommandOutput) -> str:
    """Explain a non-success exit, naming the signal or limit when there was one."""
    report = output.termination
    if report is not None and report.cause is not TerminationCause.COMPLETED and report.detail:
        return f"{scanner} did not complete: {report.detail}"
    return f"{scanner} exited with non-success status {output.exit_code}"


# The value is one non-space run, but an ``Authorization`` header carries the
# secret *after* a scheme word (``Bearer <token>``, ``Basic <b64>``): allow one
# optional known auth scheme before the credential so the token itself — not
# just the scheme name — is what gets redacted. Only enumerated schemes are
# consumed, so a secret followed by unrelated text is not over-redacted.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|cookie|credential|password|secret|token|api[-_]?key|access[-_]?key)"
    r"(\s*[:=]\s*)"
    r"((?:(?:bearer|basic|digest|negotiate|ntlm|token|apikey)\s+)?[^\s,;]+)"
)
def _evidence(output: CommandOutput) -> str:
    parts = []
    if output.stdout.strip():
        parts.append(output.stdout.strip())
    if output.stderr.strip():
        parts.append("[stderr]\n" + output.stderr.strip())
    value = "\n".join(parts)
    value = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", value)
    return redact_text(value)[:MAX_RAW_EVIDENCE]


def _safe_line(value: str, maximum: int) -> str:
    return " ".join(value.replace("\x00", "").split())[:maximum]
