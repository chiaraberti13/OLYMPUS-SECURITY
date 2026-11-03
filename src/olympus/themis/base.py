"""Shared policy and process boundary for real Themis scanner adapters."""

from __future__ import annotations

import hashlib
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace

from olympus.core.execution import (
    Cancellation,
    ExecutionPolicy,
    NeverCancelled,
    redact_arguments,
    redact_text,
    redact_url,
)
from olympus.core.models import Asset, Finding
from olympus.themis.model import (
    MAX_RAW_EVIDENCE,
    Dependency,
    OutputDigests,
    ScanRequest,
    ScanResult,
)
from olympus.themis.runner import (
    CommandError,
    CommandOutput,
    CommandTimeout,
    TerminationCause,
    TerminationReport,
    run_command,
    which,
)
from olympus.themis.scope import ensure_allowed, resolve_and_validate, socket_resolver
from olympus.themis.states import ExecutionState


class NotAuthorizedError(RuntimeError):
    """Raised when a real scan is requested without explicit authorization."""


class ParseError(RuntimeError):
    """Raised by an adapter when the scanner's output cannot be parsed."""


#: Maximum structural nesting accepted from any scanner's JSON output. CPython's
#: ``json`` decoder recurses on nested arrays and objects, so an adversarial
#: report with thousands of nested containers can exhaust the interpreter stack
#: (``RecursionError``) or burn CPU before a single finding is produced. Every
#: JSON/JSONL adapter shares this bound so the limit cannot drift between them.
MAX_JSON_DEPTH = 64


def check_json_depth(text: str, *, limit: int = MAX_JSON_DEPTH, scanner: str = "scanner") -> None:
    """Reject structurally deep JSON before it reaches Python's recursive decoder.

    Only brackets *outside* string literals are counted, so a value that merely
    contains ``[`` or ``{`` characters is never mistaken for nesting. Treating
    scanner output as hostile, this runs ahead of :func:`json.loads` to bound the
    work regardless of what a compromised or malicious target emits.
    """
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                raise ParseError(f"{scanner} JSON exceeds the {limit}-level depth limit")
        elif char in "]}":
            depth -= 1


@dataclass(frozen=True)
class PresenceResult:
    """Whether an engine's executable is installed on this host (no network).

    A probe only inspects ``PATH`` and asks the executable for its version through
    the sandboxed runner. It never contacts a target and never reads the
    environment for secrets, so it is safe to run before any scope or
    authorization decision.
    """

    engine: str
    present: bool
    path: str | None = None
    version: str | None = None
    #: Why the engine counts as absent (missing, or found but not the right tool).
    detail: str = ""
    #: The exact command an operator can run to install it.
    install: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "engine": self.engine,
            "present": self.present,
            "path": self.path,
            "version": self.version,
            "detail": self.detail,
            "install": self.install,
        }


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
        return f"AST-THEMIS-{digest}"

    def build_asset(self, host: str, request: ScanRequest) -> Asset:
        """Return a shared asset representing the scanned target."""
        from olympus.core.enums import AssetType, Source

        kind = AssetType.URL if request.target_kind == "url" else AssetType.HOST
        return Asset(
            asset_id=self.asset_id(host),
            asset_type=kind,
            hostname=host,
            ip_addresses=list(request.resolved_addresses),
            source=Source.THEMIS,
            tags=["themis", self.name],
        )

    def resolve(self, host: str) -> tuple[str, ...]:
        """Injected seam for the system DNS resolver."""
        return socket_resolver(host)

    @staticmethod
    def add_finding(findings: list[Finding], finding: Finding, request: ScanRequest) -> None:
        """Append without ever allocating beyond the configured finding cap."""
        if len(findings) >= request.max_findings:
            raise ParseError(f"scanner output exceeds the {request.max_findings} finding limit")
        findings.append(finding)

    def version(self, request: ScanRequest, timeout: float) -> str | None:
        """Return a bounded scanner version string, or ``None`` if undetermined."""
        return self._detect_version(
            timeout, min(request.max_output_bytes, 65_536), request.cancellation
        )

    def _detect_version(
        self, timeout: float, max_output_bytes: int, cancellation: Cancellation
    ) -> str | None:
        path = which(self.binary)
        if not path:
            return None
        for flag in ("--version", "-version", "-V"):
            try:
                output = run_command(
                    [self.binary, flag],
                    timeout=min(timeout, 15.0),
                    max_output_bytes=max_output_bytes,
                    cancellation=cancellation,
                )
            except (CommandError, CommandTimeout):
                continue
            if output.exit_code not in self.success_exit_codes:
                continue
            lines = (output.stdout or output.stderr).strip().splitlines()
            if lines:
                return _safe_line(lines[0], 500)
        return path

    def recognises(self, version_output: str) -> bool:
        """Return whether ``version_output`` really comes from this engine.

        The default accepts anything. Engines whose executable name collides with
        an unrelated tool (``httpx`` is also the Python HTTP library's CLI) override
        this so :meth:`probe` cannot report the wrong program as present.
        """
        return True

    def probe(self, timeout: float = 15.0) -> PresenceResult:
        """Report whether the engine is installed, without any network access.

        Run by the preflight *before* any scope check or live operation, so a
        missing mandatory engine aborts a run before a single packet is sent.
        """
        path = which(self.binary)
        if not path:
            return PresenceResult(
                engine=self.name,
                present=False,
                detail=f"'{self.binary}' is not on PATH",
                install=self.install,
            )
        version = self._detect_version(timeout, 65_536, NeverCancelled())
        if version is not None and not self.recognises(version):
            return PresenceResult(
                engine=self.name,
                present=False,
                path=path,
                version=version,
                detail=f"'{self.binary}' on PATH is not the {self.name} engine",
                install=self.install,
            )
        return PresenceResult(
            engine=self.name, present=True, path=path, version=version, install=self.install
        )

    def failure_hint(self, output: CommandOutput) -> str | None:
        """Return actionable guidance for a non-zero exit, or ``None``.

        Engines die in engine-specific ways (no templates, out of memory under the sandbox
        limit); the operator should read what to change, not just "exited with status 2".
        """
        return None

    def coverage_loss(self, output: CommandOutput, request: ScanRequest) -> str | None:
        """Return why this run covered less than requested, or ``None`` if complete.

        Called after a successful parse. Adapters override it when the engine can
        exit 0 while silently skipping work (templates that failed to load, hosts
        that timed out). The default reports no loss, so existing adapters keep
        their current behaviour until they opt in.
        """
        return None

    def simulate(self, host: str, request: ScanRequest) -> list[Finding]:
        """Return clearly-labelled illustrative findings (SIMULATION only)."""
        from olympus.core.enums import Severity, Source

        return [
            Finding(
                asset_id=self.asset_id(host),
                source=Source.THEMIS,
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
            diagnostic=f"olympus themis deps (checks '{self.binary}' on PATH)",
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
            policy.require_authorization(f"Themis {self.name} live scan")
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
                    "live scanning is disabled; set THEMIS_ENABLE_LIVE_SCANS=true for a real "
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
                raise TimeoutError("Themis overall execution deadline exceeded")
            return value

        version = self.version(request, remaining())
        policy.check_cancellation(request.cancellation)
        addresses = resolve_and_validate(
            host,
            allowed=request.allowed,
            allowed_cidrs=request.allowed_cidrs,
            required_cidrs=request.required_cidrs,
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
        command = tuple(redact_arguments(argv))
        digests = OutputDigests.of(output.stdout, output.stderr)
        if output.exit_code not in self.success_exit_codes:
            return ScanResult(
                scanner=self.name,
                state=ExecutionState.FAILED,
                target=request.target,
                resolved_addresses=addresses,
                version=version,
                raw_evidence=evidence,
                error=_exit_error(self.name, output, self.failure_hint(output)),
                exit_code=output.exit_code,
                termination=output.termination,
                duration_seconds=duration,
                argv=command,
                output_digests=digests,
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
                argv=command,
                output_digests=digests,
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
                argv=command,
                output_digests=digests,
            )
        lost = self.coverage_loss(output, request_with_addresses)
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
            partial=lost is not None,
            partial_reason=lost,
            argv=command,
            output_digests=digests,
        )


def _termination_of(exc: BaseException) -> TerminationReport:
    """Return the structured reason a failed execution carries, or derive one."""
    report = getattr(exc, "report", None)
    if isinstance(report, TerminationReport):
        return report
    # The only remaining case is the adapter's own overall-deadline TimeoutError,
    # raised before the process was started rather than by the runner.
    cause = (
        TerminationCause.TIMEOUT if isinstance(exc, TimeoutError) else TerminationCause.START_FAILED
    )
    return TerminationReport(cause=cause, detail=str(exc), limit="deadline_seconds")


def _exit_error(scanner: str, output: CommandOutput, hint: str | None = None) -> str:
    """Explain a non-success exit, naming the signal or limit when there was one."""
    report = output.termination
    if report is not None and report.cause is not TerminationCause.COMPLETED and report.detail:
        message = f"{scanner} did not complete: {report.detail}"
    else:
        message = f"{scanner} exited with non-success status {output.exit_code}"
    return f"{message}. {hint}" if hint else message


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


#: ANSI CSI/OSC escape sequences. Engines colour their banners even when piped (nuclei,
#: wafw00f), and ``translate``-style control stripping would leave their ``[34m`` tails.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")


def _safe_line(value: str, maximum: int) -> str:
    return " ".join(_ANSI.sub("", value).replace("\x00", "").split())[:maximum]
