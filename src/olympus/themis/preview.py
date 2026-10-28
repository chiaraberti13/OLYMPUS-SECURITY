"""Interface-agnostic safety preview for a planned Themis scan (ROADMAP ``UX-B``).

Before any scanner runs, an operator must be able to see — in one place and in
plain terms — exactly what is about to happen: the normalized target, whether
it matches the authorized scope, how intrusive the scanner is, which
authorization is in force, the resource budget, where output is written and
which external tool will be launched. ``UX-B`` requires this preview to be
shown *before* the run and to drive a proportionate confirmation.

This module is the single, interface-agnostic source of that preview, exactly
as :mod:`olympus.integrations.activity` is the single source of risk
classification: the CLI, the TUI and the web control plane render the same
:class:`SafetyPreview` instead of each re-deriving the decision, so the
"what am I about to do" answer cannot drift between interfaces.

It is pure and strictly offline. The scope check uses
:func:`olympus.themis.scope.ensure_allowed`, which validates host/domain/CIDR
authorization *without any network activity*; this module never resolves DNS.
When a definitive scope decision would require resolving a hostname at run time
(to catch rebinding / SSRF against the resolved address), the preview says so
honestly via :data:`ScopeDecision.RESOLUTION_REQUIRED` rather than pretending
the name is already cleared. Nothing here launches a process or contacts a
target; it only describes the planned run.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

from olympus.integrations.activity import (
    RISK_EXPLANATION,
    ActivityType,
    RiskClass,
    profile,
)
from olympus.integrations.scanners import by_name
from olympus.themis.application import ThemisRunRequest, ThemisScope
from olympus.themis.scope import (
    OutOfScopeError,
    SsrfBlockedError,
    TargetValidationError,
    ensure_allowed,
)


class ScopeDecision(StrEnum):
    """The static, offline scope verdict for the planned target.

    The ordering is by decreasing safety for the operator to launch:
    ``IN_SCOPE`` is cleared outright, ``RESOLUTION_REQUIRED`` is cleared by name
    but still checked against its resolved address at run time, and the rest
    must block the launch.
    """

    #: A literal IP authorized by an exact host entry or a CIDR. Final offline.
    IN_SCOPE = "in_scope"
    #: A hostname/domain authorized by name; the resolved-IP check is deferred
    #: to run time (it needs DNS, which this preview deliberately does not do).
    RESOLUTION_REQUIRED = "resolution_required"
    #: The target is definitively not covered by the engagement scope.
    OUT_OF_SCOPE = "out_of_scope"
    #: A non-global IP not explicitly authorized by IP/CIDR (SSRF guardrail).
    BLOCKED = "blocked"
    #: The target string itself is malformed and cannot be classified.
    INVALID = "invalid"


#: Plain-language explanation of each scope verdict, shown in the preview.
SCOPE_EXPLANATION: dict[ScopeDecision, str] = {
    ScopeDecision.IN_SCOPE: "The target address is explicitly authorized by the engagement scope.",
    ScopeDecision.RESOLUTION_REQUIRED: (
        "The target name matches the authorized scope; its resolved IP address is "
        "re-checked against the scope at run time before any traffic is sent."
    ),
    ScopeDecision.OUT_OF_SCOPE: (
        "The target is NOT covered by the engagement scope. The run would be refused."
    ),
    ScopeDecision.BLOCKED: (
        "The target is a non-global address not authorized by IP/CIDR. The run would be "
        "blocked by the SSRF guardrail."
    ),
    ScopeDecision.INVALID: "The target could not be parsed as a host, domain, or URL.",
}

#: Scope verdicts that must stop a launch rather than proceed to a run.
_BLOCKING_DECISIONS = frozenset(
    {ScopeDecision.OUT_OF_SCOPE, ScopeDecision.BLOCKED, ScopeDecision.INVALID}
)


@dataclass(frozen=True)
class SafetyPreview:
    """Everything an operator should read before authorizing one Themis run."""

    scanner: str
    scanner_known: bool
    target: str
    target_kind: str
    #: The canonical bare host, or ``None`` when the target is unparseable.
    normalized_host: str | None
    scope_decision: ScopeDecision
    scope_detail: str
    risk: RiskClass
    risk_explanation: str
    activity: ActivityType
    summary: str
    simulate: bool
    authorized: bool
    signed_manifest: bool
    lab_activation: bool
    authorization_detail: str
    #: True when the run should ask for an explicit, target-naming confirmation
    #: (``UX-B``): active/intrusive live runs, never passive or simulated ones.
    requires_confirmation: bool
    #: True when a blocking scope verdict means the run must not start at all.
    blocks_launch: bool
    timeout_seconds: float
    deadline_seconds: float
    max_output_bytes: int
    max_findings: int
    output_path: str | None
    audit_path: str | None
    #: The external tool that would be launched: a binary name, a remote-API
    #: marker, or an unknown-scanner marker. Readiness (is it on PATH?) is a
    #: separate concern owned by ``olympus themis doctor``; it is not re-derived
    #: here so the preview stays deterministic and environment-independent.
    external_tool: str
    #: The redacted argument vector the scanner *would* run (SEC-G dry-run), or
    #: ``None`` when it cannot be shown offline: a scanner with no native
    #: execution adapter (remote-API/unimplemented), or a blocked/invalid target
    #: for which no run is planned. Every token is passed through ``redact_url``
    #: (userinfo and query values stripped) and ``safe_terminal_text`` (control
    #: sequences neutralized), so a hostile target cannot leak a secret or forge
    #: terminal output into the preview. It is the *planned* command only — no
    #: process is launched and no DNS is resolved to produce it.
    planned_command: tuple[str, ...] | None

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner": self.scanner,
            "scanner_known": self.scanner_known,
            "target": self.target,
            "target_kind": self.target_kind,
            "normalized_host": self.normalized_host,
            "scope_decision": self.scope_decision.value,
            "scope_detail": self.scope_detail,
            "risk": self.risk.value,
            "risk_explanation": self.risk_explanation,
            "activity": self.activity.value,
            "summary": self.summary,
            "simulate": self.simulate,
            "authorized": self.authorized,
            "signed_manifest": self.signed_manifest,
            "lab_activation": self.lab_activation,
            "authorization_detail": self.authorization_detail,
            "requires_confirmation": self.requires_confirmation,
            "blocks_launch": self.blocks_launch,
            "timeout_seconds": self.timeout_seconds,
            "deadline_seconds": self.deadline_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_findings": self.max_findings,
            "output_path": self.output_path,
            "audit_path": self.audit_path,
            "external_tool": self.external_tool,
            "planned_command": list(self.planned_command)
            if self.planned_command is not None
            else None,
        }

    def lines(self) -> list[str]:
        """Render the preview as plain, colour-free labelled lines.

        Meaning never rides on colour alone (``UX-E``): every status is a word.
        """
        return [
            f"Scanner:        {self.scanner} ({self.external_tool})",
            f"Activity:       {self.activity.value}",
            f"Target:         {self.target} [{self.target_kind}]"
            + (f" -> {self.normalized_host}" if self.normalized_host else ""),
            f"Scope:          {self.scope_decision.value.upper()} — {self.scope_detail}",
            f"Risk:           {self.risk.value.upper()} — {self.risk_explanation}",
            f"Authorization:  {self.authorization_detail}",
            f"Budget:         timeout {self.timeout_seconds:g}s, "
            f"deadline {self.deadline_seconds:g}s, "
            f"max output {self.max_output_bytes} bytes, max findings {self.max_findings}",
            "Planned command: "
            + (
                " ".join(self.planned_command)
                if self.planned_command is not None
                else "(no native command: remote-API or unimplemented scanner)"
            ),
            f"Result output:  {self.output_path or '(not written to a file)'}",
            f"Audit log:      {self.audit_path or '(not written to a file)'}",
            f"Confirmation:   {'required' if self.requires_confirmation else 'not required'}",
            f"Launch:         {'BLOCKED' if self.blocks_launch else 'allowed'}",
        ]


def _scope_decision(
    request: ThemisRunRequest, scope: ThemisScope
) -> tuple[ScopeDecision, str | None]:
    """Classify the target against scope offline, returning the normalized host too."""
    try:
        host = ensure_allowed(
            request.target_kind,
            request.target,
            scope.allowed_hosts,
            scope.allowed_domains,
            scope.allowed_cidrs,
        )
    except SsrfBlockedError:
        return ScopeDecision.BLOCKED, None
    except OutOfScopeError:
        return ScopeDecision.OUT_OF_SCOPE, None
    except TargetValidationError:
        return ScopeDecision.INVALID, None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        # A hostname cleared by name; its resolved address is re-checked at run time.
        return ScopeDecision.RESOLUTION_REQUIRED, host
    return ScopeDecision.IN_SCOPE, host


def _authorization_detail(request: ThemisRunRequest) -> str:
    """Describe, in plain terms, which authorization is in force for the run."""
    if request.simulate:
        return "Simulation mode: no live traffic; no run-time authorization required."
    parts = ["Operator asserted authorization" if request.authorized else "NOT authorized"]
    if request.manifest_sha256 is not None:
        parts.append("backed by a signed engagement manifest")
    if request.lab_policy_sha256 is not None:
        parts.append("under a signed live-lab activation")
    return "; ".join(parts) + "."


def _planned_command(
    request: ThemisRunRequest, host: str | None, blocks_launch: bool
) -> tuple[str, ...] | None:
    """Return the redacted argv a native adapter would run, or ``None``.

    Strictly offline: it builds the argument vector with the adapter's
    :meth:`~olympus.themis.base.ScannerAdapter.build_argv` (which uses no I/O and
    does not resolve DNS), then redacts every token. ``None`` is returned when no
    run is planned (a blocking scope verdict or an unparseable target) or the
    scanner has no native execution adapter (remote-API or unimplemented).
    """
    if blocks_launch or host is None:
        return None
    # Lazy imports: the adapter registry pulls in the whole adapter chain, which
    # we must not import at module load (and only need on this offline path).
    from olympus.core.execution import redact_url, safe_terminal_text
    from olympus.themis.model import ScanRequest
    from olympus.themis.registry import UnknownScannerError, get_adapter

    try:
        adapter = get_adapter(request.scanner)
    except UnknownScannerError:
        return None
    try:
        scan_request = ScanRequest(
            scanner=request.scanner,
            target=request.target,
            target_kind=request.target_kind,
            timeout_seconds=request.timeout_seconds,
            deadline_seconds=request.deadline_seconds,
        )
        argv = adapter.build_argv(host, scan_request)
    except (ValueError, OSError):
        return None
    return tuple(safe_terminal_text(redact_url(token)) for token in argv)


def preview_run(request: ThemisRunRequest, scope: ThemisScope) -> SafetyPreview:
    """Compose the offline safety preview for a planned Themis run.

    ``scope`` is the already-loaded engagement scope (loaded offline by the
    caller, e.g. via :func:`olympus.themis.application.load_scope`). This
    function performs no I/O and contacts no target.
    """
    decision, normalized = _scope_decision(request, scope)

    activity_profile = profile(request.scanner)
    spec = by_name(request.scanner)
    if activity_profile is not None:
        risk = activity_profile.risk
        activity = activity_profile.activity
        summary = activity_profile.summary
        scanner_known = True
    else:
        # An unknown scanner is never understated: default to ACTIVE and say so.
        risk = RiskClass.ACTIVE
        activity = ActivityType.WEB
        summary = "Unrecognized scanner; treated as active until classified."
        scanner_known = False

    if spec is None:
        external_tool = "(unknown scanner)"
    elif spec.binary:
        external_tool = spec.binary
    else:
        external_tool = "(remote API service)"

    requires_confirmation = not request.simulate and risk in (RiskClass.ACTIVE, RiskClass.INTRUSIVE)

    return SafetyPreview(
        scanner=request.scanner,
        scanner_known=scanner_known,
        target=request.target,
        target_kind=request.target_kind,
        normalized_host=normalized,
        scope_decision=decision,
        scope_detail=SCOPE_EXPLANATION[decision],
        risk=risk,
        risk_explanation=RISK_EXPLANATION[risk],
        activity=activity,
        summary=summary,
        simulate=request.simulate,
        authorized=request.authorized,
        signed_manifest=request.manifest_sha256 is not None,
        lab_activation=request.lab_policy_sha256 is not None,
        authorization_detail=_authorization_detail(request),
        requires_confirmation=requires_confirmation,
        blocks_launch=decision in _BLOCKING_DECISIONS,
        timeout_seconds=request.timeout_seconds,
        deadline_seconds=request.deadline_seconds,
        max_output_bytes=request.max_output_bytes,
        max_findings=request.max_findings,
        output_path=str(request.output_path) if request.output_path is not None else None,
        audit_path=str(request.audit_path) if request.audit_path is not None else None,
        external_tool=external_tool,
        planned_command=_planned_command(request, normalized, decision in _BLOCKING_DECISIONS),
    )


__all__ = [
    "SCOPE_EXPLANATION",
    "SafetyPreview",
    "ScopeDecision",
    "preview_run",
]
