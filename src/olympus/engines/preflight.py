"""Shared, fail-closed engine preflight — decide offline whether a scan may launch.

The preflight answers one question before any network is touched: *are the engines this
run needs actually here, and the right ones, at the pinned version?* It is the shared core
(``DEC-2``) that every interface can call ahead of a scan — today the ``olympus engines
preflight`` command and operators/CI gating automation; the CLI/API/Web/worker run paths
reuse the same verdict as they adopt it.

Two independent rules decide what "the engines this run needs" means (mirroring
``engine.toml``):

``mandatory``
    Core-path engines (``nmap``, ``nuclei``, ``httpx``). Always required, every run.
``explicitly named``
    An engine the caller asks for by name. Always required for that run.

A required engine that is not :meth:`~olympus.engines.doctor.EngineStatus.ok` — missing,
the wrong tool, a version/commit mismatch or a broken data pin — blocks the launch with
:data:`~olympus.core.exit_codes.ExitCode.ENGINE_MISSING` (8) and an audit record carrying
the exact, pinned install command (never a secret). ``api``/commercial engines can never be
required (they have no local artifact), so they never block.

All host inspection is injected through :class:`~olympus.engines.doctor.Environment`, so the
verdict is deterministic offline and never performs network or target I/O.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from olympus.core.exit_codes import ExitCode
from olympus.engines.commands import THEMIS_RUN, require_known
from olympus.engines.doctor import EngineState, EngineStatus, Environment, inspect_engine
from olympus.engines.loader import ManifestError, load_all, manifest_for
from olympus.engines.schema import EngineManifest


class UnknownEngineError(ValueError):
    """A caller named an engine that has no manifest (a usage error, not a missing tool)."""


@dataclass(frozen=True)
class PreflightVerdict:
    """The outcome of a preflight: what was required, and what (if anything) blocks."""

    exit_code: ExitCode
    required: tuple[str, ...]
    #: Required engines that are not usable; the run must not launch while this is non-empty.
    blocking: tuple[EngineStatus, ...]
    #: Optional engines that are missing but were tolerated via --allow-missing-engines:
    #: the run may proceed degraded (exit 5), never for a mandatory engine.
    degraded: tuple[EngineStatus, ...] = ()

    @property
    def ok(self) -> bool:
        return self.exit_code is ExitCode.OK

    @staticmethod
    def _engine_records(statuses: tuple[EngineStatus, ...]) -> list[dict[str, object]]:
        return [
            {
                "name": status.name,
                "state": status.state.value,
                "detail": status.detail,
                "install_command": status.install_command,
            }
            for status in statuses
        ]

    def audit_metadata(self) -> dict[str, object]:
        """Redacted audit record: which engines were required, which blocked and which were
        tolerated as degraded, with the exact install command for each gap. No secret, no target."""
        return {
            "required_engines": list(self.required),
            "blocking_engines": self._engine_records(self.blocking),
            "degraded_engines": self._engine_records(self.degraded),
        }


# --- versioned machine-readable report (TOOLS-4.1) -------------------------- #
# The JSON `engines preflight --format json` prints gates CI/automation before a
# scan launches, so it is a versioned Olympus contract (olympus.engine-preflight)
# rather than an ad-hoc dict: automation can pin schema_name/schema_version and
# reject an incompatible verdict instead of guessing.


class _ReportPart(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PreflightBlockingEngine(_ReportPart):
    name: str
    state: str
    detail: str
    install_command: str | None


def _report_engines(statuses: tuple[EngineStatus, ...]) -> list[PreflightBlockingEngine]:
    return [
        PreflightBlockingEngine(
            name=status.name,
            state=status.state.value,
            detail=status.detail,
            install_command=status.install_command,
        )
        for status in statuses
    ]


class EnginePreflightReport(BaseModel):
    # BaseModel (not OlympusModel) because this contract is past 1.0.0 and OlympusModel
    # pins schema_version to Literal["1.0.0"]; mirror its strict config.
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_name: Literal["olympus.engine-preflight"] = "olympus.engine-preflight"
    schema_version: Literal["1.1.0"] = "1.1.0"
    required: list[str]
    blocking: list[PreflightBlockingEngine]
    #: Optional engines tolerated as missing via --allow-missing-engines (additive in 1.1.0).
    degraded: list[PreflightBlockingEngine] = Field(default_factory=list)
    ready: bool
    exit_code: int


def build_preflight_report(verdict: PreflightVerdict) -> EnginePreflightReport:
    """Assemble the versioned, machine-readable preflight report from the verdict."""
    return EnginePreflightReport(
        required=list(verdict.required),
        blocking=_report_engines(verdict.blocking),
        degraded=_report_engines(verdict.degraded),
        ready=verdict.ok,
        exit_code=int(verdict.exit_code),
    )


def required_engines(
    manifests: dict[str, EngineManifest],
    named: Sequence[str],
    *,
    commands: Sequence[str] = (),
) -> tuple[str, ...]:
    """Return the engines a run needs: every ``mandatory`` engine, each named one, and
    every engine a running ``command`` requires via ``required_for_commands``.

    Raises :class:`UnknownEngineError` if a named engine has no manifest, so a typo or a
    reference to an engine Olympus does not govern fails loudly instead of silently
    checking nothing. The ``commands`` are engine-launching command ids (see
    :mod:`olympus.engines.commands`); an engine whose ``required_for_commands`` names one
    of them is demanded for that run even when the caller did not name it, closing the
    gap where a command's implicit engine dependency would otherwise go unchecked.
    """
    unknown = sorted(name for name in named if name not in manifests)
    if unknown:
        raise UnknownEngineError(", ".join(unknown))
    wanted = set(commands)
    mandatory = {name for name, manifest in manifests.items() if manifest.engine.mandatory}
    for_commands = {
        name
        for name, manifest in manifests.items()
        if wanted & set(manifest.engine.required_for_commands)
    }
    return tuple(sorted(mandatory | for_commands | set(named)))


def preflight(
    env: Environment,
    *,
    engines: Sequence[str] = (),
    commands: Sequence[str] = (),
    allow_missing: bool = False,
) -> PreflightVerdict:
    """Return the fail-closed verdict for a run that needs ``engines`` (plus the mandatory set
    and any engine a running ``command`` requires via ``required_for_commands``).

    With ``allow_missing`` the operator accepts running **degraded**: an *optional* engine
    that is missing is reported as degraded (exit 5) instead of blocking, so the run may
    proceed without it. A **mandatory** engine (``nmap``/``nuclei``/``httpx``) always blocks
    (exit 8), even with the opt-in — the baseline is never waived.

    Offline and side-effect free: it inspects the host only through ``env`` (injected
    ``which``/``probe``/``git_head``), never the network or a target.
    """
    manifests = load_all()
    required = required_engines(manifests, engines, commands=commands)
    mandatory = {name for name, manifest in manifests.items() if manifest.engine.mandatory}
    statuses = [inspect_engine(name, manifests[name], env) for name in required]
    # An ``api``/commercial engine can never be required, so a REQUIRES_PRODUCT status is
    # never blocking; everything else that is not PRESENT blocks the launch.
    unusable = tuple(
        status
        for status in statuses
        if not status.ok and status.state is not EngineState.REQUIRES_PRODUCT
    )
    if allow_missing:
        blocking = tuple(s for s in unusable if s.name in mandatory)
        degraded = tuple(s for s in unusable if s.name not in mandatory)
    else:
        blocking = unusable
        degraded = ()
    if blocking:
        exit_code = ExitCode.ENGINE_MISSING
    elif degraded:
        exit_code = ExitCode.PARTIAL
    else:
        exit_code = ExitCode.OK
    return PreflightVerdict(
        exit_code=exit_code, required=required, blocking=blocking, degraded=degraded
    )


def preflight_for_scanner(
    env: Environment, scanner: str | None, *, allow_missing: bool = False
) -> PreflightVerdict:
    """Convenience wrapper: preflight a single Themis scan of ``scanner``.

    The requested scanner is required when Olympus governs it with a manifest; an
    ungoverned name (e.g. a test double) adds nothing to the mandatory set rather than
    raising, so callers on the scan path can preflight unconditionally. A Themis scan is
    the :data:`~olympus.engines.commands.THEMIS_RUN` command, so any engine declared
    ``required_for_commands = ["themis.run"]`` is demanded here too — automatically, on
    every scan path (CLI, worker, API, Web) that funnels through this wrapper.

    ``allow_missing`` is passed through: an optional engine may degrade (exit 5) while the
    mandatory baseline still blocks (exit 8). It is advisory on a readiness endpoint — the
    worker remains the fail-closed authority at run time.
    """
    try:
        governed = scanner is not None and scanner in load_all()
    except ManifestError:  # pragma: no cover - manifests ship with the package
        governed = False
    return preflight(
        env,
        engines=(scanner,) if governed and scanner else (),
        commands=(THEMIS_RUN,),
        allow_missing=allow_missing,
    )


def preflight_for_command(
    env: Environment, command_id: str, *, scanner: str | None = None
) -> PreflightVerdict:
    """Preflight the engines a governed ``command_id`` needs (fail-closed on an unknown id).

    Checks the mandatory set plus every engine whose ``required_for_commands`` names
    ``command_id`` (and the ``scanner`` when one is governed). Raises
    :class:`~olympus.engines.commands.UnknownCommandError` if ``command_id`` is not a
    command Olympus launches engines for, so an operator or CI gate cannot ask about a
    command that does not exist and read the empty answer as "ready".
    """
    require_known(command_id)
    try:
        governed = scanner is not None and scanner in load_all()
    except ManifestError:  # pragma: no cover - manifests ship with the package
        governed = False
    return preflight(
        env, engines=(scanner,) if governed and scanner else (), commands=(command_id,)
    )


def scanner_readiness(env: Environment, scanner: str) -> EngineStatus | None:
    """Full readiness of a *single* governed scanner, offline via the injected ``env``.

    Unlike :func:`preflight`, this checks **only** the named scanner (a single-scanner
    preview must not demand the whole mandatory baseline), but it is the *full*
    :func:`~olympus.engines.doctor.inspect_engine` check — binary presence, the right tool,
    version/commit against the pin **and** the pinned data dependencies (e.g. nuclei needs
    its templates at the pinned commit). Returns ``None`` when Olympus does not govern the
    scanner with a manifest, so a caller can treat an ungoverned name as "nothing to gate".
    """
    try:
        manifest = manifest_for(scanner)
    except (ManifestError, OSError):
        return None
    return inspect_engine(scanner, manifest, env)
