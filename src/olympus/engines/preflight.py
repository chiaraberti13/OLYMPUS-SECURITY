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

from olympus.core.exit_codes import ExitCode
from olympus.engines.doctor import EngineState, EngineStatus, Environment, inspect_engine
from olympus.engines.loader import ManifestError, load_all
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

    @property
    def ok(self) -> bool:
        return self.exit_code is ExitCode.OK

    def audit_metadata(self) -> dict[str, object]:
        """Redacted audit record: which engines were required and which blocked, with the
        exact install command for each gap. Contains no secret and no target."""
        return {
            "required_engines": list(self.required),
            "blocking_engines": [
                {
                    "name": status.name,
                    "state": status.state.value,
                    "detail": status.detail,
                    "install_command": status.install_command,
                }
                for status in self.blocking
            ],
        }


def required_engines(manifests: dict[str, EngineManifest], named: Sequence[str]) -> tuple[str, ...]:
    """Return the engines a run needs: every ``mandatory`` engine plus each named one.

    Raises :class:`UnknownEngineError` if a named engine has no manifest, so a typo or a
    reference to an engine Olympus does not govern fails loudly instead of silently
    checking nothing.
    """
    unknown = sorted(name for name in named if name not in manifests)
    if unknown:
        raise UnknownEngineError(", ".join(unknown))
    mandatory = {name for name, manifest in manifests.items() if manifest.engine.mandatory}
    return tuple(sorted(mandatory | set(named)))


def preflight(env: Environment, *, engines: Sequence[str] = ()) -> PreflightVerdict:
    """Return the fail-closed verdict for a run that needs ``engines`` (plus the mandatory set).

    Offline and side-effect free: it inspects the host only through ``env`` (injected
    ``which``/``probe``/``git_head``), never the network or a target.
    """
    manifests = load_all()
    required = required_engines(manifests, engines)
    statuses = [inspect_engine(name, manifests[name], env) for name in required]
    # An ``api``/commercial engine can never be required, so a REQUIRES_PRODUCT status is
    # never blocking; everything else that is not PRESENT blocks the launch.
    blocking = tuple(
        status
        for status in statuses
        if not status.ok and status.state is not EngineState.REQUIRES_PRODUCT
    )
    exit_code = ExitCode.ENGINE_MISSING if blocking else ExitCode.OK
    return PreflightVerdict(exit_code=exit_code, required=required, blocking=blocking)


def preflight_for_scanner(env: Environment, scanner: str | None) -> PreflightVerdict:
    """Convenience wrapper: preflight a single Themis scan of ``scanner``.

    The requested scanner is required when Olympus governs it with a manifest; an
    ungoverned name (e.g. a test double) adds nothing to the mandatory set rather than
    raising, so callers on the scan path can preflight unconditionally.
    """
    try:
        governed = scanner is not None and scanner in load_all()
    except ManifestError:  # pragma: no cover - manifests ship with the package
        governed = False
    return preflight(env, engines=(scanner,) if governed and scanner else ())
