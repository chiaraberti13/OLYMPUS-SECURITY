"""Per-scanner diagnostics: is this one engine actually runnable, and how proven?

``olympus aegis doctor`` answers a question about the whole AEGIS runtime. This
module answers it one scanner at a time — "can Olympus run *nmap* here, what
version, and how far has the project validated it?" — which is what an operator
needs before adding an engine to an engagement.

It composes the four facts Olympus already tracks separately, deliberately
keeping them distinct rather than collapsing them into a single pass/fail:

* **catalogued** — the engine is in :mod:`olympus.integrations.scanners`;
* **adapter** — Olympus owns a native execution adapter (:func:`implemented`);
* **runnable here** — the binary is on PATH (with its version), or, for API
  engines, the endpoint and secret variables are configured (names only, never
  their values);
* **maturity** — how far the project has validated the integration
  (:mod:`olympus.integrations.maturity`).

Every check is read-only and secret-safe. A binary's version is captured by
running ``<binary> <flag>`` with a fixed argv and no shell; an API engine's
configuration reports only *which* variables are set.
"""

from __future__ import annotations

import re
import shutil

from olympus.aegis.registry import implemented
from olympus.integrations.capabilities import API_CONFIGURATION, inspect
from olympus.integrations.diagnostics import Check, Report, binary_version
from olympus.integrations.maturity import record_for
from olympus.integrations.scanners import REGISTRY, ScannerSpec

#: Version flags to try, in order. Tools disagree: nmap wants ``--version``,
#: some Go tools want ``-version``, a few only answer ``-V``.
_VERSION_FLAGS = ("--version", "-version", "-V", "version")

#: Strips SGR colour escapes so a coloured version banner reads cleanly in JSON.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _spec(name: str) -> ScannerSpec | None:
    return next((spec for spec in REGISTRY if spec.name == name), None)


def scanner_names() -> list[str]:
    """Return every catalogued scanner name, sorted."""
    return sorted(spec.name for spec in REGISTRY)


def detect_version(binary: str) -> str | None:
    """Return a version string for ``binary``, trying several flags, or ``None``."""
    if not shutil.which(binary):
        return None
    path = shutil.which(binary)
    for flag in _VERSION_FLAGS:
        version = binary_version(binary, flag)
        # binary_version falls back to the path when a flag yields no output;
        # keep trying other flags before accepting the path as the answer.
        if version and version != path:
            return _ANSI.sub("", version).strip()
    return path


def _binary_check(spec: ScannerSpec) -> Check:
    if not shutil.which(spec.binary or ""):
        return Check(
            f"scanner:{spec.name}:binary",
            False,
            f"'{spec.binary}' not installed / not on PATH — install: {spec.install}",
            optional=True,
        )
    version = detect_version(spec.binary or "")
    return Check(f"scanner:{spec.name}:binary", True, f"{spec.binary}: {version}", optional=True)


def _api_check(spec: ScannerSpec) -> Check:
    required = API_CONFIGURATION.get(spec.name, ())
    if not required:
        return Check(
            f"scanner:{spec.name}:api",
            False,
            "no API configuration contract is known for this engine",
            optional=True,
        )
    import os

    missing = [name for name in required if not os.environ.get(name, "").strip()]
    if missing:
        # Secret-safe: name the variables that are unset, never any value.
        return Check(
            f"scanner:{spec.name}:api",
            False,
            f"configuration incomplete; set: {', '.join(missing)}",
            optional=True,
        )
    return Check(
        f"scanner:{spec.name}:api",
        True,
        f"configured ({', '.join(required)} present)",
        optional=True,
    )


def scanner_report(name: str) -> Report:
    """Build the full diagnostic report for one scanner.

    Raises :class:`KeyError` when ``name`` is not a catalogued scanner, so the
    CLI can turn an unknown name into a clean usage error.
    """
    spec = _spec(name)
    if spec is None:
        raise KeyError(name)

    report = Report(f"aegis doctor --scanner {name}")
    adapters = set(implemented())
    record = record_for(name)
    capability = inspect(spec)

    report.add(
        Check(f"scanner:{name}:catalogued", True, f"{spec.category} · {spec.kind}", optional=True)
    )
    report.add(
        Check(
            f"scanner:{name}:adapter",
            name in adapters,
            "native execution adapter present"
            if name in adapters
            else "no native adapter — this engine is catalogue-only",
            optional=True,
        )
    )
    # A binary engine is diagnosed by its executable; an API engine by its config.
    report.add(_binary_check(spec) if spec.binary is not None else _api_check(spec))
    report.add(
        Check(
            f"scanner:{name}:maturity",
            True,
            f"{record.stage.value}"
            + (f" — blocker: {record.blocker}" if record.blocker else ""),
            optional=True,
        )
    )
    report.add(
        Check(
            f"scanner:{name}:ready",
            capability.ready,
            "ready for a live job"
            if capability.ready
            else f"not ready: {capability.state.value}"
            + (f" (missing: {', '.join(capability.missing)})" if capability.missing else ""),
            optional=True,
        )
    )
    return report


def all_scanner_reports() -> list[Report]:
    """Build a report for every catalogued scanner, sorted by name."""
    return [scanner_report(name) for name in scanner_names()]
