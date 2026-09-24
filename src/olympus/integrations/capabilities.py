"""Runtime capability inventory for the AEGIS professional control plane.

The catalogue deliberately separates four facts that older Olympus releases
collapsed into a single "scanner present" claim:

* catalogued: Olympus knows the engine and its deployment contract;
* adapted: Olympus owns an execution/parser adapter for the engine;
* available: the executable or API configuration is present;
* ready: adapted and available, therefore eligible for a live job.

A fifth fact travels alongside these and answers a different question:
``maturity`` (see :mod:`olympus.integrations.maturity`) says how far *the
project* has validated the integration — catalogue entry, registered adapter,
parser proven against recorded output, run against a real engine, or fully
production-ready. Readiness is about this host; maturity is about the code, and
an engine can be ready here while the project has never run it live.

No network request is made while building the inventory.  API-backed engines
are considered configured only when their endpoint and secret environment
variables are both present; connectivity is a separate, explicit health check.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum

from olympus.aegis.registry import implemented
from olympus.integrations.maturity import LADDER, Maturity, at_least, record_for
from olympus.integrations.scanners import REGISTRY, ScannerSpec


class CapabilityState(StrEnum):
    """Operational readiness of one scanner integration."""

    READY = "ready"
    ADAPTER_MISSING = "adapter-missing"
    DEPENDENCY_MISSING = "dependency-missing"
    CONFIGURATION_MISSING = "configuration-missing"


API_CONFIGURATION: dict[str, tuple[str, str]] = {
    "zap": ("AEGIS_ZAP_URL", "AEGIS_ZAP_API_KEY"),
    "openvas": ("AEGIS_OPENVAS_URL", "AEGIS_OPENVAS_TOKEN"),
    "nessus": ("AEGIS_NESSUS_URL", "AEGIS_NESSUS_TOKEN"),
    "burp": ("AEGIS_BURP_URL", "AEGIS_BURP_API_KEY"),
    "acunetix": ("AEGIS_ACUNETIX_URL", "AEGIS_ACUNETIX_API_KEY"),
}


@dataclass(frozen=True)
class Capability:
    """One honest, machine-readable AEGIS capability record."""

    name: str
    category: str
    purpose: str
    kind: str
    licence: str
    adapted: bool
    available: bool
    state: CapabilityState
    missing: tuple[str, ...] = ()
    maturity: Maturity = Maturity.CATALOG_ONLY
    #: Repository path backing the maturity claim; ``None`` for catalog-only.
    evidence: str | None = None
    #: What stands between this integration and the next rung of the ladder.
    blocker: str | None = None

    @property
    def ready(self) -> bool:
        return self.state is CapabilityState.READY

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "purpose": self.purpose,
            "kind": self.kind,
            "licence": self.licence,
            "adapted": self.adapted,
            "available": self.available,
            "ready": self.ready,
            "state": self.state.value,
            "missing": list(self.missing),
            "maturity": self.maturity.value,
            "evidence": self.evidence,
            "blocker": self.blocker,
        }


def inspect(spec: ScannerSpec, environment: dict[str, str] | None = None) -> Capability:
    """Inspect one engine without importing or contacting it."""
    env = environment if environment is not None else dict(os.environ)
    adapted = spec.name in set(implemented())
    missing: tuple[str, ...] = ()

    if spec.binary is not None:
        available = spec.available()
        if not adapted:
            state = CapabilityState.ADAPTER_MISSING
            missing = ("olympus-adapter",)
        elif not available:
            state = CapabilityState.DEPENDENCY_MISSING
            missing = (spec.binary,)
        else:
            state = CapabilityState.READY
    else:
        required = API_CONFIGURATION.get(spec.name, ())
        missing = tuple(name for name in required if not env.get(name, "").strip())
        available = bool(required) and not missing
        # API adapters are not registered yet; configuration alone must never
        # make the engine appear executable.
        if not adapted:
            state = CapabilityState.ADAPTER_MISSING
            missing = ("olympus-adapter", *missing)
        elif missing:
            state = CapabilityState.CONFIGURATION_MISSING
        else:
            state = CapabilityState.READY

    declared = record_for(spec.name)
    return Capability(
        name=spec.name,
        category=spec.category,
        purpose=spec.purpose,
        kind=spec.kind,
        licence=spec.licence,
        adapted=adapted,
        available=available,
        state=state,
        missing=missing,
        maturity=declared.stage,
        evidence=declared.evidence or None,
        blocker=declared.blocker or None,
    )


def inventory(environment: dict[str, str] | None = None) -> list[Capability]:
    """Return the complete deterministic capability inventory."""
    return [inspect(spec, environment) for spec in sorted(REGISTRY, key=lambda item: item.name)]


def count_at_least(minimum: Maturity, environment: dict[str, str] | None = None) -> int:
    """Return how many integrations reach ``minimum`` on the maturity ladder."""
    return sum(at_least(item.maturity, minimum) for item in inventory(environment))


def inventory_document(environment: dict[str, str] | None = None) -> dict[str, object]:
    """Return a versioned document suitable for CLI, API and CI readiness gates.

    Schema ``1.1.0`` adds the maturity axis: per-engine ``maturity``/``evidence``/
    ``blocker`` plus a ``maturity`` histogram, so a reader can tell "runnable on
    this host" from "validated by the project" without cross-referencing docs.
    """
    capabilities = inventory(environment)
    histogram = dict.fromkeys((stage.value for stage in LADDER), 0)
    for item in capabilities:
        histogram[item.maturity.value] += 1
    return {
        "schema_name": "olympus.aegis-capability-inventory",
        "schema_version": "1.1.0",
        "catalogued": len(capabilities),
        "adapted": sum(item.adapted for item in capabilities),
        "available": sum(item.available for item in capabilities),
        "ready": sum(item.ready for item in capabilities),
        "maturity": histogram,
        "capabilities": [item.to_dict() for item in capabilities],
    }
