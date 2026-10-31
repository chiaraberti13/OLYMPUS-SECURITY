"""Honest alignment of integrated-toolkit capabilities onto Olympus modules.

A commercial toolkit advertises product *capabilities* — a Website Scanner, a
Port Scanner, a Subdomain Finder — not individual engines. This module states,
for each such capability, which Olympus modules and engines back it and whether
Olympus actually delivers it, in three deliberately blunt states:

* ``present`` — Olympus genuinely provides the capability: a backing engine whose
  parser is proven against real output (maturity ``offline-tested`` or above), or
  a first-party module capability with committed tests.
* ``simulated`` — Olympus has the capability wired (a registered adapter,
  maturity ``adapter-ready``) but its parser is not yet proven against real
  output, so it is honest only in simulation, never as a verified result.
* ``missing`` — no Olympus coverage beyond, at most, a catalogue entry.

The state is **derived**, never asserted: engine coverage comes from the maturity
ledger (:mod:`olympus.integrations.maturity`) and native coverage from committed
test evidence, so the alignment cannot drift into marketing.
:func:`verify_catalog` re-derives what the repository can back and reports any
capability that references an unknown engine or cites missing evidence; a unit
test asserts it is empty, exactly as the maturity ledger is guarded.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from olympus.integrations.maturity import Maturity, at_least, rank, record_for
from olympus.integrations.scanners import REGISTRY


class CoverageState(StrEnum):
    """How completely Olympus delivers one suite capability."""

    PRESENT = "present"
    SIMULATED = "simulated"
    MISSING = "missing"


@dataclass(frozen=True)
class NativeCapability:
    """A first-party (non-scanner) module capability and its test evidence."""

    module: str
    purpose: str
    #: Repository-relative test file that exercises the capability.
    evidence: str


@dataclass(frozen=True)
class SuiteCapability:
    """One toolkit capability mapped onto the Olympus modules that back it."""

    capability_id: str
    title: str
    summary: str
    #: Olympus modules that contribute to this capability (for the reader).
    modules: tuple[str, ...]
    #: Scanner engines (names in the scanner registry) that back it.
    engines: tuple[str, ...] = ()
    #: First-party module capabilities that back it, with committed evidence.
    native: tuple[NativeCapability, ...] = ()
    #: Honest caveat: what is partial, detection-only or catalogued-not-adapted.
    note: str = ""


#: The declared alignment. Each capability maps to the engines/modules that
#: genuinely deliver *that* capability; lesser or detection-only coverage is
#: stated in ``note`` rather than inflating the engine list.
SUITE_CAPABILITIES: tuple[SuiteCapability, ...] = (
    SuiteCapability(
        capability_id="website-scanner",
        title="Website Vulnerability Scanner",
        summary="Crawl and test a web application for injection, XSS and misconfiguration.",
        modules=("themis", "artemis"),
        engines=(
            "nuclei",
            "nikto",
            "wapiti",
            "sqlmap",
            "dalfox",
            "xsstrike",
            "arjun",
            "commix",
            "dirsearch",
            "katana",
            "httpx",
        ),
        note="API-backed engines (zap, burp, acunetix) are catalogued only, not yet adapted.",
    ),
    SuiteCapability(
        capability_id="network-scanner",
        title="Network Vulnerability Scanner",
        summary="Authenticated network vulnerability scanning across hosts and services.",
        modules=("themis",),
        engines=("nessus", "openvas"),
        note="Open-/closed-source network vulnerability engines are catalogued but not adapted; "
        "port and service discovery is delivered separately by the port scanner (nmap).",
    ),
    SuiteCapability(
        capability_id="ssl-scanner",
        title="SSL/TLS Scanner",
        summary="Assess TLS protocols, ciphers and certificate issues on a host.",
        modules=("themis",),
        engines=("testssl",),
        note="testssl parser is proven against recorded output; no authorized live run yet.",
    ),
    SuiteCapability(
        capability_id="cms-scanner",
        title="CMS Scanner",
        summary="Detect CMS-specific vulnerabilities (e.g. WordPress plugins/themes).",
        modules=("themis",),
        engines=("wpscan",),
        note="CMS vulnerability scanning (wpscan) is catalogued only; CMS/technology "
        "detection is available via whatweb (offline-tested) under website fingerprinting.",
    ),
    SuiteCapability(
        capability_id="port-scanner",
        title="Port Scanner",
        summary="Discover open ports and services on in-scope hosts.",
        modules=("themis",),
        engines=("nmap",),
    ),
    SuiteCapability(
        capability_id="subdomain-finder",
        title="Subdomain Finder",
        summary="Enumerate subdomains of an in-scope domain from passive sources.",
        modules=("argus", "themis"),
        engines=("subfinder",),
        native=(
            NativeCapability(
                "argus",
                "Certificate Transparency subdomain discovery (crt.sh)",
                "tests/unit/test_argus_ct.py",
            ),
        ),
        note="Passive CT discovery is native and tested; subfinder is catalogued but not adapted.",
    ),
    SuiteCapability(
        capability_id="domain-finder",
        title="Domain / DNS Finder",
        summary="Resolve DNS records and registration data for an in-scope domain.",
        modules=("argus",),
        native=(
            NativeCapability(
                "argus", "Passive DNS/MX/SPF/DMARC recon", "tests/unit/test_argus_dns.py"
            ),
            NativeCapability(
                "argus", "RDAP/WHOIS registration lookup", "tests/unit/test_argus_whois.py"
            ),
        ),
    ),
    SuiteCapability(
        capability_id="password-auditor",
        title="Password Auditor",
        summary="Test services for weak, default or reused credentials.",
        modules=(),
        note="No Olympus module provides credential auditing; deliberately out of scope for now.",
    ),
)


def _repository_root() -> Path:
    """Return the checkout root (the evidence files are repository artifacts)."""
    return Path(__file__).resolve().parents[3]


def _native_evidence_ok(capability: SuiteCapability) -> bool | None:
    """Whether every native-evidence file exists, or ``None`` off a checkout."""
    if not capability.native:
        return None
    root = _repository_root()
    if not (root / "pyproject.toml").exists():
        return None  # installed wheel: repository test files are simply absent
    return all((root / native.evidence).exists() for native in capability.native)


def _best_engine_maturity(capability: SuiteCapability) -> Maturity:
    """Return the highest maturity among the capability's backing engines."""
    best = Maturity.CATALOG_ONLY
    for name in capability.engines:
        stage = record_for(name).stage
        if rank(stage) > rank(best):
            best = stage
    return best


def coverage_of(capability: SuiteCapability) -> CoverageState:
    """Derive the coverage state from engine maturity and native evidence.

    Native first-party coverage counts as ``present`` when its evidence exists
    (or cannot be checked from a wheel). Otherwise the strongest backing engine
    decides: a proven parser (``offline-tested`` or above) is ``present``, a bare
    registered adapter (``adapter-ready``) is ``simulated``, and anything less is
    ``missing``.
    """
    if capability.native and _native_evidence_ok(capability) is not False:
        return CoverageState.PRESENT
    best = _best_engine_maturity(capability)
    if at_least(best, Maturity.OFFLINE_TESTED):
        return CoverageState.PRESENT
    if at_least(best, Maturity.ADAPTER_READY):
        return CoverageState.SIMULATED
    return CoverageState.MISSING


def _capability_dict(capability: SuiteCapability) -> dict[str, object]:
    return {
        "capability_id": capability.capability_id,
        "title": capability.title,
        "summary": capability.summary,
        "coverage": coverage_of(capability).value,
        "modules": list(capability.modules),
        "engines": list(capability.engines),
        "best_engine_maturity": _best_engine_maturity(capability).value,
        "native": [
            {"module": native.module, "purpose": native.purpose} for native in capability.native
        ],
        "note": capability.note or None,
    }


def catalog_document() -> dict[str, object]:
    """Return the versioned, deterministic suite-capability alignment document."""
    capabilities = sorted(SUITE_CAPABILITIES, key=lambda item: item.capability_id)
    histogram = dict.fromkeys((state.value for state in CoverageState), 0)
    for capability in capabilities:
        histogram[coverage_of(capability).value] += 1
    return {
        "schema_name": "olympus.suite-capability-catalog",
        "schema_version": "1.0.0",
        "capabilities": [_capability_dict(capability) for capability in capabilities],
        "coverage": histogram,
    }


def verify_catalog() -> list[str]:
    """Return every alignment claim the repository cannot back up.

    * every referenced engine must exist in the scanner registry;
    * every native-capability evidence file must exist (when on a checkout);
    * capability ids must be unique.

    An empty list means the catalogue promises exactly what the code delivers.
    """
    problems: list[str] = []
    catalogued = {spec.name for spec in REGISTRY}
    seen: set[str] = set()
    for capability in SUITE_CAPABILITIES:
        if capability.capability_id in seen:
            problems.append(f"{capability.capability_id}: duplicate capability id")
        seen.add(capability.capability_id)
        for name in capability.engines:
            if name not in catalogued:
                problems.append(
                    f"{capability.capability_id}: engine {name!r} absent from the scanner catalogue"
                )
        if _native_evidence_ok(capability) is False:
            missing = [
                native.evidence
                for native in capability.native
                if not (_repository_root() / native.evidence).exists()
            ]
            problems.append(
                f"{capability.capability_id}: native evidence missing: {sorted(missing)}"
            )
    return problems


__all__ = [
    "SUITE_CAPABILITIES",
    "CoverageState",
    "NativeCapability",
    "SuiteCapability",
    "catalog_document",
    "coverage_of",
    "verify_catalog",
]
