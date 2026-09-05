"""How far each scanner integration has actually been validated.

:mod:`olympus.integrations.capabilities` answers "can this engine run *here,
right now?*" — a question about the current machine. This module answers a
different and, for an honest catalogue, more important one: **how far has the
project itself taken this integration?** A binary installed on the operator's
laptop says nothing about whether Olympus owns a parser for it, whether that
parser was ever exercised against recorded output, or whether the pair was ever
run against a real engine.

The two axes are deliberately independent. An engine can be `live-tested` by
the project and still `dependency-missing` on this host; another can be
`available` here and remain `catalog-only`, because a `ScannerSpec` is a
product-catalogue entry, not an implementation.

The ladder, from least to most validated:

``catalog-only``
    A :class:`~olympus.integrations.scanners.ScannerSpec` exists. Nothing
    executes. This is the honest state of most of the catalogue.
``adapter-ready``
    A native adapter is registered in :mod:`olympus.aegis.registry`: Olympus can
    build the command line and has parser code. Neither has been proven.
``offline-tested``
    The parser is exercised against recorded real output, so a regression in it
    fails the build.
``live-tested``
    The adapter was run end to end against a real engine in an authorized lab
    and the captured evidence is committed.
``production-ready``
    Live-tested **and** the whole Definition of Done is met — evidence manifest
    with digests, SBOM, vulnerability scan, documented version compatibility.

Declarations are not taken on trust. :func:`verify_declarations` re-derives what
the repository can prove and reports every claim that outruns it; a unit test
asserts the result is empty, so this ledger cannot quietly drift into marketing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from olympus.aegis.registry import implemented
from olympus.integrations.scanners import REGISTRY


class Maturity(StrEnum):
    """How far the project has validated one integration."""

    CATALOG_ONLY = "catalog-only"
    ADAPTER_READY = "adapter-ready"
    OFFLINE_TESTED = "offline-tested"
    LIVE_TESTED = "live-tested"
    PRODUCTION_READY = "production-ready"


#: The ladder in order. Index doubles as the comparison key.
LADDER: tuple[Maturity, ...] = (
    Maturity.CATALOG_ONLY,
    Maturity.ADAPTER_READY,
    Maturity.OFFLINE_TESTED,
    Maturity.LIVE_TESTED,
    Maturity.PRODUCTION_READY,
)


def rank(stage: Maturity) -> int:
    """Return the ladder position of ``stage``, so stages can be compared."""
    return LADDER.index(stage)


def at_least(stage: Maturity, minimum: Maturity) -> bool:
    """Return whether ``stage`` reaches ``minimum`` on the ladder."""
    return rank(stage) >= rank(minimum)


@dataclass(frozen=True)
class MaturityRecord:
    """One declared stage and the evidence backing it."""

    name: str
    stage: Maturity
    #: Repository-relative path proving the claim. Empty only for catalog-only.
    evidence: str = ""
    #: Why the integration sits here and not one rung higher.
    blocker: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "maturity": self.stage.value,
            "maturity_rank": rank(self.stage),
            "evidence": self.evidence or None,
            "blocker": self.blocker or None,
        }


_OFFLINE_EVIDENCE = "tests/unit/test_aegis_execution.py"
_OFFLINE_EVIDENCE_PD = "tests/unit/test_aegis_adapters_projectdiscovery.py"
_OFFLINE_EVIDENCE_DC = "tests/unit/test_aegis_adapters_dirsearch_commix.py"
_LIVE_EVIDENCE = "docs/aegis-execution-evidence.md"

#: Where parser tests live. Adapters are grouped by family rather than piled
#: into one module, so the check scans the whole unit suite instead of pinning
#: a single file and forcing every future adapter into it.
_TEST_ROOT = "tests/unit"

#: The declared ledger. Every entry above ``catalog-only`` is cross-checked by
#: :func:`verify_declarations` against what the repository actually contains.
#:
#: Nothing is ``production-ready`` yet, and saying so is the point of this
#: module: the Definition of Done (evidence manifest with digests, SBOM,
#: vulnerability scan, documented version compatibility) is not met for any
#: adapter, so claiming otherwise would be exactly the overpromise the ladder
#: exists to prevent.
DECLARED: dict[str, MaturityRecord] = {
    "nmap": MaturityRecord(
        "nmap",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "nikto": MaturityRecord(
        "nikto",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "wafw00f": MaturityRecord(
        "wafw00f",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "sqlmap": MaturityRecord(
        "sqlmap",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "testssl": MaturityRecord(
        "testssl",
        Maturity.OFFLINE_TESTED,
        _OFFLINE_EVIDENCE,
        "No authorized live run yet: the captured evidence covers the parser only.",
    ),
    "whatweb": MaturityRecord(
        "whatweb",
        Maturity.OFFLINE_TESTED,
        _OFFLINE_EVIDENCE,
        "No authorized live run yet: the captured run failed on a broken Ruby "
        "environment, so the adapter has never parsed real engine output.",
    ),
    "httpx": MaturityRecord(
        "httpx",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "nuclei": MaturityRecord(
        "nuclei",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "katana": MaturityRecord(
        "katana",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "dalfox": MaturityRecord(
        "dalfox",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "dirsearch": MaturityRecord(
        "dirsearch",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
    "commix": MaturityRecord(
        "commix",
        Maturity.LIVE_TESTED,
        _LIVE_EVIDENCE,
        "Definition of Done incomplete: no per-adapter evidence manifest or SBOM.",
    ),
}


def record_for(name: str) -> MaturityRecord:
    """Return the declared record for ``name``, defaulting to catalog-only."""
    declared = DECLARED.get(name)
    if declared is not None:
        return declared
    return MaturityRecord(
        name,
        Maturity.CATALOG_ONLY,
        "",
        "No native execution adapter in olympus.aegis.registry.",
    )


def _repository_root() -> Path:
    """Return the checkout root, or ``None``-ish when running from a wheel.

    The evidence files are repository artifacts, not packaged data. When Olympus
    runs from an installed wheel they are simply absent, and evidence existence
    is then unverifiable rather than false — see :func:`verify_declarations`.
    """
    return Path(__file__).resolve().parents[3]


def evidence_is_present(record: MaturityRecord) -> bool | None:
    """Return whether the evidence file exists, or ``None`` outside a checkout."""
    if not record.evidence:
        return None
    root = _repository_root()
    if not (root / "pyproject.toml").exists():
        return None  # installed wheel: nothing to check against
    return (root / record.evidence).exists()


def parser_test_is_present(name: str) -> bool | None:
    """Return whether a parser test exists for ``name``, or ``None`` off-checkout.

    ``offline-tested`` means "a regression in this parser fails the build", so
    the claim is only worth making if such a test is really there. The project
    convention is one ``test_<scanner>_parser*`` function per adapter, which is
    cheap to verify and hard to satisfy by accident. The whole unit suite is
    scanned, so adapters can be grouped by family without the check pinning
    them all to one module.
    """
    root = _repository_root()
    tests = root / _TEST_ROOT
    if not (root / "pyproject.toml").exists() or not tests.is_dir():
        return None
    needle = f"def test_{name}_parser"
    return any(
        needle in module.read_text(encoding="utf-8") for module in tests.glob("test_*.py")
    )


def verify_declarations() -> list[str]:
    """Return every declared claim the repository cannot back up.

    This is the guard that keeps the ladder honest. It checks that:

    * a declaration exists only for a catalogued scanner;
    * anything above ``catalog-only`` really has a registered adapter;
    * anything above ``catalog-only`` cites evidence, and that the cited file
      exists when we are running from a checkout;
    * nothing claims ``production-ready`` while the Definition of Done is open.

    An empty list means the catalogue promises exactly what it can execute.
    """
    problems: list[str] = []
    catalogued = {spec.name for spec in REGISTRY}
    adapters = set(implemented())

    for name, record in sorted(DECLARED.items()):
        if name not in catalogued:
            problems.append(f"{name}: declared but absent from the scanner catalogue")
            continue
        if record.stage is Maturity.CATALOG_ONLY:
            problems.append(
                f"{name}: declared catalog-only; leave it out of DECLARED instead"
            )
            continue
        if name not in adapters:
            problems.append(
                f"{name}: declared {record.stage.value} but has no native adapter"
            )
        if not record.evidence:
            problems.append(f"{name}: declared {record.stage.value} without evidence")
        elif evidence_is_present(record) is False:
            problems.append(
                f"{name}: evidence {record.evidence} does not exist in the repository"
            )
        if (
            at_least(record.stage, Maturity.OFFLINE_TESTED)
            and parser_test_is_present(name) is False
        ):
            problems.append(
                f"{name}: declared {record.stage.value} but "
                f"{_OFFLINE_EVIDENCE} has no test_{name}_parser* function"
            )
        if record.stage is Maturity.PRODUCTION_READY and record.blocker:
            problems.append(
                f"{name}: declared production-ready while still recording a blocker"
            )

    # An adapter that exists but is not declared would silently read as
    # catalog-only, understating the project rather than overstating it — still
    # a drift, and still worth failing on.
    for name in sorted(adapters - set(DECLARED)):
        problems.append(f"{name}: has a native adapter but no maturity declaration")

    return problems


def summary() -> dict[str, int]:
    """Return how many catalogued integrations sit at each stage."""
    counts = dict.fromkeys((stage.value for stage in LADDER), 0)
    for spec in REGISTRY:
        counts[record_for(spec.name).stage.value] += 1
    return counts
