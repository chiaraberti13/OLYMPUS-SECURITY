"""CMS version → advisory assessment (TOOLS-2, cms-scanner).

Artemis already names the CMS and its version from the single authorized response
(:mod:`olympus.artemis.fingerprint`). This module adds the honest next step: given
an **operator-provided** advisory feed — never a vulnerability invented or baked
into Olympus — it reports which advisories' affected version ranges contain the
detected version.

A match is a **version-based inference**: the installed version falls inside a
known-affected range. It is *not* a confirmation that the instance is
exploitable, because a backported fix, a disabled component or a compensating
control can change the real exposure. Findings are labelled accordingly and
carry ``Confidence.MEDIUM``.

The assessment is fully offline and deterministic: it sends no traffic, probes no
guessed paths and enumerates no plugins or themes (that is live CMS scanning —
``wpscan`` — and stays out of scope). It consumes the advisory feed the same way
Nemesis consumes a known-password list and Metis consumes a STIX bundle: the
operator supplies the data, Olympus supplies the vetted matching.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from olympus.artemis.fingerprint import Fingerprint
from olympus.core.enums import Confidence, Severity, Source
from olympus.core.models import Finding

#: Hard cap on advisories parsed from one feed, so a crafted file cannot grow the
#: assessment without bound.
MAX_ADVISORIES = 10_000

#: Fingerprint category that names a CMS (see ``fingerprint.Signature.category``).
_CMS_CATEGORY = "cms"


class CmsAdvisoryError(ValueError):
    """Raised when an advisory feed is malformed or a version is unparseable."""


@dataclass(frozen=True)
class CmsAdvisory:
    """One operator-supplied advisory and the version range it affects.

    The affected range is half-open ``[introduced, fixed)``: a version is in
    range when it is at least ``introduced`` (or no lower bound is set) and
    strictly below ``fixed`` (or no upper bound is set).
    """

    cms: str
    advisory_id: str
    title: str
    severity: Severity
    introduced: str | None = None
    fixed: str | None = None
    cves: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    remediation: str = ""

    def range_text(self) -> str:
        """Human-readable affected range, e.g. ``>= 4.7, < 4.7.2`` or ``< 5.1.1``."""
        lower = f">= {self.introduced}" if self.introduced else None
        upper = f"< {self.fixed}" if self.fixed else None
        return ", ".join(part for part in (lower, upper) if part) or "all versions"


@dataclass(frozen=True)
class CmsAssessment:
    """The outcome of a CMS version-advisory assessment."""

    findings: tuple[Finding, ...]
    assessed: tuple[tuple[str, str], ...] = field(default=())
    unversioned: tuple[str, ...] = field(default=())
    advisories_considered: int = 0


def _parse_version(raw: str) -> tuple[int, ...]:
    """Parse a dotted version into a comparable integer tuple.

    Each dot-separated component contributes its leading run of digits; parsing
    stops at the first component with no leading digit (so ``1.2.3-beta`` reads
    as ``(1, 2, 3)``). A version with no leading numeric component is rejected.
    """
    parts: list[int] = []
    for component in raw.strip().split("."):
        digits = ""
        for char in component:
            if char.isdigit():
                digits += char
            else:
                break
        if not digits:
            break
        parts.append(int(digits))
    if not parts:
        raise CmsAdvisoryError(f"unparseable version: {raw!r}")
    return tuple(parts)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Three-way compare two version tuples, zero-padding the shorter one."""
    width = max(len(a), len(b))
    a_padded = a + (0,) * (width - len(a))
    b_padded = b + (0,) * (width - len(b))
    return (a_padded > b_padded) - (a_padded < b_padded)


def version_in_range(version: str, introduced: str | None, fixed: str | None) -> bool:
    """Return whether ``version`` is in the half-open range ``[introduced, fixed)``."""
    parsed = _parse_version(version)
    above_lower = introduced is None or _cmp(parsed, _parse_version(introduced)) >= 0
    below_upper = fixed is None or _cmp(parsed, _parse_version(fixed)) < 0
    return above_lower and below_upper


def _str_tuple(value: Any, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CmsAdvisoryError(f"advisory {field_name} must be a list of strings")
    return tuple(value)


def _advisory_from_dict(entry: dict[str, Any]) -> CmsAdvisory:
    cms = entry.get("cms")
    advisory_id = entry.get("advisory_id")
    title = entry.get("title")
    if not isinstance(cms, str) or not cms.strip():
        raise CmsAdvisoryError("advisory 'cms' must be a non-empty string")
    if not isinstance(advisory_id, str) or not advisory_id.strip():
        raise CmsAdvisoryError("advisory 'advisory_id' must be a non-empty string")
    if not isinstance(title, str) or not title.strip():
        raise CmsAdvisoryError("advisory 'title' must be a non-empty string")
    try:
        severity = Severity(str(entry.get("severity", "medium")).lower())
    except ValueError as exc:
        raise CmsAdvisoryError(f"advisory '{advisory_id}' has an unknown severity") from exc
    introduced = entry.get("introduced")
    fixed = entry.get("fixed")
    for bound_name, bound in (("introduced", introduced), ("fixed", fixed)):
        if bound is not None:
            if not isinstance(bound, str):
                raise CmsAdvisoryError(f"advisory '{advisory_id}' {bound_name} must be a string")
            _parse_version(bound)  # validate it is a usable version, fail closed otherwise
    return CmsAdvisory(
        cms=cms.strip(),
        advisory_id=advisory_id.strip(),
        title=title.strip(),
        severity=severity,
        introduced=introduced,
        fixed=fixed,
        cves=_str_tuple(entry.get("cves"), "cves"),
        cwes=_str_tuple(entry.get("cwes"), "cwes"),
        references=_str_tuple(entry.get("references"), "references"),
        remediation=str(entry.get("remediation", "")),
    )


def load_advisories(text: str) -> tuple[CmsAdvisory, ...]:
    """Parse an operator-provided advisory feed (a JSON list or ``{"advisories": [...]}``).

    Raises :class:`CmsAdvisoryError` on malformed input, an unknown severity, an
    unparseable version bound, or more than :data:`MAX_ADVISORIES` entries.
    """
    try:
        document: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CmsAdvisoryError(f"invalid advisory JSON: {exc.msg}") from exc
    if isinstance(document, dict):
        document = document.get("advisories", [])
    if not isinstance(document, list):
        raise CmsAdvisoryError("advisory feed must be a JSON list or have an 'advisories' array")
    if len(document) > MAX_ADVISORIES:
        raise CmsAdvisoryError(f"advisory feed exceeds the {MAX_ADVISORIES} entry limit")
    advisories: list[CmsAdvisory] = []
    for entry in document:
        if not isinstance(entry, dict):
            raise CmsAdvisoryError("every advisory must be a JSON object")
        advisories.append(_advisory_from_dict(entry))
    return tuple(advisories)


def assess_cms(
    fingerprints: Iterable[Fingerprint],
    advisories: Sequence[CmsAdvisory],
    *,
    asset_id: str,
    url: str,
) -> CmsAssessment:
    """Match detected CMS versions against ``advisories`` and emit findings.

    Only ``cms``-category fingerprints are considered. A CMS detected without a
    version cannot be assessed and is reported in ``unversioned``. Findings are
    sorted deterministically by ``(cms, version, advisory_id)``.
    """
    assessed: list[tuple[str, str]] = []
    unversioned: list[str] = []
    findings: list[Finding] = []

    for fingerprint in fingerprints:
        if fingerprint.category != _CMS_CATEGORY:
            continue
        if not fingerprint.version:
            unversioned.append(fingerprint.product)
            continue
        try:
            _parse_version(fingerprint.version)
        except CmsAdvisoryError:
            unversioned.append(fingerprint.product)
            continue
        assessed.append((fingerprint.product, fingerprint.version))
        for advisory in advisories:
            if advisory.cms.lower() != fingerprint.product.lower():
                continue
            if not version_in_range(fingerprint.version, advisory.introduced, advisory.fixed):
                continue
            findings.append(_finding(asset_id, url, fingerprint, advisory))

    findings.sort(key=lambda item: item.title)
    return CmsAssessment(
        findings=tuple(findings),
        assessed=tuple(assessed),
        unversioned=tuple(dict.fromkeys(unversioned)),
        advisories_considered=len(advisories),
    )


def _finding(asset_id: str, url: str, fingerprint: Fingerprint, advisory: CmsAdvisory) -> Finding:
    product = fingerprint.product
    version = fingerprint.version or "?"
    return Finding(
        asset_id=asset_id,
        source=Source.ARTEMIS,
        title=f"{product} {version}: {advisory.title} ({advisory.advisory_id})",
        description=(
            f"{url} runs {product} {version}, which falls within the affected range "
            f"{advisory.range_text()} of advisory {advisory.advisory_id}. This is a "
            "version-based inference from the detected version, not a confirmation of "
            "exploitability: a backported fix, a disabled component or a compensating "
            "control can change the real exposure. No request beyond the single authorized "
            "fingerprint was sent; plugin and theme enumeration is out of scope."
        ),
        severity=advisory.severity,
        confidence=Confidence.MEDIUM,
        cve=list(advisory.cves),
        cwe=list(advisory.cwes),
        evidence=[
            fingerprint.evidence,
            f"detected version {version} in affected range {advisory.range_text()}",
        ],
        references=list(advisory.references),
        remediation=advisory.remediation,
        tags=["cms", "version-advisory"],
    )


__all__ = [
    "MAX_ADVISORIES",
    "CmsAdvisory",
    "CmsAdvisoryError",
    "CmsAssessment",
    "assess_cms",
    "load_advisories",
    "version_in_range",
]
