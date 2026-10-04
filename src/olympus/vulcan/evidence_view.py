"""Interface-agnostic evidence browser for a finding (ROADMAP ``WEB-C``).

A finding is only as trustworthy as the material behind it, so an operator must
be able to walk from a finding to its evidence — and judge whether that evidence
is tamper-evident — identically from the CLI, the TUI or the Web UI. This module
is the single, tested place that projects a
:class:`~olympus.core.models.Finding`'s ``evidence`` list into a navigable view
that reuses Minerva's chain of custody, exactly as :mod:`olympus.vulcan.view` is
the single place that projects a finding into operator columns and
:mod:`olympus.vulcan.search` the single place that filters findings.

Two kinds of evidence reference can appear on a finding:

* a **structured** reference ``EVD-YYYY-NNNNN`` that names an
  :class:`~olympus.core.models.Evidence` record and, through Minerva, a
  tamper-evident chain of custody — its digest, the collection/transfer/
  analysis/archive events, and the ledger's signature state;
* an **inline** snippet an adapter attached directly (``scanner=nmap``,
  ``url=...``), which is target-influenced free text.

Everything shown here is defanged. Inline snippets and URIs are stripped of
terminal control sequences and passed through
:func:`~olympus.core.execution.redact_text`, and the raw bytes an evidence
reference points at are never read or printed — only its digest and custody
metadata — so browsing a finding's evidence can neither leak a secret nor let a
hostile target rewrite the operator's terminal (ROADMAP ``SEC-H``). Absence is
told honestly: an unresolved reference, a missing custody record, or an unsigned
or unverified ledger each render as themselves, never as a reassuring blank.

The chain-of-custody signature surfaced here is the Minerva ledger's
``HMAC-SHA256`` head signature (see :mod:`olympus.minerva.custody`); a verified
custody timeline can additionally be exported and Ed25519-signed with
``olympus minerva timeline --export --sign-key`` for third-party verification.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from olympus.core.execution import redact_text
from olympus.core.models import Evidence, Finding
from olympus.minerva.custody import CustodyEntry, CustodyRecord
from olympus.vulcan.view import ABSENT

#: A finding evidence reference that names a structured Evidence record.
EVIDENCE_ID_RE = re.compile(r"^EVD-\d{4}-\d{5}$")

#: Control characters a hostile target could smuggle into an inline evidence
#: snippet or a URI to corrupt a terminal or forge a log line (mirrors
#: :data:`olympus.helios.scanner._CONTROL_CHARACTERS`).
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(text: str) -> str:
    """Render target-influenced text safely: no control bytes, URL secrets redacted.

    The order matters: control bytes are removed first so a smuggled escape can
    neither split a URL away from :func:`redact_text` nor survive into the
    output, then URL query secrets are redacted.
    """
    return redact_text(_CONTROL_CHARACTERS.sub("", text)).strip()


def _custody_digest(record: CustodyRecord) -> str | None:
    """Return the evidence digest a custody event anchors, if the format carries one.

    Only the v2 :class:`CustodyEntry` anchors an ``evidence_sha256``; a read-only
    legacy v1 entry does not, so this returns ``None`` for it rather than inventing
    a digest.
    """
    return record.evidence_sha256 if isinstance(record, CustodyEntry) else None


@dataclass(frozen=True)
class CustodyEventView:
    """One chain-of-custody event for an evidence reference, presentation-ready."""

    sequence: int
    action: str
    actor: str
    occurred_at: str
    digest: str | None


@dataclass(frozen=True)
class EvidenceItemView:
    """A navigable projection of one evidence reference carried by a finding.

    ``structured`` tells inline snippets apart from ``EVD-YYYY-NNNNN`` references.
    For an inline snippet only ``label`` is meaningful (the safe-rendered text).
    For a structured reference the resolution fields describe the
    :class:`~olympus.core.models.Evidence` record and its Minerva custody chain;
    any field the inputs do not resolve stays ``None``/empty rather than a
    fabricated value, so "absent" never reads like "verified".
    """

    label: str
    structured: bool
    evidence_id: str | None = None
    evidence_type: str | None = None
    uri: str | None = None
    digest: str | None = None
    in_ledger: bool = False
    custody: tuple[CustodyEventView, ...] = ()
    #: ``True``/``False`` when both a record digest and a custody digest exist and
    #: can be compared; ``None`` when the match is simply unknowable (no record,
    #: no custody digest, or a legacy ledger).
    digest_matches_custody: bool | None = None

    def integrity(self) -> str:
        """A one-word custody verdict for a compact table cell."""
        if not self.structured:
            return "inline"
        if not self.in_ledger:
            return "no-custody"
        if self.digest_matches_custody is True:
            return "anchored"
        if self.digest_matches_custody is False:
            return "digest-mismatch"
        return "in-custody"

    def detail(self) -> dict[str, object]:
        """Full, JSON-serialisable projection of this evidence reference."""
        return {
            "label": self.label,
            "structured": self.structured,
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "uri": self.uri,
            "digest": self.digest,
            "in_ledger": self.in_ledger,
            "integrity": self.integrity(),
            "digest_matches_custody": self.digest_matches_custody,
            "custody": [
                {
                    "sequence": event.sequence,
                    "action": event.action,
                    "actor": event.actor,
                    "occurred_at": event.occurred_at,
                    "digest": event.digest,
                }
                for event in self.custody
            ],
        }


@dataclass(frozen=True)
class FindingEvidenceView:
    """A finding's evidence projected for navigation across every interface.

    Holds the finding, the resolved evidence items, and the custody ledger's
    signature posture (``signed``/``signature_verified``/``evidence_anchored``)
    so a consumer can state plainly how trustworthy the chain behind the finding
    is without re-reading the ledger.
    """

    finding: Finding
    items: tuple[EvidenceItemView, ...]
    signed: bool = False
    signature_verified: bool = False
    evidence_anchored: bool = True

    def custody_signature(self) -> str:
        """A human label for the ledger's chain-of-custody signature posture."""
        if not self.evidence_anchored:
            return "legacy ledger (not digest-anchored)"
        if self.signed and self.signature_verified:
            return "HMAC-SHA256 signature verified"
        if self.signed:
            return "SIGNED but not verified (no key)"
        return "unsigned"

    def rows(self) -> list[dict[str, str]]:
        """Compact, table-ready cells, one per evidence reference."""
        rows: list[dict[str, str]] = []
        for item in self.items:
            rows.append(
                {
                    "kind": "structured" if item.structured else "inline",
                    "reference": item.evidence_id or item.label,
                    "type": item.evidence_type or ABSENT,
                    "digest": item.digest or ABSENT,
                    "custody": str(len(item.custody)) if item.structured else ABSENT,
                    "integrity": item.integrity(),
                }
            )
        return rows

    def detail(self) -> dict[str, object]:
        """Full, JSON-serialisable projection of the finding's evidence."""
        return {
            "finding_id": self.finding.finding_id,
            "title": self.finding.title,
            "evidence_anchored": self.evidence_anchored,
            "signed": self.signed,
            "signature_verified": self.signature_verified,
            "custody_signature": self.custody_signature(),
            "items": [item.detail() for item in self.items],
        }


#: Columns of the compact evidence list, in display order.
LIST_COLUMNS: tuple[str, ...] = (
    "kind",
    "reference",
    "type",
    "digest",
    "custody",
    "integrity",
)


def build_finding_evidence_view(
    finding: Finding,
    *,
    custody_records: Sequence[CustodyRecord] = (),
    evidence_records: Mapping[str, Evidence] | None = None,
    signed: bool = False,
    signature_verified: bool = False,
    evidence_anchored: bool = True,
) -> FindingEvidenceView:
    """Project a finding's ``evidence`` into a navigable, custody-aware view.

    ``custody_records`` are Minerva custody entries (already verified by
    :func:`olympus.minerva.custody.inspect_ledger`); ``evidence_records`` maps an
    ``EVD-YYYY-NNNNN`` id to its :class:`~olympus.core.models.Evidence` record.
    Both are optional: with neither, structured references still render honestly
    as "no custody record" rather than disappearing. The custody chain is matched
    by ``evidence_id`` and the input order of ``custody_records`` is preserved, so
    the verified sequence is shown as recorded.
    """
    records = evidence_records or {}
    items: list[EvidenceItemView] = []
    for reference in finding.evidence:
        reference = reference.strip()
        if not reference:
            continue
        if not EVIDENCE_ID_RE.fullmatch(reference):
            items.append(EvidenceItemView(label=_safe(reference), structured=False))
            continue

        evidence = records.get(reference)
        events = tuple(
            CustodyEventView(
                sequence=record.sequence,
                action=record.action.value,
                actor=_safe(record.actor),
                occurred_at=record.occurred_at.isoformat(),
                digest=_custody_digest(record),
            )
            for record in custody_records
            if record.evidence_id == reference
        )
        record_digest = evidence.sha256.lower() if evidence is not None else None
        custody_digests = {event.digest for event in events if event.digest is not None}
        matches: bool | None
        if record_digest is not None and custody_digests:
            matches = custody_digests == {record_digest}
        else:
            matches = None
        items.append(
            EvidenceItemView(
                label=reference,
                structured=True,
                evidence_id=reference,
                evidence_type=evidence.evidence_type if evidence is not None else None,
                uri=_safe(evidence.uri) if evidence is not None else None,
                digest=record_digest or (next(iter(custody_digests), None)),
                in_ledger=bool(events),
                custody=events,
                digest_matches_custody=matches,
            )
        )
    return FindingEvidenceView(
        finding=finding,
        items=tuple(items),
        signed=signed,
        signature_verified=signature_verified,
        evidence_anchored=evidence_anchored,
    )
