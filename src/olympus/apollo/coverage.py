"""ATT&CK detection-coverage matrix: technique -> telemetry -> rule (ROADMAP ``OPS-PURPLE``).

A detection rule that targets an ATT&CK technique is worthless if the telemetry
it needs is never ingested. This module answers the Purple-team question the
roadmap poses — *not merely "does a rule exist?" but "has the telemetry it needs
been produced and ingested?"* — by correlating three facts Olympus already holds:

* the techniques each :class:`~olympus.apollo.rules.DetectionRule` claims to cover
  (``mitre_attack``) and the single ``event_type`` it fires on;
* the event types actually present in a telemetry stream (what Apollo ingested);

and classifying every technique in the rule set as:

* ``covered`` — every rule targeting it fires on an event type that is present;
* ``partial`` — some but not all of its rules can fire (blind spots remain);
* ``no-telemetry`` — a rule targets it but none of the needed telemetry is present,
  so the technique is **undetectable** with the current data, however many rules
  exist on paper.

The analysis is pure, deterministic and offline. It never invents a technique for
which no rule exists (honest absence): a reference ATT&CK catalogue is out of
scope, so this measures the *detection set's* coverage against *available*
telemetry, exactly the gap that makes a rule silently blind.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from pydantic import ValidationError

from olympus.apollo.rules import DetectionRule
from olympus.core.models import Event

#: A MITRE ATT&CK (sub-)technique id, e.g. ``T1059`` or ``T1059.001``.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class CoverageStatus(StrEnum):
    """How well a technique is actually detectable given the telemetry present."""

    COVERED = "covered"
    PARTIAL = "partial"
    NO_TELEMETRY = "no-telemetry"


@dataclass(frozen=True)
class RuleCoverage:
    """One rule targeting a technique, and whether its telemetry is present."""

    rule_id: str
    event_type: str
    telemetry_present: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "event_type": self.event_type,
            "telemetry_present": self.telemetry_present,
        }


@dataclass(frozen=True)
class TechniqueCoverage:
    """Detection coverage for one ATT&CK technique."""

    technique: str
    status: CoverageStatus
    rules: tuple[RuleCoverage, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "technique": self.technique,
            "status": self.status.value,
            "rules": [rule.to_dict() for rule in self.rules],
        }


@dataclass(frozen=True)
class TelemetryIngestSummary:
    """Validity and completeness of the bounded telemetry input."""

    accepted: int = 0
    rejected: int = 0
    truncated: bool = False

    @property
    def complete(self) -> bool:
        return self.rejected == 0 and not self.truncated

    def to_dict(self) -> dict[str, object]:
        return {
            "status": "complete" if self.complete else "partial",
            "accepted": self.accepted,
            "rejected": self.rejected,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class CoverageReport:
    """The full technique coverage matrix plus the telemetry it was measured against."""

    techniques: tuple[TechniqueCoverage, ...]
    available_event_types: tuple[str, ...]
    telemetry_input: TelemetryIngestSummary = TelemetryIngestSummary()

    @property
    def counts(self) -> dict[str, int]:
        summary = dict.fromkeys((status.value for status in CoverageStatus), 0)
        for technique in self.techniques:
            summary[technique.status.value] += 1
        return summary

    @property
    def blind_spots(self) -> tuple[TechniqueCoverage, ...]:
        """Techniques with a rule but no telemetry — the hard detection gaps."""
        return tuple(t for t in self.techniques if t.status is CoverageStatus.NO_TELEMETRY)

    def to_dict(self) -> dict[str, object]:
        return {
            "available_event_types": list(self.available_event_types),
            "telemetry_input": self.telemetry_input.to_dict(),
            "summary": {"techniques": len(self.techniques), **self.counts},
            "techniques": [technique.to_dict() for technique in self.techniques],
        }


def assess_coverage(
    rules: Iterable[DetectionRule],
    available_event_types: Iterable[str],
    *,
    telemetry_input: TelemetryIngestSummary | None = None,
) -> CoverageReport:
    """Correlate detection rules with available telemetry into a coverage matrix.

    Deterministic: techniques and their rules are returned in sorted order, so the
    same rule set and telemetry always produce the same report.
    """
    present = set(available_event_types)
    by_technique: dict[str, list[RuleCoverage]] = {}
    for rule in rules:
        for technique in set(rule.mitre_attack):
            if not _TECHNIQUE_RE.match(technique):
                continue  # ignore malformed ids rather than fabricate a cell
            by_technique.setdefault(technique, []).append(
                RuleCoverage(rule.rule_id, rule.event_type, rule.event_type in present)
            )

    techniques: list[TechniqueCoverage] = []
    for technique in sorted(by_technique):
        rule_cov = tuple(sorted(by_technique[technique], key=lambda r: (r.rule_id, r.event_type)))
        detectable = sum(1 for rule in rule_cov if rule.telemetry_present)
        if detectable == 0:
            status = CoverageStatus.NO_TELEMETRY
        elif detectable == len(rule_cov):
            status = CoverageStatus.COVERED
        else:
            status = CoverageStatus.PARTIAL
        techniques.append(TechniqueCoverage(technique, status, rule_cov))

    return CoverageReport(
        tuple(techniques), tuple(sorted(present)), telemetry_input or TelemetryIngestSummary()
    )


def event_types_from_events(events: Iterable[Event]) -> set[str]:
    """Return the distinct event types present in a telemetry stream."""
    return {event.event_type for event in events}


def parse_telemetry_ndjson(
    text: str, *, max_lines: int = 1_000_000
) -> tuple[set[str], TelemetryIngestSummary]:
    """Validate a bounded NDJSON stream and report rejects/truncation explicitly."""
    if not 1 <= max_lines <= 10_000_000:
        raise ValueError("max_lines must be between 1 and 10000000")
    found: set[str] = set()
    accepted = rejected = 0
    truncated = False
    for number, line in enumerate(text.splitlines(), start=1):
        if number > max_lines:
            truncated = True
            break
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
            event = Event.model_validate(record)
        except (json.JSONDecodeError, RecursionError, ValidationError, TypeError, ValueError):
            rejected += 1
            continue
        found.add(event.event_type)
        accepted += 1
    return found, TelemetryIngestSummary(accepted, rejected, truncated)


def event_types_from_ndjson(text: str, *, max_lines: int = 1_000_000) -> set[str]:
    """Return only contract-valid event types from bounded NDJSON input."""
    found, _summary = parse_telemetry_ndjson(text, max_lines=max_lines)
    return found


__all__ = [
    "CoverageReport",
    "CoverageStatus",
    "RuleCoverage",
    "TechniqueCoverage",
    "TelemetryIngestSummary",
    "assess_coverage",
    "event_types_from_events",
    "event_types_from_ndjson",
    "parse_telemetry_ndjson",
]
