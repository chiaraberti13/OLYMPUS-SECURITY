"""Purple-team detection exercise: did the detections catch the attack? (ROADMAP ``PURPLE-1``).

A purple exercise closes the loop the roadmap draws for ``VAL-3`` — ATT&CK
technique → detection rule → telemetry → **outcome** — by asking the one question
structural coverage cannot: *when the attack's telemetry was replayed through the
detection set, did a rule actually fire?* This module is the pure, offline core
that decides it.

It is an honest **replay**, not exploitation: it performs no network activity and
attacks nothing. It takes the alerts a rule set produced against a bundle of
attack telemetry (evaluated by Apollo — the same engine, never a parallel one)
together with the ATT&CK techniques the attack was meant to exercise (the
red-team plan), and classifies each **planned** technique as:

* ``detected`` — at least one rule fired carrying that technique;
* ``missed`` — the technique was exercised but no rule fired on it: a real
  detection gap, never counted as detected because a rule exists "on paper".

Techniques detected that were **not** in the plan are reported separately
(``unexpected_detections``) rather than silently folded into the score. The
analysis is deterministic. Demonstrating detection against a *live* authorized
attack still needs the reproducible lab (``PURPLE-2``) and real execution; this
measures whether the deployed detections would have fired on the given telemetry.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from olympus.core.models import Alert

#: A MITRE ATT&CK (sub-)technique id, e.g. ``T1059`` or ``T1059.001``.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class DetectionResult(StrEnum):
    """Whether a planned technique was caught when its telemetry was replayed."""

    DETECTED = "detected"
    MISSED = "missed"


@dataclass(frozen=True)
class TechniqueOutcome:
    """One planned ATT&CK technique and whether the detection set fired on it."""

    technique: str
    result: DetectionResult
    #: Rule ids whose alert carried this technique (empty when ``missed``), sorted.
    fired_rules: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "technique": self.technique,
            "result": self.result.value,
            "fired_rules": list(self.fired_rules),
        }


@dataclass(frozen=True)
class PurpleExerciseReport:
    """The detection outcome of one replayed attack against a detection set."""

    outcomes: tuple[TechniqueOutcome, ...]
    #: Techniques detected that were not part of the plan (reported, not scored).
    unexpected_detections: tuple[str, ...]
    events_total: int
    alerts_total: int

    @property
    def detected(self) -> tuple[TechniqueOutcome, ...]:
        return tuple(o for o in self.outcomes if o.result is DetectionResult.DETECTED)

    @property
    def missed(self) -> tuple[TechniqueOutcome, ...]:
        """The detection gaps — planned techniques no rule fired on."""
        return tuple(o for o in self.outcomes if o.result is DetectionResult.MISSED)

    @property
    def has_gaps(self) -> bool:
        """Whether any planned technique went undetected."""
        return any(o.result is DetectionResult.MISSED for o in self.outcomes)

    @property
    def detection_rate(self) -> float:
        """detected / planned techniques; ``0.0`` when the plan is empty."""
        if not self.outcomes:
            return 0.0
        return round(len(self.detected) / len(self.outcomes), 4)

    def summary(self) -> dict[str, object]:
        return {
            "planned": len(self.outcomes),
            "detected": len(self.detected),
            "missed": len(self.missed),
            "detection_rate": self.detection_rate,
            "unexpected_detections": len(self.unexpected_detections),
            "events": self.events_total,
            "alerts": self.alerts_total,
            "has_gaps": self.has_gaps,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": self.summary(),
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
            "unexpected_detections": list(self.unexpected_detections),
            "limit": (
                "Detection replay against provided telemetry — not a live attack. A "
                "'detected' technique means a rule fired on the replayed events; proving "
                "detection against a live authorized attack needs the lab (PURPLE-2)."
            ),
        }


def _detected_techniques(alerts: Iterable[Alert]) -> dict[str, set[str]]:
    """Map each ATT&CK technique a fired alert carries to the rule ids that fired it."""
    # Alert.mitre_attack is contract-validated (every id matches T####[.###]), so no
    # id check is needed here — only the planned techniques (user input) are validated.
    by_technique: dict[str, set[str]] = {}
    for alert in alerts:
        for technique in alert.mitre_attack:
            # The alert's presence already proves the technique was detected; record
            # the firing rule id when the alert carries one (the contract allows none).
            fired = by_technique.setdefault(technique, set())
            if alert.rule_id:
                fired.add(alert.rule_id)
    return by_technique


def evaluate_detection_exercise(
    alerts: Sequence[Alert],
    planned_techniques: Iterable[str],
    *,
    events_total: int,
) -> PurpleExerciseReport:
    """Classify each planned technique as detected or missed against fired alerts.

    ``alerts`` are what the detection set produced over the attack telemetry (from
    Apollo). ``planned_techniques`` is the red-team plan — the techniques the
    attack exercised; it must be non-empty and every entry a well-formed ATT&CK id
    (fail-closed: a malformed id raises ``ValueError`` rather than being scored).
    A planned technique is ``detected`` when a fired alert carries it, otherwise
    ``missed`` (a gap). Techniques detected outside the plan are reported in
    ``unexpected_detections``. Deterministic: every list is sorted.
    """
    planned = {technique.strip() for technique in planned_techniques}
    planned.discard("")
    if not planned:
        raise ValueError("a purple exercise needs at least one planned ATT&CK technique")
    malformed = sorted(t for t in planned if not _TECHNIQUE_RE.match(t))
    if malformed:
        raise ValueError(f"malformed ATT&CK technique id(s): {', '.join(malformed)}")

    detected = _detected_techniques(alerts)
    outcomes = tuple(
        TechniqueOutcome(
            technique=technique,
            result=DetectionResult.DETECTED if technique in detected else DetectionResult.MISSED,
            fired_rules=tuple(sorted(detected.get(technique, ()))),
        )
        for technique in sorted(planned)
    )
    unexpected = tuple(sorted(set(detected) - planned))
    return PurpleExerciseReport(
        outcomes=outcomes,
        unexpected_detections=unexpected,
        events_total=events_total,
        alerts_total=len(alerts),
    )


__all__ = [
    "DetectionResult",
    "PurpleExerciseReport",
    "TechniqueOutcome",
    "evaluate_detection_exercise",
]
