"""Map detections to MITRE ATT&CK and emit a Navigator layer (§3.3 Apollo).

Apollo rules and the alerts they raise already carry MITRE ATT&CK technique ids
(validated ``T####`` / ``T####.###``). This module turns a set of them into an
**ATT&CK Navigator layer** — the JSON the freely available MITRE ATT&CK
Navigator renders as a heat-mapped matrix — so an operator can see, offline,
which techniques their detections or findings cover and how often.

The layer format is plain JSON (Navigator layer schema 4.5, ATT&CK spec), so no
dependency is needed. Sub-technique ids (``T1059.001``) are emitted as-is with
``showSubtechniques`` on; a score is the count of contributing items for that
technique, which drives the Navigator colour gradient.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from typing import Any

from olympus.apollo.rules import DetectionRule
from olympus.core.models import Alert

#: Navigator layer schema version and the ATT&CK domain this targets.
NAVIGATOR_LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"
ATTACK_DOMAIN = "enterprise-attack"

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def techniques_from_rules(rules: Iterable[DetectionRule]) -> Counter[str]:
    """Count ATT&CK technique ids across detection rules."""
    counter: Counter[str] = Counter()
    for rule in rules:
        counter.update(t for t in rule.mitre_attack if _TECHNIQUE_RE.match(t))
    return counter


def techniques_from_alerts(alerts: Iterable[Alert]) -> Counter[str]:
    """Count ATT&CK technique ids across raised alerts."""
    counter: Counter[str] = Counter()
    for alert in alerts:
        counter.update(t for t in alert.mitre_attack if _TECHNIQUE_RE.match(t))
    return counter


def build_navigator_layer(
    technique_counts: Counter[str],
    *,
    name: str = "Olympus Apollo coverage",
    description: str = "Techniques covered by Olympus Apollo detections.",
) -> dict[str, Any]:
    """Build an ATT&CK Navigator layer from ``{technique_id: count}``.

    Each technique's ``score`` is its count; ``maxValue`` in the gradient is the
    highest count, so the Navigator colours frequently-covered techniques most
    strongly. Ids are emitted sorted for a byte-stable layer.
    """
    highest = max(technique_counts.values(), default=1)
    techniques = [
        {
            "techniqueID": technique,
            "score": count,
            "enabled": True,
        }
        for technique, count in sorted(technique_counts.items())
    ]
    return {
        "name": name,
        "versions": {
            "attack": "14",
            "navigator": NAVIGATOR_VERSION,
            "layer": NAVIGATOR_LAYER_VERSION,
        },
        "domain": ATTACK_DOMAIN,
        "description": description,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0b5cad"],
            "minValue": 0,
            "maxValue": highest,
        },
        "showSubtechniques": True,
    }
