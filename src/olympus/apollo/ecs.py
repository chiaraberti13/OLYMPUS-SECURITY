"""Render Apollo alerts as Elastic Common Schema (ECS) documents (§2 Apollo).

ECS is the field vocabulary most SIEMs (Elastic, and via translation others)
ingest, and it is plain JSON — so exporting Olympus detections into it needs no
dependency and lets an alert land in a SIEM without bespoke parsing. Output is
newline-delimited JSON (one ECS document per line), the shape log shippers and
bulk ingest expect.

Only the mappings ECS actually defines are used: ``@timestamp``, the ``event.*``
fields, ``rule.*``, ``threat.technique`` (from MITRE ATT&CK ids) and
``message``. Everything Olympus-specific that has no ECS home (the source event
id, the alert status, evidence ids) goes under a namespaced ``olympus`` object
rather than being forced into an unrelated ECS field.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from olympus.core.enums import Severity
from olympus.core.models import Alert

#: ECS version whose field set this mapping targets.
ECS_VERSION = "8.11.0"

#: Olympus severity -> ECS ``event.severity`` (a numeric 0-100 scale).
_SEVERITY_SCORE: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 21,
    Severity.MEDIUM: 47,
    Severity.HIGH: 73,
    Severity.CRITICAL: 99,
}


def alert_to_ecs(alert: Alert) -> dict[str, Any]:
    """Map one Olympus :class:`Alert` to an ECS document."""
    event: dict[str, Any] = {
        "kind": "alert",
        "id": alert.alert_id,
        "severity": _SEVERITY_SCORE.get(alert.severity, 0),
        "provider": alert.source.value,
        "action": "detection",
        "dataset": "olympus.apollo",
    }
    document: dict[str, Any] = {
        "@timestamp": alert.created_at.isoformat(),
        "ecs": {"version": ECS_VERSION},
        "event": event,
        "message": alert.title,
        "tags": [alert.status.value],
        "olympus": {
            "event_id": alert.event_id,
            "status": alert.status.value,
            "evidence_ids": list(alert.evidence_ids),
        },
    }
    if alert.rule_id is not None:
        document["rule"] = {"id": alert.rule_id, "name": alert.title}
    if alert.mitre_attack:
        document["threat"] = {
            "technique": [{"id": technique} for technique in alert.mitre_attack]
        }
    return document


def alerts_to_ndjson(alerts: Sequence[Alert]) -> str:
    """Render alerts as newline-delimited ECS JSON (one document per line)."""
    lines = [json.dumps(alert_to_ecs(alert), sort_keys=True) for alert in alerts]
    return "\n".join(lines) + ("\n" if lines else "")
