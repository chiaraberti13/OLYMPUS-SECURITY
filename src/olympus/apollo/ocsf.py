"""Render Apollo alerts as OCSF Detection Findings (§2 Apollo).

OCSF (Open Cybersecurity Schema Framework) is the vendor-neutral schema behind
Amazon Security Lake and a growing set of SIEMs; it is plain JSON, so this adds
no dependency and complements the ECS export. An Olympus alert maps to the OCSF
**Detection Finding** class (``class_uid`` 2004, Findings category), the class
OCSF defines for a detection/alert.

Only OCSF-defined fields are populated: the event core (``activity_id``,
``category_uid``, ``class_uid``, ``type_uid``, ``severity_id``, ``status_id``,
``time``, ``metadata``), ``finding_info``, ``message`` and — from MITRE ATT&CK
ids — ``attacks``. Olympus-specific fields with no OCSF home (the source event
id, evidence ids, the raw status string) go under OCSF's own ``unmapped``
object, which exists exactly for that. Output is newline-delimited JSON, one
finding per line.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from olympus.core.enums import AlertStatus, Severity
from olympus.core.models import Alert

#: OCSF schema version this mapping targets.
OCSF_VERSION = "1.1.0"

#: Detection Finding class and the Create activity.
_CLASS_UID = 2004
_CATEGORY_UID = 2
_ACTIVITY_ID = 1  # Create
_TYPE_UID = _CLASS_UID * 100 + _ACTIVITY_ID  # 200401

#: Olympus severity -> OCSF severity_id (0 Unknown .. 6 Fatal).
_SEVERITY_ID: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

#: Olympus alert status -> OCSF status_id (1 New, 2 In Progress, 4 Resolved).
_STATUS_ID: dict[AlertStatus, int] = {
    AlertStatus.OPEN: 1,
    AlertStatus.ACKNOWLEDGED: 2,
    AlertStatus.INVESTIGATING: 2,
    AlertStatus.CLOSED: 4,
}


def alert_to_ocsf(alert: Alert) -> dict[str, Any]:
    """Map one Olympus :class:`Alert` to an OCSF Detection Finding."""
    epoch_ms = int(alert.created_at.timestamp() * 1000)
    document: dict[str, Any] = {
        "activity_id": _ACTIVITY_ID,
        "category_uid": _CATEGORY_UID,
        "class_uid": _CLASS_UID,
        "type_uid": _TYPE_UID,
        "severity_id": _SEVERITY_ID.get(alert.severity, 0),
        "status_id": _STATUS_ID.get(alert.status, 0),
        "time": epoch_ms,
        "message": alert.title,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {"name": "Olympus Apollo", "vendor_name": "Olympus"},
        },
        "finding_info": {
            "uid": alert.alert_id,
            "title": alert.title,
            "created_time": epoch_ms,
        },
        "unmapped": {
            "event_id": alert.event_id,
            "status": alert.status.value,
            "source": alert.source.value,
            "evidence_ids": list(alert.evidence_ids),
        },
    }
    if alert.rule_id is not None:
        document["finding_info"]["analytic"] = {"uid": alert.rule_id, "name": alert.title}
    if alert.mitre_attack:
        document["attacks"] = [
            {"technique": {"uid": technique}} for technique in alert.mitre_attack
        ]
    return document


def alerts_to_ndjson(alerts: Sequence[Alert]) -> str:
    """Render alerts as newline-delimited OCSF JSON (one finding per line)."""
    lines = [json.dumps(alert_to_ocsf(alert), sort_keys=True) for alert in alerts]
    return "\n".join(lines) + ("\n" if lines else "")
