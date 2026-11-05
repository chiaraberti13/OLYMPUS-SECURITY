"""Offline Apollo alert formatter for Azure Monitor / Microsoft Sentinel (BLUE-2).

The Azure Monitor Logs Ingestion API accepts a JSON *array* of records. A Data
Collection Rule (DCR) must explicitly map these fields to an existing custom
Log Analytics table (for example, OlympusApollo_CL). This is not a Sentinel
incident-creation API and does not perform any network operation, provision a
DCR, or authenticate to Azure.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from olympus.core.models import Alert


def alert_to_sentinel(alert: Alert) -> dict[str, Any]:
    """Map an alert to a flat, custom-table-friendly DCR input record.

    Arrays are JSON-encoded strings to avoid requiring dynamic column types.
    The target DCR stream declaration and table schema must agree with these
    exact names and types. No target-controlled data is interpreted as code.
    """
    return {
        "TimeGenerated": alert.created_at.isoformat(),
        "AlertId": alert.alert_id,
        "EventId": alert.event_id,
        "Title": alert.title,
        "Source": alert.source.value,
        "Severity": alert.severity.value,
        "Status": alert.status.value,
        "RuleId": alert.rule_id or "",
        "MitreAttackIds": json.dumps(alert.mitre_attack),
        "EvidenceIds": json.dumps(alert.evidence_ids),
    }


def alerts_to_sentinel_json(alerts: Sequence[Alert]) -> str:
    """Render a JSON array suitable as an Azure Logs Ingestion request body.

    Empty inputs produce [] (a valid JSON array), not NDJSON. The caller
    decides whether to send it; this formatter never makes HTTP requests.
    """
    return json.dumps([alert_to_sentinel(alert) for alert in alerts], sort_keys=True) + "\n"
