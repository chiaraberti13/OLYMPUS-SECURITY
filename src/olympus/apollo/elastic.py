"""Render Apollo alerts as an Elasticsearch ``_bulk`` request body (BLUE-2).

The ECS exporter (:mod:`olympus.apollo.ecs`) already produces newline-delimited
ECS documents that a log shipper (Filebeat/Logstash) can forward. For *direct*
ingestion through the Elasticsearch ``_bulk`` API — no shipper in between — each
document must be preceded by an action-and-metadata line. This module builds that
body by reusing the ECS mapping verbatim, so the two Elastic paths agree on
fields.

It only *formats* — no network I/O happens here. The ``create`` action keys each
document by the alert id, so re-sending the same alert is rejected by
Elasticsearch as a duplicate rather than silently overwriting an existing record
(append-only, audit-friendly). Delivery to a live cluster is a separate, scope-
and authorization-gated step and is never exercised against a real host from here.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from olympus.apollo.ecs import alert_to_ecs
from olympus.core.models import Alert

#: Default Elasticsearch index/data-stream for Olympus detections. Overridable so
#: an operator can route into their own naming scheme.
DEFAULT_ELASTIC_INDEX = "olympus-apollo"


def alerts_to_elastic_bulk(alerts: Sequence[Alert], *, index: str = DEFAULT_ELASTIC_INDEX) -> str:
    """Render alerts as an Elasticsearch ``_bulk`` request body.

    For each alert two NDJSON lines are emitted: a ``create`` action line keyed by
    the alert id, then the ECS document. The body ends with a trailing newline, as
    the ``_bulk`` API requires. Empty input yields an empty string (no stray
    newline), matching the other exporters.
    """
    lines: list[str] = []
    for alert in alerts:
        action = {"create": {"_index": index, "_id": alert.alert_id}}
        lines.append(json.dumps(action, sort_keys=True))
        lines.append(json.dumps(alert_to_ecs(alert), sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")
