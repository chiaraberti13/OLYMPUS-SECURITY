"""Render Apollo alerts as Splunk HTTP Event Collector (HEC) events (BLUE-2).

Splunk's HEC ``/services/collector/event`` endpoint ingests one JSON *event
envelope* per record: a small wrapper carrying ``time`` (epoch seconds),
``host``/``source``/``sourcetype`` metadata and an arbitrary ``event`` payload.
Several envelopes are sent back-to-back (newline-separated is the shape log
shippers and the batch endpoint accept).

This module only *formats* alerts into that envelope — it performs no network
I/O. The ``event`` payload reuses the ECS document (:mod:`olympus.apollo.ecs`)
so a HEC-ingested alert keeps the same field vocabulary as the direct ECS
export, with no duplicated mapping. Delivery to a live HEC endpoint is a
separate, scope- and authorization-gated step (it is an outbound, active
operation) and is never exercised against a real host from here.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from olympus.apollo.ecs import alert_to_ecs
from olympus.core.models import Alert

#: Fixed, non-identifying metadata. ``host`` is the producing platform, not a
#: scan target; ``sourcetype`` lets a Splunk admin route Olympus detections
#: without bespoke parsing. The HEC token's configuration supplies the index.
HEC_HOST = "olympus"
HEC_SOURCE = "olympus.apollo"
HEC_SOURCETYPE = "olympus:apollo:alert"


def alert_to_hec(alert: Alert) -> dict[str, Any]:
    """Wrap one Olympus :class:`Alert` in a Splunk HEC event envelope.

    ``time`` is the alert's creation instant as epoch seconds (the unit HEC
    expects); the ECS document is embedded verbatim as the ``event`` payload.
    """
    return {
        "time": alert.created_at.timestamp(),
        "host": HEC_HOST,
        "source": HEC_SOURCE,
        "sourcetype": HEC_SOURCETYPE,
        "event": alert_to_ecs(alert),
    }


def alerts_to_hec(alerts: Sequence[Alert]) -> str:
    """Render alerts as newline-delimited Splunk HEC event envelopes.

    One JSON envelope per line; empty input yields an empty string (never a
    stray newline), matching the ECS/OCSF exporters.
    """
    lines = [json.dumps(alert_to_hec(alert), sort_keys=True) for alert in alerts]
    return "\n".join(lines) + ("\n" if lines else "")
