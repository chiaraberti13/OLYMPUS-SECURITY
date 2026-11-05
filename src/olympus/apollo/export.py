"""Atomic Apollo alert export."""

import json
import os
import tempfile
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from olympus.apollo.ecs import alerts_to_ndjson
from olympus.apollo.elastic import DEFAULT_ELASTIC_INDEX, alerts_to_elastic_bulk
from olympus.apollo.hec import alerts_to_hec
from olympus.apollo.ocsf import alerts_to_ndjson as ocsf_alerts_to_ndjson
from olympus.apollo.sentinel import alerts_to_sentinel_json
from olympus.core.fileio import atomic_write_text
from olympus.core.models import Alert


def export_alerts(alerts: Sequence[Alert], output: Path) -> None:
    """Write core-compatible alerts as a versioned document."""
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_name": "olympus.apollo-alerts",
        "schema_version": "1.0.0",
        "alerts": [alert.model_dump(mode="json") for alert in alerts],
    }
    content = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(output)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def export_alerts_ecs(alerts: Sequence[Alert], output: Path) -> None:
    """Write alerts as owner-only newline-delimited ECS JSON for SIEM ingestion."""
    atomic_write_text(output, alerts_to_ndjson(alerts), mode=0o600)


def export_alerts_ocsf(alerts: Sequence[Alert], output: Path) -> None:
    """Write alerts as owner-only newline-delimited OCSF Detection Findings."""
    atomic_write_text(output, ocsf_alerts_to_ndjson(alerts), mode=0o600)


def export_alerts_hec(alerts: Sequence[Alert], output: Path) -> None:
    """Write alerts as owner-only newline-delimited Splunk HEC event envelopes."""
    atomic_write_text(output, alerts_to_hec(alerts), mode=0o600)


def export_alerts_elastic_bulk(
    alerts: Sequence[Alert], output: Path, *, index: str = DEFAULT_ELASTIC_INDEX
) -> None:
    """Write alerts as an owner-only Elasticsearch ``_bulk`` request body."""
    atomic_write_text(output, alerts_to_elastic_bulk(alerts, index=index), mode=0o600)


def export_alerts_sentinel(alerts: Sequence[Alert], output: Path) -> None:
    """Write an owner-only Azure Monitor Logs Ingestion API JSON array."""
    atomic_write_text(output, alerts_to_sentinel_json(alerts), mode=0o600)
