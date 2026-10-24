"""Ingest real telemetry into normalized ``core.Event`` records for Apollo (Blue).

Apollo's detection engine consumes :class:`olympus.core.models.Event` NDJSON
(``apollo run --events``). This module is the missing front door: it turns a real
telemetry source into that contract so the same rules, ATT&CK mapping and
ECS/OCSF export apply to operational data, not just synthetic events.

Discipline (the same used across Olympus import boundaries):

* **Bounded** — a maximum number of lines and total bytes; nothing unbounded is
  read from a log an attacker may influence.
* **Skip, never guess** — a line that does not match the expected shape is
  recorded in ``skipped`` with a reason instead of being coerced into a bogus
  event.
* **Parsing separated from I/O** — :func:`parse_access_log` is pure and unit
  tested against real captured output; the CLI does the reading and writing.

First format: **HTTP access logs**. It accepts the Apache/nginx *Common* and
*Combined* Log Formats and the Python ``http.server`` / ``BaseHTTPRequestHandler``
variant (same field layout, space between date and time), mapping each request to
``event_type="http.request"`` with string attributes a detection rule can match
(``client_ip``, ``method``, ``path``, ``query``, ``protocol``, ``status``,
``bytes``, and — for Combined — ``referer``, ``user_agent``).

Second format: **Zeek JSON-streaming logs** (:func:`parse_zeek_json`). Each line
is one Zeek record (NDJSON); its ``_path`` selects the log kind. The ``conn``,
``dns``, ``http`` and ``ssl`` kinds map to ``network.connection``, ``dns.query``,
``http.request`` and ``tls.session`` events using documented Zeek fields only
(read as flat ``id.orig_h`` keys or the nested ``{"id": {"orig_h"}}`` form). A
line with no known ``_path`` or no mappable field is skipped, never guessed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

from olympus.core.enums import Source
from olympus.core.models import Event

#: Access-log record: host ident authuser [ts] "METHOD target proto" status size
#: with an optional Combined suffix of "referer" "user-agent". Tolerant of both
#: the CLF timestamp (``10/Oct/2000:13:55:36 -0700``) and the Python dev-server
#: one (``20/Sep/2026 21:01:13``) — the timestamp is captured opaquely and parsed
#: separately.
_ACCESS_LINE = re.compile(
    r"^(?P<host>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z][A-Z_-]*)\s+(?P<target>[^"\s]+)(?:\s+(?P<proto>[^"]*))?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?\s*$'
)

#: Timestamp layouts tried in order: CLF (with timezone) then the dev-server one.
_TS_FORMATS = ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y %H:%M:%S")


class IngestError(ValueError):
    """Raised when a telemetry source is unreadable or the format is unknown."""


@dataclass(frozen=True)
class SkippedLine:
    """A log line that could not be parsed into an event, and why."""

    line: int
    text: str
    reason: str


@dataclass(frozen=True)
class IngestResult:
    """Normalized events plus everything deliberately not ingested."""

    events: tuple[Event, ...]
    skipped: tuple[SkippedLine, ...]


def _parse_timestamp(raw: str) -> datetime | None:
    for fmt in _TS_FORMATS:
        try:
            parsed = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        # A dev-server timestamp is naive; treat it as UTC so events are ordered.
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return None


def parse_access_log(
    text: str,
    *,
    source: Source = Source.MANUAL,
    max_lines: int = 1_000_000,
) -> IngestResult:
    """Parse HTTP access-log text into ``http.request`` events (skip, never guess).

    Lines that are not access records (e.g. a server's interleaved diagnostic
    lines) are recorded in ``skipped`` rather than turned into events.
    """
    events: list[Event] = []
    skipped: list[SkippedLine] = []
    for item in iter_access_log(text.splitlines(), source=source, max_lines=max_lines):
        if isinstance(item, Event):
            events.append(item)
        else:
            skipped.append(item)
    return IngestResult(events=tuple(events), skipped=tuple(skipped))


def iter_access_log(
    lines: Iterable[str],
    *,
    source: Source = Source.MANUAL,
    max_lines: int = 1_000_000,
) -> Iterator[Event | SkippedLine]:
    """Parse access-log lines lazily, applying backpressure from the consumer."""
    if not 1 <= max_lines <= 10_000_000:
        raise ValueError("max_lines must be between 1 and 10000000")
    for number, line in enumerate(lines, start=1):
        if number > max_lines:
            yield SkippedLine(number, line[:80], "line budget exceeded")
            break
        stripped = line.strip()
        if not stripped:
            continue
        match = _ACCESS_LINE.match(stripped)
        if match is None:
            yield SkippedLine(number, stripped[:80], "not an access-log record")
            continue
        yield _event_from_match(match, source)


def _event_from_match(match: re.Match[str], source: Source) -> Event:
    target = match.group("target")
    route, _, query = target.partition("?")
    attributes = {
        "client_ip": match.group("host"),
        "method": match.group("method"),
        "path": route,
        "protocol": (match.group("proto") or "").strip(),
        "status": match.group("status"),
        "bytes": match.group("size") if match.group("size") != "-" else "0",
    }
    if query:
        attributes["query"] = query
    if match.group("referer"):
        attributes["referer"] = match.group("referer")
    if match.group("agent"):
        attributes["user_agent"] = match.group("agent")
    # Drop empty values so a rule never matches an accidental "".
    attributes = {key: value for key, value in attributes.items() if value}

    observed = _parse_timestamp(match.group("ts"))
    fields: dict[str, object] = {
        "event_type": "http.request",
        "source": source,
        "attributes": attributes,
    }
    if observed is not None:
        fields["observed_at"] = observed
    return Event(**fields)  # type: ignore[arg-type]


#: Zeek ``_path`` (log kind) -> (event_type, {zeek field: event attribute}). Only
#: documented, stable Zeek fields are mapped; anything else is ignored rather than
#: guessed. Field names are read both as Zeek's flat dotted keys (``id.orig_h``)
#: and, as a fallback, as the nested ``{"id": {"orig_h": ...}}`` form, so either
#: JSON logger layout works without inventing data.
_ZEEK_MAP: dict[str, tuple[str, dict[str, str]]] = {
    "conn": (
        "network.connection",
        {
            "id.orig_h": "client_ip",
            "id.orig_p": "src_port",
            "id.resp_h": "dest_ip",
            "id.resp_p": "dest_port",
            "proto": "transport",
            "service": "service",
            "conn_state": "conn_state",
            "orig_bytes": "orig_bytes",
            "resp_bytes": "resp_bytes",
        },
    ),
    "dns": (
        "dns.query",
        {
            "id.orig_h": "client_ip",
            "id.resp_h": "dest_ip",
            "query": "query",
            "qtype_name": "query_type",
            "rcode_name": "response_code",
        },
    ),
    "http": (
        "http.request",
        {
            "id.orig_h": "client_ip",
            "id.resp_h": "dest_ip",
            "method": "method",
            "host": "host",
            "uri": "path",
            "status_code": "status",
            "user_agent": "user_agent",
        },
    ),
    "ssl": (
        "tls.session",
        {
            "id.orig_h": "client_ip",
            "id.resp_h": "dest_ip",
            "server_name": "server_name",
            "version": "tls_version",
            "validation_status": "validation_status",
        },
    ),
}


def _zeek_field(record: dict[str, object], key: str) -> object:
    """Read a Zeek field as a flat dotted key, falling back to the nested form."""
    if key in record:
        return record[key]
    if "." in key:
        head, _, tail = key.partition(".")
        nested = record.get(head)
        if isinstance(nested, dict):
            return nested.get(tail)
    return None


def _stringify(value: object) -> str:
    """Render a scalar Zeek value as an attribute string; empty for None/containers."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _zeek_timestamp(value: object) -> datetime | None:
    """Convert a Zeek epoch ``ts`` (seconds, int/float/numeric str) to a UTC datetime."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        epoch = float(value)
    except ValueError:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def iter_zeek_json(
    lines: Iterable[str],
    *,
    source: Source = Source.MANUAL,
    max_lines: int = 1_000_000,
) -> Iterator[Event | SkippedLine]:
    """Parse Zeek JSON-streaming log lines lazily into normalized events.

    Each line is one Zeek record (NDJSON). The ``_path`` field selects the log
    kind; only the ``conn``/``dns``/``http``/``ssl`` kinds with documented fields
    are mapped. A line that is not a JSON object, has no known ``_path``, or
    carries no mappable field is recorded as skipped — never coerced into an
    event with invented fields.
    """
    if not 1 <= max_lines <= 10_000_000:
        raise ValueError("max_lines must be between 1 and 10000000")
    for number, line in enumerate(lines, start=1):
        if number > max_lines:
            yield SkippedLine(number, line[:80], "line budget exceeded")
            break
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError:
            yield SkippedLine(number, stripped[:80], "not valid JSON")
            continue
        except RecursionError:
            # A pathologically nested line is skipped honestly, never crashed on.
            yield SkippedLine(number, stripped[:80], "JSON nesting too deep")
            continue
        if not isinstance(record, dict):
            yield SkippedLine(number, stripped[:80], "not a JSON object")
            continue
        path = record.get("_path")
        if not isinstance(path, str) or path not in _ZEEK_MAP:
            yield SkippedLine(number, stripped[:80], "unknown or missing Zeek _path")
            continue
        event_type, field_map = _ZEEK_MAP[path]
        attributes = {
            attribute: _stringify(_zeek_field(record, zeek_key))
            for zeek_key, attribute in field_map.items()
        }
        attributes = {key: value for key, value in attributes.items() if value}
        if not attributes:
            yield SkippedLine(number, stripped[:80], f"no mappable {path} fields")
            continue
        fields: dict[str, object] = {
            "event_type": event_type,
            "source": source,
            "attributes": attributes,
        }
        observed = _zeek_timestamp(record.get("ts"))
        if observed is not None:
            fields["observed_at"] = observed
        yield Event(**fields)  # type: ignore[arg-type]


def parse_zeek_json(
    text: str,
    *,
    source: Source = Source.MANUAL,
    max_lines: int = 1_000_000,
) -> IngestResult:
    """Parse Zeek JSON-streaming log text into normalized events (skip, never guess)."""
    events: list[Event] = []
    skipped: list[SkippedLine] = []
    for item in iter_zeek_json(text.splitlines(), source=source, max_lines=max_lines):
        if isinstance(item, Event):
            events.append(item)
        else:
            skipped.append(item)
    return IngestResult(events=tuple(events), skipped=tuple(skipped))


def events_to_ndjson(events: Iterable[Event]) -> str:
    """Serialize events as one canonical JSON object per line for ``apollo run``."""
    return "".join(event.model_dump_json() + "\n" for event in events)
