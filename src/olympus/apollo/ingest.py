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
"""

from __future__ import annotations

import re
from collections.abc import Iterable
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
    for number, line in enumerate(text.splitlines(), start=1):
        if number > max_lines:
            skipped.append(SkippedLine(number, line[:80], "line budget exceeded"))
            break
        stripped = line.strip()
        if not stripped:
            continue
        match = _ACCESS_LINE.match(stripped)
        if match is None:
            skipped.append(SkippedLine(number, stripped[:80], "not an access-log record"))
            continue
        events.append(_event_from_match(match, source))
    return IngestResult(events=tuple(events), skipped=tuple(skipped))


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


def events_to_ndjson(events: Iterable[Event]) -> str:
    """Serialize events as one canonical JSON object per line for ``apollo run``."""
    return "".join(event.model_dump_json() + "\n" for event in events)
