"""Durable, local-first CTI case storage and indicator correlation."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import sqlite3
import stat
from collections.abc import Iterable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from olympus.core.fileio import atomic_write_text, read_regular_text
from olympus.metis.models import Indicator, IndicatorType, IntelCaseDocument, IntelFinding

MAX_INGEST_BYTES = 10_000_000
MAX_INDICATORS_PER_INGEST = 20_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS metis_schema (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('open', 'monitoring', 'closed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS indicators (
    indicator_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
    first_seen TEXT NOT NULL,
    UNIQUE(case_id, indicator_type, value)
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    assessment TEXT NOT NULL,
    source TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_indicators (
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    indicator_id TEXT NOT NULL REFERENCES indicators(indicator_id) ON DELETE CASCADE,
    PRIMARY KEY(finding_id, indicator_id)
);
CREATE TABLE IF NOT EXISTS activity (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metis_indicators_case ON indicators(case_id);
CREATE INDEX IF NOT EXISTS idx_metis_findings_case ON findings(case_id);
CREATE INDEX IF NOT EXISTS idx_metis_links_indicator ON finding_indicators(indicator_id);
"""

_URL = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\]\[\"']{3,2048}")
_EMAIL = re.compile(
    r"(?i)(?<![\w.+-])[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}\b"
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?i)(?<![\w:])(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}(?![\w:])")
_DOMAIN = re.compile(
    r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.-])"
)
_SHA256 = re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])")
_SHA1 = re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])")
_MD5 = re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])")
_CVE = re.compile(r"(?i)\bCVE-\d{4}-\d{4,7}\b")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:24]
    return f"{prefix}-{digest}"


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:24]}"


def _safe_source(value: str) -> str:
    candidate = " ".join(value.replace("\x00", "").split())
    if not 1 <= len(candidate) <= 500:
        raise ValueError("source must contain 1-500 visible characters")
    return candidate


def _refang(value: str) -> str:
    return (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )


def _normalize_url(value: str) -> str | None:
    candidate = _refang(value).rstrip(".,;:!?)")
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    host = parsed.hostname.casefold().rstrip(".")
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        return None
    return urlunsplit((parsed.scheme.casefold(), host + port, parsed.path or "/", parsed.query, ""))


def _valid_domain(value: str) -> str | None:
    candidate = _refang(value).casefold().rstrip(".")
    if len(candidate) > 253 or ".." in candidate:
        return None
    labels = candidate.split(".")
    if len(labels) < 2 or any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        return None
    return candidate


def _indicator(
    indicator_type: IndicatorType, value: str, source: str, confidence: int
) -> Indicator:
    timestamp = datetime.now(UTC)
    return Indicator(
        indicator_id=_stable_id("ioc", indicator_type.value, value),
        indicator_type=indicator_type,
        value=value,
        source=source,
        confidence=confidence,
        first_seen=timestamp,
    )


def extract_indicators(
    text: str,
    *,
    source: str,
    confidence: int = 50,
    limit: int = MAX_INDICATORS_PER_INGEST,
) -> tuple[Indicator, ...]:
    """Extract, normalize and deduplicate common IOCs without network access."""
    source = _safe_source(source)
    if not 0 <= confidence <= 100:
        raise ValueError("confidence must be between 0 and 100")
    if not 1 <= limit <= MAX_INDICATORS_PER_INGEST:
        raise ValueError(f"limit must be between 1 and {MAX_INDICATORS_PER_INGEST}")
    if len(text.encode("utf-8")) > MAX_INGEST_BYTES:
        raise ValueError(f"input exceeds the {MAX_INGEST_BYTES} byte limit")

    found: dict[tuple[IndicatorType, str], Indicator] = {}

    def add(kind: IndicatorType, value: str) -> None:
        key = (kind, value)
        if key not in found:
            if len(found) >= limit:
                raise ValueError(f"indicator count exceeds the {limit} item limit")
            found[key] = _indicator(kind, value, source, confidence)

    url_spans: list[tuple[int, int]] = []
    for match in _URL.finditer(_refang(text)):
        normalized = _normalize_url(match.group())
        if normalized is None:
            continue
        add(IndicatorType.URL, normalized)
        hostname = urlsplit(normalized).hostname
        if hostname:
            try:
                address = ipaddress.ip_address(hostname)
            except ValueError:
                domain = _valid_domain(hostname)
                if domain:
                    add(IndicatorType.DOMAIN, domain)
            else:
                add(
                    IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6, str(address)
                )
        url_spans.append(match.span())

    for match in _EMAIL.finditer(_refang(text)):
        local, domain_raw = match.group().rsplit("@", 1)
        domain = _valid_domain(domain_raw)
        if domain:
            add(IndicatorType.EMAIL, f"{local}@{domain}")
            add(IndicatorType.DOMAIN, domain)

    for match in _IPV4.finditer(text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        add(IndicatorType.IPV4, str(address))
    for match in _IPV6.finditer(text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        add(IndicatorType.IPV6, str(address))

    for match in _DOMAIN.finditer(_refang(text)):
        if any(start <= match.start() < end for start, end in url_spans):
            continue
        domain = _valid_domain(match.group())
        if domain:
            add(IndicatorType.DOMAIN, domain)
    for match in _SHA256.finditer(text):
        add(IndicatorType.SHA256, match.group().casefold())
    for match in _SHA1.finditer(text):
        add(IndicatorType.SHA1, match.group().casefold())
    for match in _MD5.finditer(text):
        add(IndicatorType.MD5, match.group().casefold())
    for match in _CVE.finditer(text):
        add(IndicatorType.CVE, match.group().upper())
    return tuple(sorted(found.values(), key=lambda item: (item.indicator_type.value, item.value)))


class CaseStore:
    """Owner-only SQLite case store with explicit schema and foreign keys."""

    def __init__(self, path: Path) -> None:
        if path.is_symlink():
            raise OSError(f"METIS database must not be a symlink: {path}")
        path = path.resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            path.parent.chmod(0o700)
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO metis_schema(version, applied_at) VALUES(1, ?)", (_now(),)
        )
        self._conn.commit()
        with suppress(OSError):
            path.chmod(0o600)
        if path.exists() and not stat.S_ISREG(path.stat().st_mode):
            raise OSError(f"METIS database must be a regular file: {path}")

    def __enter__(self) -> CaseStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def backup(self, destination: Path) -> Path:
        """Write a consistent owner-only snapshot of the case store.

        Uses SQLite's online backup API, so the snapshot is transactionally
        consistent even under WAL and even if the store is being written
        concurrently — unlike a plain file copy, which can catch a torn write or
        miss the WAL. Returns the resolved destination path.
        """
        if destination.is_symlink():
            raise OSError(f"backup destination must not be a symlink: {destination}")
        destination = destination.resolve()
        if destination == self.path:
            raise ValueError("backup destination must differ from the live database")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            destination.parent.chmod(0o700)
        target = sqlite3.connect(destination)
        try:
            with target:
                self._conn.backup(target)
        finally:
            target.close()
        with suppress(OSError):
            destination.chmod(0o600)
        return destination

    def _touch(self, case_id: str) -> None:
        self._conn.execute("UPDATE cases SET updated_at=? WHERE case_id=?", (_now(), case_id))

    def _require_case(self, case_id: str) -> None:
        if self._conn.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone() is None:
            raise LookupError(f"METIS case not found: {case_id}")

    def _activity(self, case_id: str, action: str, detail: str) -> None:
        self._conn.execute(
            "INSERT INTO activity(case_id, action, detail, created_at) VALUES(?,?,?,?)",
            (case_id, action, detail[:1_000], _now()),
        )

    def create_case(self, title: str) -> str:
        title = " ".join(title.replace("\x00", "").split())
        if not 3 <= len(title) <= 300:
            raise ValueError("case title must contain 3-300 visible characters")
        case_id = _new_id("case")
        now = _now()
        with self._conn:
            self._conn.execute(
                "INSERT INTO cases(case_id,title,status,created_at,updated_at) VALUES(?,?,?,?,?)",
                (case_id, title, "open", now, now),
            )
            self._activity(case_id, "case_created", title)
        return case_id

    def add_indicators(self, case_id: str, indicators: Iterable[Indicator]) -> int:
        self._require_case(case_id)
        inserted = 0
        with self._conn:
            for indicator in indicators:
                cursor = self._conn.execute(
                    """INSERT OR IGNORE INTO indicators
                    (indicator_id,case_id,indicator_type,value,source,confidence,first_seen)
                    VALUES(?,?,?,?,?,?,?)""",
                    (
                        _stable_id("ioc", case_id, indicator.indicator_type.value, indicator.value),
                        case_id,
                        indicator.indicator_type.value,
                        indicator.value,
                        indicator.source,
                        indicator.confidence,
                        indicator.first_seen.isoformat(),
                    ),
                )
                inserted += cursor.rowcount
            self._touch(case_id)
            self._activity(case_id, "indicators_ingested", str(inserted))
        return inserted

    def ingest_file(
        self,
        case_id: str,
        path: Path,
        *,
        source: str,
        confidence: int = 50,
    ) -> int:
        text = read_regular_text(path, max_bytes=MAX_INGEST_BYTES, label="METIS evidence")
        return self.add_indicators(
            case_id,
            extract_indicators(text, source=source, confidence=confidence),
        )

    def add_finding(
        self,
        case_id: str,
        *,
        title: str,
        assessment: str,
        source: str,
        confidence: int,
        indicator_ids: tuple[str, ...] = (),
    ) -> str:
        self._require_case(case_id)
        source = _safe_source(source)
        if not 3 <= len(title.strip()) <= 300:
            raise ValueError("finding title must contain 3-300 characters")
        if not 3 <= len(assessment.strip()) <= 10_000:
            raise ValueError("finding assessment must contain 3-10000 characters")
        if not 0 <= confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        if len(indicator_ids) != len(set(indicator_ids)) or len(indicator_ids) > 1_000:
            raise ValueError("indicator IDs must be unique and contain at most 1000 entries")
        known = {
            row["indicator_id"]
            for row in self._conn.execute(
                "SELECT indicator_id FROM indicators WHERE case_id=?", (case_id,)
            )
        }
        unknown = set(indicator_ids) - known
        if unknown:
            raise ValueError(f"finding references unknown indicator IDs: {sorted(unknown)}")
        finding_id = _new_id("cti")
        with self._conn:
            self._conn.execute(
                """INSERT INTO findings
                (finding_id,case_id,title,assessment,source,confidence,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (
                    finding_id,
                    case_id,
                    title.strip(),
                    assessment.strip(),
                    source,
                    confidence,
                    _now(),
                ),
            )
            self._conn.executemany(
                "INSERT INTO finding_indicators(finding_id,indicator_id) VALUES(?,?)",
                ((finding_id, indicator_id) for indicator_id in indicator_ids),
            )
            self._touch(case_id)
            self._activity(case_id, "finding_added", finding_id)
        return finding_id

    def load_case(self, case_id: str) -> IntelCaseDocument:
        row = self._conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if row is None:
            raise LookupError(f"METIS case not found: {case_id}")
        indicators = tuple(
            Indicator(
                indicator_id=item["indicator_id"],
                indicator_type=IndicatorType(item["indicator_type"]),
                value=item["value"],
                source=item["source"],
                confidence=item["confidence"],
                first_seen=datetime.fromisoformat(item["first_seen"]),
            )
            for item in self._conn.execute(
                "SELECT * FROM indicators WHERE case_id=? ORDER BY indicator_type,value",
                (case_id,),
            )
        )
        links: dict[str, list[str]] = {}
        for item in self._conn.execute(
            """SELECT fi.finding_id,fi.indicator_id FROM finding_indicators fi
            JOIN findings f ON f.finding_id=fi.finding_id
            WHERE f.case_id=? ORDER BY fi.finding_id,fi.indicator_id""",
            (case_id,),
        ):
            links.setdefault(item["finding_id"], []).append(item["indicator_id"])
        findings = tuple(
            IntelFinding(
                finding_id=item["finding_id"],
                title=item["title"],
                assessment=item["assessment"],
                source=item["source"],
                confidence=item["confidence"],
                indicator_ids=tuple(links.get(item["finding_id"], ())),
                created_at=datetime.fromisoformat(item["created_at"]),
            )
            for item in self._conn.execute(
                "SELECT * FROM findings WHERE case_id=? ORDER BY created_at,finding_id",
                (case_id,),
            )
        )
        correlations: set[tuple[str, str]] = set()
        by_indicator: dict[str, list[str]] = {}
        for finding in findings:
            for indicator_id in finding.indicator_ids:
                by_indicator.setdefault(indicator_id, []).append(finding.finding_id)
        for finding_ids in by_indicator.values():
            ordered = sorted(set(finding_ids))
            for index, left in enumerate(ordered):
                correlations.update((left, right) for right in ordered[index + 1 :])
        return IntelCaseDocument(
            case_id=row["case_id"],
            title=row["title"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            indicators=indicators,
            findings=findings,
            correlations=tuple(sorted(correlations)),
        )


class BackupError(ValueError):
    """Raised when a backup is not a usable METIS case database."""


def verify_backup(path: Path) -> dict[str, int]:
    """Open a backup read-only and confirm it is a real METIS store.

    Returns row counts for the core tables. Raises :class:`BackupError` if the
    file is not a regular file, is not SQLite, or lacks the METIS schema — so a
    restore never overwrites a live database from a bogus source.
    """
    if path.is_symlink() or not path.is_file():
        raise BackupError(f"backup must be a regular non-symlink file: {path}")
    if not stat.S_ISREG(path.stat().st_mode):
        raise BackupError(f"backup must be a regular file: {path}")
    uri = f"file:{path}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise BackupError(f"backup is not a readable SQLite database: {exc}") from exc
    try:
        version_row = connection.execute("SELECT MAX(version) FROM metis_schema").fetchone()
        if version_row is None or version_row[0] != 1:
            raise BackupError("backup is not a METIS schema version 1 database")
        # Table names are a fixed literal allowlist, never user input, so the
        # f-string cannot be an injection vector.
        counts = {
            table: int(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
            )
            for table in ("cases", "indicators", "findings")
        }
    except sqlite3.Error as exc:
        raise BackupError(f"backup is missing the METIS schema: {exc}") from exc
    finally:
        connection.close()
    return counts


def restore_backup(backup: Path, destination: Path) -> dict[str, int]:
    """Restore a verified backup into ``destination``, replacing its contents.

    The backup is validated with :func:`verify_backup` first, then copied in
    through the SQLite backup API (a clean, consistent write) rather than a raw
    file move, so a half-written destination can never result. Refuses to write
    through a symlink. Returns the restored row counts.
    """
    counts = verify_backup(backup)
    if destination.is_symlink():
        raise OSError(f"restore destination must not be a symlink: {destination}")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with suppress(OSError):
        destination.parent.chmod(0o700)
    source = sqlite3.connect(f"file:{backup.resolve()}?mode=ro", uri=True)
    target = sqlite3.connect(destination)
    try:
        with target:
            source.backup(target)
    finally:
        target.close()
        source.close()
    with suppress(OSError):
        destination.chmod(0o600)
    return counts


def render_markdown(case: IntelCaseDocument) -> str:
    """Render one self-contained, source-aware CTI case report."""
    def markdown_text(value: str) -> str:
        compact = " ".join(value.split())
        escaped = compact.replace("\\", "\\\\")
        for character in "`*_[]<>|#":
            escaped = escaped.replace(character, f"\\{character}")
        return escaped

    lines = [
        f"# {markdown_text(case.title)}",
        "",
        f"- Case: `{case.case_id}`",
        f"- Status: **{case.status}**",
        f"- Updated: {case.updated_at.isoformat()}",
        f"- Indicators: {len(case.indicators)}",
        f"- Findings: {len(case.findings)}",
        "",
        "## Analytic findings",
        "",
    ]
    if not case.findings:
        lines.append("No analytic findings have been recorded.")
    for finding in case.findings:
        lines.extend(
            [
                f"### {markdown_text(finding.title)}",
                "",
                markdown_text(finding.assessment),
                "",
                f"Source: `{markdown_text(finding.source)}` · "
                f"Confidence: **{finding.confidence}/100**",
                "",
                "Indicators: "
                + (", ".join(f"`{item}`" for item in finding.indicator_ids) or "none"),
                "",
            ]
        )
    lines.extend(
        [
            "## Indicators",
            "",
            "| Type | Value | Confidence | Source |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for indicator in case.indicators:
        safe_value = markdown_text(indicator.value)
        safe_source = markdown_text(indicator.source)
        row = (
            f"| {indicator.indicator_type.value} | `{safe_value}` | "
            f"{indicator.confidence} | {safe_source} |"
        )
        lines.append(row)
    lines.extend(["", "## Correlations", ""])
    if case.correlations:
        lines.extend(f"- `{left}` ↔ `{right}`" for left, right in case.correlations)
    else:
        lines.append("No shared-indicator finding correlations.")
    return "\n".join(lines) + "\n"


def export_report(case: IntelCaseDocument, path: Path, *, format: str = "markdown") -> None:
    """Atomically export a private JSON or Markdown case report."""
    if format == "json":
        content = case.model_dump_json(indent=2) + "\n"
    elif format == "markdown":
        content = render_markdown(case)
    else:
        raise ValueError("format must be json or markdown")
    atomic_write_text(path, content, mode=0o600)
