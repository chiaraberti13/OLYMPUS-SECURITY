"""Import a faithful subset of Sigma rules into Apollo (§3.3).

Sigma (https://sigmahq.io) is the portable detection-rule format. Apollo's own
:class:`~olympus.apollo.rules.DetectionRule` evaluates *exact* field==value
conditions, which is a strict subset of what Sigma can express. This module
imports the rules that map faithfully onto that model and **refuses** — loudly,
with a reason — the ones that do not, rather than silently turning a
``|contains`` or a wildcard into a wrong exact match. It is the same
import-the-subset, refuse-the-rest discipline used for STIX/MISP.

To stay consistent with the project's deliberate avoidance of a YAML dependency
(see ``apollo.rules._parse_yaml``), Sigma YAML is read by a small, strict,
indentation-based parser here — it supports only plain/quoted scalars, block
maps and block sequences, rejects tabs, tags, anchors and flow collections, and
is bounded in size and depth. It is a parser for trusted-but-simple rule files,
not a general YAML engine.

Faithfully imported:
* ``title`` -> title, ``level`` -> severity, ``logsource`` -> a sanitized
  ``event_type`` (product/service/category joined), ``tags`` of the form
  ``attack.tXXXX`` -> MITRE ATT&CK technique ids.
* a ``detection`` with exactly one ``selection`` map of ``field: value`` and
  ``condition: selection`` -> exact-match conditions.

Refused (:class:`SigmaImportError`):
* field modifiers (``field|contains``), value lists (an OR), wildcards
  (``*``/``?``) in a value, more than one selection, or any ``condition`` other
  than the single selection's name.
"""

from __future__ import annotations

import re
from typing import Any

from olympus.apollo.rules import RULE_SCHEMA_NAME, RULE_SCHEMA_VERSION, DetectionRule

_MAX_LINES = 5_000
_MAX_INDENT_DEPTH = 16
_MAX_SCALAR = 4_096

#: Sigma level -> Olympus severity.
_LEVEL_TO_SEVERITY = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

_ATTACK_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_EVENT_TYPE_SANITIZE = re.compile(r"[^A-Za-z0-9_.-]+")


class SigmaImportError(ValueError):
    """Raised when a Sigma rule is malformed or outside the faithful subset."""


# --- A strict, bounded YAML-subset parser (no external dependency) ----------- #


def _scalar(raw: str) -> Any:
    text = raw.strip()
    if text in {"", "~", "null"}:
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    if " #" in text:
        text = text.split(" #", 1)[0].rstrip()
    if len(text) > _MAX_SCALAR or any(ch in text for ch in "\r\x00"):
        raise SigmaImportError("Sigma scalar is too large or unsafe")
    if text.startswith(("!", "&", "*", "{", "[", "|", ">")):
        raise SigmaImportError(f"unsupported YAML construct: {text[:16]!r}")
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def _prepare(text: str) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if "\t" in line:
            raise SigmaImportError(f"tabs are not allowed in Sigma YAML (line {number})")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        rows.append((indent, stripped))
    if len(rows) > _MAX_LINES:
        raise SigmaImportError("Sigma rule exceeds the line limit")
    return rows


def _parse_block(
    rows: list[tuple[int, str]], start: int, indent: int, depth: int
) -> tuple[Any, int]:
    if depth > _MAX_INDENT_DEPTH:
        raise SigmaImportError("Sigma nesting is too deep")
    is_list = rows[start][1].startswith("- ") or rows[start][1] == "-"
    return (
        _parse_sequence(rows, start, indent, depth)
        if is_list
        else _parse_mapping(rows, start, indent, depth)
    )


def _parse_mapping(
    rows: list[tuple[int, str]], start: int, indent: int, depth: int
) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    index = start
    while index < len(rows):
        row_indent, content = rows[index]
        if row_indent < indent:
            break
        if row_indent > indent:
            raise SigmaImportError("invalid Sigma indentation")
        if ":" not in content:
            raise SigmaImportError(f"expected 'key: value' in Sigma mapping: {content[:32]!r}")
        key, _, rest = content.partition(":")
        key = key.strip()
        if key in mapping:
            raise SigmaImportError(f"duplicate Sigma key: {key!r}")
        rest = rest.strip()
        if rest:
            mapping[key] = _scalar(rest)
            index += 1
        else:
            if index + 1 >= len(rows) or rows[index + 1][0] <= indent:
                raise SigmaImportError(f"Sigma key {key!r} has no value")
            value, index = _parse_block(rows, index + 1, rows[index + 1][0], depth + 1)
            mapping[key] = value
    return mapping, index


def _parse_sequence(
    rows: list[tuple[int, str]], start: int, indent: int, depth: int
) -> tuple[list[Any], int]:
    items: list[Any] = []
    index = start
    while index < len(rows):
        row_indent, content = rows[index]
        if row_indent < indent:
            break
        if row_indent > indent or not (content == "-" or content.startswith("- ")):
            raise SigmaImportError("invalid Sigma sequence item")
        items.append(_scalar(content[2:] if content.startswith("- ") else ""))
        index += 1
    return items, index


def parse_sigma_yaml(text: str) -> dict[str, Any]:
    """Parse one Sigma document from the supported strict YAML subset."""
    rows = _prepare(text)
    if not rows:
        raise SigmaImportError("empty Sigma document")
    value, _ = _parse_block(rows, 0, rows[0][0], 0)
    if not isinstance(value, dict):
        raise SigmaImportError("Sigma document must be a mapping")
    return value


# --- Mapping the faithful subset onto an Apollo DetectionRule ---------------- #


def _event_type_from_logsource(logsource: Any) -> str:
    if not isinstance(logsource, dict):
        raise SigmaImportError("Sigma logsource must be a mapping")
    parts = [
        str(logsource[key])
        for key in ("product", "service", "category")
        if isinstance(logsource.get(key), str) and logsource[key]
    ]
    if not parts:
        raise SigmaImportError("Sigma logsource has no product/service/category")
    event_type = _EVENT_TYPE_SANITIZE.sub("_", ".".join(parts)).strip("._-")
    if not event_type:
        raise SigmaImportError("Sigma logsource does not yield a usable event_type")
    return event_type


def _techniques_from_tags(tags: Any) -> list[str]:
    if tags is None:
        return []
    if not isinstance(tags, list):
        raise SigmaImportError("Sigma tags must be a sequence")
    techniques: list[str] = []
    for tag in tags:
        match = _ATTACK_TAG.match(str(tag))
        if match:
            technique = match.group(1).upper()
            if technique not in techniques:
                techniques.append(technique)
    return techniques


def _conditions_from_detection(detection: Any) -> dict[str, str]:
    if not isinstance(detection, dict):
        raise SigmaImportError("Sigma detection must be a mapping")
    condition = detection.get("condition")
    selections = {key: value for key, value in detection.items() if key != "condition"}
    if len(selections) != 1:
        raise SigmaImportError(
            "only a single named selection is supported (no multi-selection logic)"
        )
    name, selection = next(iter(selections.items()))
    if not isinstance(condition, str) or condition.strip() != name:
        raise SigmaImportError(
            f"only 'condition: {name}' is supported (no and/or/not/aggregation)"
        )
    if not isinstance(selection, dict):
        raise SigmaImportError("the selection must be a field:value mapping, not a list")
    conditions: dict[str, str] = {}
    for field, value in selection.items():
        if "|" in field:
            raise SigmaImportError(f"field modifier not supported: {field!r} (only exact match)")
        if isinstance(value, list):
            raise SigmaImportError(f"value list (OR) not supported for {field!r}")
        if value is None:
            raise SigmaImportError(f"empty value not supported for {field!r}")
        text = str(value)
        if "*" in text or "?" in text:
            raise SigmaImportError(f"wildcard not supported in value for {field!r}")
        conditions[field] = text
    if not conditions:
        raise SigmaImportError("Sigma selection has no fields")
    return conditions


def _rule_id_from_sigma(document: dict[str, Any]) -> str:
    raw = str(document.get("id") or document.get("title") or "")
    slug = re.sub(r"[^A-Za-z0-9]+", "", raw).upper()[:40]
    return f"APL-SIGMA-{slug}" if slug else "APL-SIGMA-RULE"


def sigma_to_rule(text: str) -> DetectionRule:
    """Convert one Sigma rule (faithful subset) to an Apollo DetectionRule.

    Raises :class:`SigmaImportError` with a specific reason for anything outside
    the exact-match subset, so nothing is silently mistranslated.
    """
    document = parse_sigma_yaml(text)
    title = document.get("title")
    if not isinstance(title, str) or not title.strip():
        raise SigmaImportError("Sigma rule needs a non-empty title")
    level = str(document.get("level", "medium")).lower()
    severity = _LEVEL_TO_SEVERITY.get(level, "medium")
    payload = {
        "schema_name": RULE_SCHEMA_NAME,
        "schema_version": RULE_SCHEMA_VERSION,
        "rule_id": _rule_id_from_sigma(document),
        "title": title.strip(),
        "event_type": _event_type_from_logsource(document.get("logsource")),
        "conditions": _conditions_from_detection(document.get("detection")),
        "severity": severity,
        "mitre_attack": _techniques_from_tags(document.get("tags")),
    }
    try:
        return DetectionRule.model_validate(payload)
    except ValueError as exc:
        raise SigmaImportError(f"converted rule failed Apollo validation: {exc}") from exc
