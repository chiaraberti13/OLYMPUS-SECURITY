"""Strict detection rule loading and evaluation."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from olympus.core.contracts import validate_contract_header
from olympus.core.enums import Severity
from olympus.core.models import Event

RULE_SCHEMA_NAME = "olympus.apollo-rule"
RULE_SCHEMA_VERSION = "1.0.0"
DEFAULT_MAX_RULE_BYTES = 1_000_000
DEFAULT_MAX_RULES = 1_000
_CONDITION_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
try:
    _NOFOLLOW = os.O_NOFOLLOW
except AttributeError:  # pragma: no cover - Windows lacks this flag
    _NOFOLLOW = 0


class DetectionRule(BaseModel):
    """A minimal portable detection rule expressed as YAML-compatible JSON."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_name: Literal["olympus.apollo-rule"] = "olympus.apollo-rule"
    schema_version: Literal["1.0.0"] = "1.0.0"
    rule_id: str = Field(pattern=r"^APL-[A-Z0-9-]+$", max_length=128)
    title: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    conditions: dict[str, str] = Field(min_length=1, max_length=64)
    severity: Severity = Severity.MEDIUM
    mitre_attack: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("title")
    @classmethod
    def validate_title(cls, title: str) -> str:
        if any(character in title for character in "\r\n\x00"):
            raise ValueError("rule title must be one line without NUL")
        return title

    @field_validator("conditions")
    @classmethod
    def validate_conditions(cls, conditions: dict[str, str]) -> dict[str, str]:
        for key, value in conditions.items():
            if _CONDITION_KEY.fullmatch(key) is None:
                raise ValueError(f"invalid condition key: {key!r}")
            if (
                not value
                or len(value) > 4096
                or any(character in value for character in "\r\n\x00")
            ):
                raise ValueError(f"invalid condition value for {key!r}")
        return conditions

    @field_validator("mitre_attack")
    @classmethod
    def validate_mitre(cls, techniques: list[str]) -> list[str]:
        """Validate ATT&CK technique identifiers without external lookups."""
        if any(re.fullmatch(r"T\d{4}(?:\.\d{3})?", item) is None for item in techniques):
            raise ValueError("MITRE ATT&CK IDs must match T#### or T####.###")
        if len(set(techniques)) != len(techniques):
            raise ValueError("MITRE ATT&CK IDs must be unique")
        return techniques


def _plain_scalar(value: str, line_number: int) -> str:
    """Parse a deliberately small, non-executable YAML plain scalar."""
    scalar = value.strip()
    if not scalar or scalar.startswith(("!", "&", "*", "|", ">", "{", "[")):
        raise ValueError(f"unsupported YAML scalar on line {line_number}")
    if len(scalar) >= 2 and scalar[0] == scalar[-1] and scalar[0] in {'"', "'"}:
        return scalar[1:-1]
    if " #" in scalar:
        scalar = scalar.split(" #", 1)[0].rstrip()
    if len(scalar) > 4096 or any(character in scalar for character in "\r\n\x00"):
        raise ValueError(f"YAML scalar is too large or unsafe on line {line_number}")
    return scalar


def _parse_yaml(text: str) -> dict[str, Any]:
    """Parse the strict mapping/list subset used by portable Apollo rules."""
    payload: dict[str, Any] = {}
    section: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if "\t" in raw_line:
            raise ValueError(f"tabs are not allowed in YAML on line {line_number}")
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indentation = len(raw_line) - len(raw_line.lstrip(" "))
        content = raw_line.strip()
        if indentation == 0:
            if ":" not in content:
                raise ValueError(f"expected key/value pair on line {line_number}")
            key, raw_value = content.split(":", 1)
            key = key.strip()
            if key in payload:
                raise ValueError(f"duplicate YAML key {key!r} on line {line_number}")
            if raw_value.strip():
                payload[key] = _plain_scalar(raw_value, line_number)
                section = None
            elif key == "conditions":
                payload[key] = {}
                section = key
            elif key == "mitre_attack":
                payload[key] = []
                section = key
            else:
                raise ValueError(f"unsupported nested YAML key {key!r}")
            continue
        if indentation != 2 or section is None:
            raise ValueError(f"invalid YAML indentation on line {line_number}")
        if section == "mitre_attack" and content.startswith("- "):
            payload[section].append(_plain_scalar(content[2:], line_number))
        elif section == "conditions" and ":" in content:
            key, raw_value = content.split(":", 1)
            if key.strip() in payload[section]:
                raise ValueError(f"duplicate condition on line {line_number}")
            payload[section][key.strip()] = _plain_scalar(raw_value, line_number)
        else:
            raise ValueError(f"invalid YAML collection item on line {line_number}")
    return payload


def _read_rule_text(path: Path, max_rule_bytes: int) -> str:
    if not 1 <= max_rule_bytes <= 10_000_000:
        raise ValueError("max_rule_bytes must be between 1 and 10000000")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"rule path must be a regular non-symlink file: {path}")
    descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        content = handle.read(max_rule_bytes + 1)
    if len(content) > max_rule_bytes:
        raise ValueError(f"rule file exceeds the {max_rule_bytes} byte limit: {path}")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"rule file must be UTF-8 text: {path}") from exc


def _migrate_legacy_rule(payload: object) -> object:
    if (
        isinstance(payload, dict)
        and "schema_name" not in payload
        and "schema_version" not in payload
    ):
        return {
            "schema_name": RULE_SCHEMA_NAME,
            "schema_version": RULE_SCHEMA_VERSION,
            **payload,
        }
    return payload


def load_rule(path: Path, *, max_rule_bytes: int = DEFAULT_MAX_RULE_BYTES) -> DetectionRule:
    """Safely load a strict Apollo YAML rule without constructors, tags or anchors."""
    text = _read_rule_text(path, max_rule_bytes)
    payload: object = json.loads(text) if text.lstrip().startswith("{") else _parse_yaml(text)
    payload = _migrate_legacy_rule(payload)
    if not isinstance(payload, dict):
        raise ValueError("rule document must be a mapping")
    validate_contract_header(payload, schema_name=RULE_SCHEMA_NAME)
    return DetectionRule.model_validate(payload)


def load_rules(
    directory: Path,
    *,
    max_rules: int = DEFAULT_MAX_RULES,
    max_rule_bytes: int = DEFAULT_MAX_RULE_BYTES,
    progress_check: Callable[[], None] | None = None,
) -> list[DetectionRule]:
    """Load every ``*.yml``/``*.yaml`` rule in ``directory``, sorted by path."""
    if not 1 <= max_rules <= 10_000:
        raise ValueError("max_rules must be between 1 and 10000")
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f"rules path must be a regular non-symlink directory: {directory}")
    paths = sorted(path for pattern in ("*.yml", "*.yaml") for path in directory.glob(pattern))
    if not paths:
        raise ValueError(f"rules directory contains no .yml/.yaml files: {directory}")
    if len(paths) > max_rules:
        raise ValueError(f"rules directory exceeds the {max_rules} rule limit")
    rules: list[DetectionRule] = []
    for path in paths:
        if progress_check is not None:
            progress_check()
        rules.append(load_rule(path, max_rule_bytes=max_rule_bytes))
    seen: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            raise ValueError(f"duplicate rule_id in {directory}: {rule.rule_id}")
        seen.add(rule.rule_id)
    return rules


def matches(rule: DetectionRule, event: Event) -> bool:
    """Evaluate exact, deterministic event attribute conditions."""
    return event.event_type == rule.event_type and all(
        event.attributes.get(key) == value for key, value in rule.conditions.items()
    )
