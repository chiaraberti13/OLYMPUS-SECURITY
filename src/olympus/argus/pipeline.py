"""Bounded event-driven reconnaissance pipeline for Argus.

This is a native implementation of a useful event-bus/preset pattern: modules
subscribe to typed events and may emit new events, while the engine owns
deduplication, depth, blacklist, authorization and item limits. Built-in
modules are offline-only. Network-capable extensions must declare themselves
active and pass the injected scope gate before every expansion.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from olympus.core.execution import ExecutionPolicy, StructuredAuditRecord, append_structured_audit
from olympus.core.fileio import atomic_write_text, read_regular_text

DEFAULT_MAX_PRESET_BYTES = 1_000_000


class ReconEventType(StrEnum):
    DOMAIN = "domain"
    EMAIL = "email"
    HOST = "host"
    IP = "ip"
    PHONE = "phone"
    URL = "url"
    USERNAME = "username"


def _event_value(event_type: ReconEventType, value: str) -> str:
    candidate = value.strip()
    if event_type in {ReconEventType.DOMAIN, ReconEventType.HOST}:
        return candidate.casefold().rstrip(".")
    if event_type is ReconEventType.EMAIL and "@" in candidate:
        local, domain = candidate.rsplit("@", 1)
        return f"{local}@{domain.casefold().rstrip('.')}"
    if event_type is ReconEventType.IP:
        return str(ipaddress.ip_address(candidate))
    if event_type is ReconEventType.URL:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("URL events must use http or https and include a hostname")
        return candidate
    if event_type is ReconEventType.USERNAME:
        return candidate.casefold()
    return candidate


class ReconSeed(BaseModel):
    """One typed pipeline seed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_type: ReconEventType = Field(alias="type")
    value: str = Field(min_length=1, max_length=2_048)
    tags: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator("value")
    @classmethod
    def _safe_value(cls, value: str) -> str:
        if value != value.strip() or any(character in value for character in "\r\n\x00"):
            raise ValueError("seed values must be trimmed and contain no CR/LF/NUL")
        return value


class PipelinePreset(BaseModel):
    """Versioned pipeline configuration with hard resource bounds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["olympus.argus-pipeline-preset"] = "olympus.argus-pipeline-preset"
    schema_version: Literal["1.0.0"] = "1.0.0"
    name: str = Field(min_length=1, max_length=120)
    seeds: tuple[ReconSeed, ...] = Field(min_length=1, max_length=1_024)
    modules: tuple[str, ...] = Field(min_length=1, max_length=64)
    blacklist: tuple[str, ...] = Field(default=(), max_length=2_048)
    max_depth: int = Field(default=2, ge=0, le=8)
    max_events: int = Field(default=5_000, ge=1, le=100_000)

    @field_validator("modules", "blacklist")
    @classmethod
    def _unique_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() or value != value.strip() for value in values):
            raise ValueError("module/blacklist entries must be non-empty and trimmed")
        if len(values) != len(set(values)):
            raise ValueError("module/blacklist entries must be unique")
        return values


class ReconEvent(BaseModel):
    """Normalized event stored in the pipeline document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(pattern=r"^evt-[a-f0-9]{24}$")
    event_type: ReconEventType
    value: str = Field(min_length=1, max_length=2_048)
    depth: int = Field(ge=0, le=8)
    discovered_by: str = Field(min_length=1, max_length=64)
    tags: tuple[str, ...] = Field(default=(), max_length=64)
    attributes: Mapping[str, str] = Field(default_factory=dict)


class PipelineEdge(BaseModel):
    """One provenance edge between emitted events."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_event_id: str
    target_event_id: str
    module: str


class PipelineDocument(BaseModel):
    """Portable, bounded pipeline result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_name: Literal["olympus.argus-pipeline"] = "olympus.argus-pipeline"
    schema_version: Literal["1.0.0"] = "1.0.0"
    name: str
    events: tuple[ReconEvent, ...] = Field(max_length=100_000)
    edges: tuple[PipelineEdge, ...] = Field(max_length=200_000)
    blocked: tuple[str, ...] = Field(default=(), max_length=100_000)
    truncated: bool = False


@dataclass(frozen=True)
class EmittedEvent:
    event_type: ReconEventType
    value: str
    tags: tuple[str, ...] = ()
    attributes: Mapping[str, str] | None = None


class PipelineModule(Protocol):
    """Port implemented by local or network-active event transforms."""

    name: str
    consumes: frozenset[ReconEventType]
    active: bool

    def expand(self, event: ReconEvent) -> Iterable[EmittedEvent]:
        """Emit zero or more related events."""
        ...


def _id(event_type: ReconEventType, value: str) -> str:
    digest = hashlib.sha256(f"{event_type.value}\x00{value}".encode()).hexdigest()[:24]
    return f"evt-{digest}"


@dataclass(frozen=True)
class UrlHostModule:
    name: str = "url-host"
    consumes: frozenset[ReconEventType] = frozenset({ReconEventType.URL})
    active: bool = False

    def expand(self, event: ReconEvent) -> Iterable[EmittedEvent]:
        host = urlsplit(event.value).hostname
        if host is None:
            return ()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return (EmittedEvent(ReconEventType.DOMAIN, host, ("url-host",)),)
        return (EmittedEvent(ReconEventType.IP, str(address), ("url-host",)),)


@dataclass(frozen=True)
class EmailDomainModule:
    name: str = "email-domain"
    consumes: frozenset[ReconEventType] = frozenset({ReconEventType.EMAIL})
    active: bool = False

    def expand(self, event: ReconEvent) -> Iterable[EmittedEvent]:
        if "@" not in event.value:
            return ()
        return (EmittedEvent(ReconEventType.DOMAIN, event.value.rsplit("@", 1)[1]),)


@dataclass(frozen=True)
class DomainParentModule:
    name: str = "domain-parent"
    consumes: frozenset[ReconEventType] = frozenset({ReconEventType.DOMAIN, ReconEventType.HOST})
    active: bool = False

    def expand(self, event: ReconEvent) -> Iterable[EmittedEvent]:
        labels = event.value.rstrip(".").split(".")
        if len(labels) <= 2:
            return ()
        return (EmittedEvent(ReconEventType.DOMAIN, ".".join(labels[1:]), ("parent",)),)


@dataclass(frozen=True)
class PhoneProfileModule:
    name: str = "phone-profile"
    consumes: frozenset[ReconEventType] = frozenset({ReconEventType.PHONE})
    active: bool = False

    def expand(self, event: ReconEvent) -> Iterable[EmittedEvent]:
        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone

            parsed = phonenumbers.parse(event.value, None)
        except Exception:
            return ()
        if not phonenumbers.is_possible_number(parsed):
            return ()
        normalized = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        attributes = {
            "country": geocoder.description_for_number(parsed, "en"),
            "carrier": carrier.name_for_number(parsed, "en"),
            "timezones": ",".join(timezone.time_zones_for_number(parsed)),
        }
        return (
            EmittedEvent(
                ReconEventType.PHONE,
                normalized,
                ("normalized",),
                {key: value for key, value in attributes.items() if value},
            ),
        )


BUILTIN_MODULES: dict[str, PipelineModule] = {
    module.name: cast(PipelineModule, module)
    for module in (UrlHostModule(), EmailDomainModule(), DomainParentModule(), PhoneProfileModule())
}

ScopeGate = Callable[[ReconEvent], bool]


@dataclass(frozen=True)
class EventPipeline:
    """Execute a closed module registry under one preset."""

    registry: Mapping[str, PipelineModule]
    scope_gate: ScopeGate | None = None

    def run(
        self,
        preset: PipelinePreset,
        *,
        authorized: bool = False,
        audit_path: Path | None = None,
    ) -> PipelineDocument:
        unknown = set(preset.modules) - self.registry.keys()
        if unknown:
            raise ValueError(f"unknown Argus pipeline modules: {sorted(unknown)}")
        modules = tuple(self.registry[name] for name in preset.modules)
        if any(module.active for module in modules):
            ExecutionPolicy(authorized=authorized).require_authorization("Argus active pipeline")
            if self.scope_gate is None:
                raise ValueError("active Argus pipeline modules require a scope gate")

        blacklist = {value.casefold() for value in preset.blacklist}
        queue: deque[ReconEvent] = deque()
        events: dict[str, ReconEvent] = {}
        edges: list[PipelineEdge] = []
        blocked: list[str] = []
        truncated = False

        def candidate(
            event_type: ReconEventType,
            value: str,
            *,
            depth: int,
            discovered_by: str,
            tags: tuple[str, ...] = (),
            attributes: Mapping[str, str] | None = None,
        ) -> ReconEvent:
            normalized = _event_value(event_type, value)
            return ReconEvent(
                event_id=_id(event_type, normalized),
                event_type=event_type,
                value=normalized,
                depth=depth,
                discovered_by=discovered_by,
                tags=tuple(dict.fromkeys(tags)),
                attributes=dict(attributes or {}),
            )

        def add(event: ReconEvent) -> ReconEvent | None:
            nonlocal truncated
            blacklist_keys = {
                event.value.casefold(),
                f"{event.event_type.value}:{event.value}".casefold(),
            }
            if blacklist_keys & blacklist:
                blocked.append(f"blacklist:{event.event_type.value}:{event.value}")
                return None
            existing = events.get(event.event_id)
            if existing is not None:
                merged = existing.model_copy(
                    update={
                        "tags": tuple(dict.fromkeys((*existing.tags, *event.tags))),
                        "attributes": {**existing.attributes, **event.attributes},
                    }
                )
                events[event.event_id] = merged
                return merged
            if len(events) >= preset.max_events:
                truncated = True
                return None
            events[event.event_id] = event
            queue.append(event)
            return event

        for seed in preset.seeds:
            add(
                candidate(
                    seed.event_type, seed.value, depth=0, discovered_by="seed", tags=seed.tags
                )
            )

        while queue:
            current = queue.popleft()
            if current.depth >= preset.max_depth:
                continue
            for module in modules:
                if current.event_type not in module.consumes:
                    continue
                if module.active and self.scope_gate is not None and not self.scope_gate(current):
                    blocked.append(f"scope:{current.event_type.value}:{current.value}")
                    continue
                for emitted in module.expand(current):
                    target = candidate(
                        emitted.event_type,
                        emitted.value,
                        depth=current.depth + 1,
                        discovered_by=module.name,
                        tags=emitted.tags,
                        attributes=emitted.attributes,
                    )
                    accepted = add(target)
                    if accepted is not None and accepted.event_id != current.event_id:
                        edge = PipelineEdge(
                            source_event_id=current.event_id,
                            target_event_id=accepted.event_id,
                            module=module.name,
                        )
                        if edge not in edges:
                            edges.append(edge)

        document = PipelineDocument(
            name=preset.name,
            events=tuple(events.values()),
            edges=tuple(edges),
            blocked=tuple(dict.fromkeys(blocked)),
            truncated=truncated,
        )
        if audit_path is not None:
            append_structured_audit(
                audit_path,
                StructuredAuditRecord(
                    timestamp=datetime.now(UTC).isoformat(),
                    execution_id=f"argus-pipeline-{hashlib.sha256(preset.name.encode()).hexdigest()[:16]}",
                    action="argus.pipeline",
                    outcome="truncated" if truncated else "complete",
                    metadata={
                        "event_count": len(document.events),
                        "edge_count": len(document.edges),
                        "blocked_count": len(document.blocked),
                        "modules": list(preset.modules),
                    },
                ),
            )
        return document


def load_preset(path: Path, *, max_bytes: int = DEFAULT_MAX_PRESET_BYTES) -> PipelinePreset:
    """Load one strict, current pipeline preset from a regular JSON file."""
    try:
        raw = json.loads(
            read_regular_text(path, max_bytes=max_bytes, label="Argus pipeline preset")
        )
        return PipelinePreset.model_validate(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid Argus pipeline JSON: {exc.msg}") from exc
    except ValidationError as exc:
        raise ValueError(
            f"invalid Argus pipeline preset: {exc.errors(include_input=False, include_url=False)}"
        ) from exc


def export_pipeline(document: PipelineDocument, path: Path) -> None:
    """Atomically write an owner-only versioned pipeline document."""
    atomic_write_text(path, document.model_dump_json(indent=2) + "\n", mode=0o600)
