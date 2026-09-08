"""Investigation-graph model for Argus (flowsint-style OSINT pivoting).

An investigation is a graph of typed **entities** (nodes) connected by typed
**relationships** (edges). Transforms (see :mod:`olympus.argus.transforms`)
pivot from an existing entity to related ones — e.g. a domain to its IPs, an
IP to its geolocation/ASN, a username to the sites it exists on — growing the
graph. The whole graph is JSON-serializable and can be rendered to Mermaid or
Graphviz DOT for visualization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from olympus.core.fileio import atomic_write_text


class EntityType(StrEnum):
    """Kinds of node an OSINT investigation graph can hold."""

    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    ASN = "asn"
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    ACCOUNT = "account"
    URL = "url"
    ORG = "org"


def entity_id(entity_type: EntityType, value: str) -> str:
    """Return a stable, deduplicating id for an entity (``type:normalized``)."""
    return f"{entity_type.value}:{value.strip().lower()}"


@dataclass
class Entity:
    """One node: a typed value plus free-form attributes and its provenance."""

    entity_type: EntityType
    value: str
    attributes: dict[str, str] = field(default_factory=dict)
    discovered_by: str = "seed"

    @property
    def id(self) -> str:
        """Stable identifier used for deduplication and edges."""
        return entity_id(self.entity_type, self.value)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the entity."""
        return {
            "id": self.id,
            "type": self.entity_type.value,
            "value": self.value,
            "attributes": self.attributes,
            "discovered_by": self.discovered_by,
        }


@dataclass(frozen=True)
class Relationship:
    """One directed edge between two entity ids, carrying a label."""

    source_id: str
    target_id: str
    label: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serializable view of the relationship."""
        return {"source": self.source_id, "target": self.target_id, "label": self.label}


class Investigation:
    """A named OSINT investigation graph: deduplicated entities + relationships."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._entities: dict[str, Entity] = {}
        self._relationships: list[Relationship] = []

    @property
    def entities(self) -> list[Entity]:
        """Return the entities in insertion order."""
        return list(self._entities.values())

    @property
    def relationships(self) -> list[Relationship]:
        """Return the relationships in insertion order."""
        return list(self._relationships)

    def get(self, entity_id_value: str) -> Entity | None:
        """Return the entity with ``entity_id_value``, or ``None``."""
        return self._entities.get(entity_id_value)

    def add_entity(self, entity: Entity) -> Entity:
        """Add ``entity`` (merging attributes if the id already exists)."""
        existing = self._entities.get(entity.id)
        if existing is None:
            self._entities[entity.id] = entity
            return entity
        existing.attributes.update(entity.attributes)
        return existing

    def add_relationship(self, source: Entity, target: Entity, label: str) -> None:
        """Add a directed, deduplicated edge ``source -> target`` labeled ``label``."""
        relationship = Relationship(source.id, target.id, label)
        if relationship not in self._relationships:
            self._relationships.append(relationship)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view of the whole investigation."""
        return {
            "name": self.name,
            "entities": [entity.to_dict() for entity in self.entities],
            "relationships": [rel.to_dict() for rel in self._relationships],
        }

    def _node_ids(self) -> dict[str, str]:
        return {entity.id: f"n{index}" for index, entity in enumerate(self.entities)}

    def to_mermaid(self) -> str:
        """Render the graph as a Mermaid ``graph LR`` diagram."""
        lines = ["graph LR"]
        node_ids = self._node_ids()
        for entity in self.entities:
            label = f"{entity.entity_type.value}: {entity.value}".replace('"', "'")
            lines.append(f'    {node_ids[entity.id]}["{label}"]')
        for rel in self._relationships:
            source = node_ids.get(rel.source_id)
            target = node_ids.get(rel.target_id)
            if source and target:
                lines.append(f"    {source} -->|{rel.label}| {target}")
        return "\n".join(lines) + "\n"

    def to_dot(self) -> str:
        """Render the graph as Graphviz DOT (for `dot`, Gephi, etc.)."""

        def esc(text: str) -> str:
            return text.replace("\\", "\\\\").replace('"', '\\"')

        node_ids = self._node_ids()
        lines = ["digraph olympus {", "  rankdir=LR;", '  node [shape=box];']
        for entity in self.entities:
            label = esc(f"{entity.entity_type.value}: {entity.value}")
            lines.append(f'  {node_ids[entity.id]} [label="{label}"];')
        for rel in self._relationships:
            source = node_ids.get(rel.source_id)
            target = node_ids.get(rel.target_id)
            if source and target:
                lines.append(f'  {source} -> {target} [label="{esc(rel.label)}"];')
        lines.append("}")
        return "\n".join(lines) + "\n"

    def to_graphml(self) -> str:
        """Render the graph as GraphML (for yEd, Neo4j import, Gephi...)."""
        from xml.sax.saxutils import escape

        node_ids = self._node_ids()
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
            '  <key id="etype" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="rel" for="edge" attr.name="label" attr.type="string"/>',
            '  <graph edgedefault="directed">',
        ]
        for entity in self.entities:
            node = node_ids[entity.id]
            lines.append(f'    <node id="{node}">')
            lines.append(f'      <data key="label">{escape(entity.value)}</data>')
            lines.append(f'      <data key="etype">{escape(entity.entity_type.value)}</data>')
            lines.append("    </node>")
        for index, rel in enumerate(self._relationships):
            source = node_ids.get(rel.source_id)
            target = node_ids.get(rel.target_id)
            if source and target:
                lines.append(f'    <edge id="e{index}" source="{source}" target="{target}">')
                lines.append(f'      <data key="rel">{escape(rel.label)}</data>')
                lines.append("    </edge>")
        lines += ["  </graph>", "</graphml>"]
        return "\n".join(lines) + "\n"


def export_investigation(investigation: Investigation, path: Path) -> None:
    """Write the investigation graph as JSON to ``path``."""
    atomic_write_text(
        path, json.dumps(investigation.to_dict(), indent=2, sort_keys=True), mode=0o600
    )
