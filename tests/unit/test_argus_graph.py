"""Unit tests for the Argus investigation-graph model."""

import json
from pathlib import Path

from olympus.argus.graph import (
    Entity,
    EntityType,
    Investigation,
    entity_id,
    export_investigation,
)


def test_entity_id_normalizes() -> None:
    assert entity_id(EntityType.DOMAIN, "Example.COM") == "domain:example.com"


def test_add_entity_dedupes_and_merges_attributes() -> None:
    graph = Investigation("t")
    a = graph.add_entity(Entity(EntityType.IP, "1.1.1.1", attributes={"kind": "global"}))
    b = graph.add_entity(Entity(EntityType.IP, "1.1.1.1", attributes={"country": "AU"}))
    assert a is b  # same id -> merged, not duplicated
    assert len(graph.entities) == 1
    assert a.attributes == {"kind": "global", "country": "AU"}


def test_add_relationship_dedupes() -> None:
    graph = Investigation("t")
    d = graph.add_entity(Entity(EntityType.DOMAIN, "x.example"))
    ip = graph.add_entity(Entity(EntityType.IP, "203.0.113.1"))
    graph.add_relationship(d, ip, "resolves_to")
    graph.add_relationship(d, ip, "resolves_to")
    assert len(graph.relationships) == 1


def test_to_dict_and_mermaid() -> None:
    graph = Investigation("case")
    email = graph.add_entity(Entity(EntityType.EMAIL, "a@b.example"))
    user = graph.add_entity(Entity(EntityType.USERNAME, "a"))
    graph.add_relationship(email, user, "local_part")
    payload = graph.to_dict()
    assert payload["name"] == "case"
    assert len(graph.entities) == 2
    mermaid = graph.to_mermaid()
    assert mermaid.startswith("graph LR")
    assert "local_part" in mermaid


def test_export_roundtrip(tmp_path: Path) -> None:
    graph = Investigation("case")
    graph.add_entity(Entity(EntityType.PHONE, "+16505550123"))
    out = tmp_path / "g.json"
    export_investigation(graph, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["entities"][0]["type"] == "phone"


def test_to_dot_and_graphml() -> None:
    graph = Investigation("case")
    d = graph.add_entity(Entity(EntityType.DOMAIN, "x.example"))
    ip = graph.add_entity(Entity(EntityType.IP, "203.0.113.1"))
    graph.add_relationship(d, ip, "resolves_to")

    dot = graph.to_dot()
    assert dot.startswith("digraph olympus")
    assert "x.example" in dot and "resolves_to" in dot

    graphml = graph.to_graphml()
    assert graphml.startswith("<?xml")
    assert "<graphml" in graphml
    assert "203.0.113.1" in graphml
    assert 'edgedefault="directed"' in graphml
