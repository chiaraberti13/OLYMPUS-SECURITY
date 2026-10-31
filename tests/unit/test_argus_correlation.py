"""Correlation/pivot analysis over an Argus investigation graph (§2 Argus).

Deterministic, dependency-free graph analysis. Tests cover connected components,
degree-ranked pivots, n-hop neighbors, shared-value correlation, the JSON
round-trip loader, and the `argus correlate` CLI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.argus.correlation import (
    connected_components,
    correlate_by_value,
    neighbors,
    pivots,
)
from olympus.argus.graph import (
    Entity,
    EntityType,
    Investigation,
    investigation_from_dict,
)
from olympus.cli import app

runner = CliRunner()


def _investigation() -> Investigation:
    inv = Investigation("case")
    d1 = Entity(EntityType.DOMAIN, "evil.example")
    d2 = Entity(EntityType.DOMAIN, "evil2.example")
    ip = Entity(EntityType.IP, "203.0.113.9")
    email = Entity(EntityType.EMAIL, "a@evil.example")
    account = Entity(EntityType.ACCOUNT, "bob", {"email": "a@evil.example"})
    lone = Entity(EntityType.ORG, "LoneCorp")
    for entity in (d1, d2, ip, email, account, lone):
        inv.add_entity(entity)
    inv.add_relationship(d1, ip, "resolves")
    inv.add_relationship(d2, ip, "resolves")
    inv.add_relationship(d1, email, "whois")
    return inv


def test_connected_components_finds_clusters_and_isolates() -> None:
    components = connected_components(_investigation())
    # Largest cluster: the two domains, the shared IP and the whois email.
    assert components[0] == frozenset(
        {"domain:evil.example", "domain:evil2.example", "ip:203.0.113.9", "email:a@evil.example"}
    )
    # The account and the org are isolated (no edges).
    singletons = {next(iter(component)) for component in components if len(component) == 1}
    assert singletons == {"account:bob", "org:lonecorp"}


def test_pivots_rank_by_degree() -> None:
    ranked = pivots(_investigation())
    top = ranked[0]
    # The shared IP and the domain that has two edges are the degree-2 hubs.
    assert top.degree == 2
    degrees = {pivot.entity.id: pivot.degree for pivot in ranked}
    assert degrees["ip:203.0.113.9"] == 2
    assert degrees["domain:evil.example"] == 2
    assert degrees["org:lonecorp"] == 0  # isolated node still ranked


def test_neighbors_expands_by_hops() -> None:
    inv = _investigation()
    one = neighbors(inv, "ip:203.0.113.9", hops=1)
    assert one == {"domain:evil.example", "domain:evil2.example"}
    two = neighbors(inv, "ip:203.0.113.9", hops=2)
    assert "email:a@evil.example" in two  # reached via evil.example at hop 2
    assert neighbors(inv, "does:not-exist") == set()
    with pytest.raises(ValueError, match="hops must be"):
        neighbors(inv, "ip:203.0.113.9", hops=0)


def test_correlate_by_value_finds_the_shared_email() -> None:
    correlations = correlate_by_value(_investigation())
    # a@evil.example is one entity's value and another entity's attribute.
    shared = {c.value: c.entity_ids for c in correlations}
    assert shared["a@evil.example"] == ("account:bob", "email:a@evil.example")
    with pytest.raises(ValueError, match="min_entities"):
        correlate_by_value(_investigation(), min_entities=1)


def test_investigation_round_trips_through_dict() -> None:
    original = _investigation()
    restored = investigation_from_dict(original.to_dict())
    assert {e.id for e in restored.entities} == {e.id for e in original.entities}
    assert len(restored.relationships) == len(original.relationships)
    # Analysis is identical on the reconstructed graph.
    assert connected_components(restored) == connected_components(original)


def test_investigation_from_dict_rejects_a_bad_type() -> None:
    with pytest.raises(ValueError, match="invalid entity type"):
        investigation_from_dict({"name": "x", "entities": [{"type": "not-a-type", "value": "v"}]})


def test_cli_correlate_reports_clusters_pivots_and_neighbors(tmp_path: Path) -> None:
    graph_file = tmp_path / "investigation.json"
    graph_file.write_text(json.dumps(_investigation().to_dict()), encoding="utf-8")

    result = runner.invoke(
        app,
        ["argus", "correlate", str(graph_file), "--seed", "ip:203.0.113.9", "--hops", "2"],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert any(len(component) == 4 for component in report["components"])
    assert report["pivots"][0]["degree"] == 2
    assert report["neighbors"]["seed"] == "ip:203.0.113.9"
    assert "email:a@evil.example" in report["neighbors"]["ids"]
    assert any(c["value"] == "a@evil.example" for c in report["value_correlations"])
