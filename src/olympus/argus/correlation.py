"""Correlation and pivot analysis over an Argus investigation graph (§2 Argus).

The :mod:`~olympus.argus.graph` model stores typed entities and directed edges;
this module reads that graph and surfaces the structure an OSINT analyst pivots
on, with deterministic, dependency-free graph algorithms:

* :func:`connected_components` — the distinct clusters in a case (entities that
  reach each other, treating edges as undirected). Two clusters mean two
  unconnected sub-investigations.
* :func:`pivots` — entities ranked by degree (how many edges touch them). The
  high-degree nodes are the hubs worth pivoting from — a shared IP, a reused
  registrant email.
* :func:`neighbors` — the entities within ``hops`` of a seed, for expanding an
  investigation outward one ring at a time.
* :func:`correlate_by_value` — entities that carry the **same normalized value**
  in different places (a value that is one entity's ``value`` and another's
  attribute, or a shared attribute across entities). These are the non-obvious
  links — the same phone number behind two personas, the same IP in two records.

Everything operates on the public :class:`~olympus.argus.graph.Investigation`
API, so it never depends on that class's internals.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from olympus.argus.graph import Entity, Investigation


def _adjacency(investigation: Investigation) -> dict[str, set[str]]:
    """Undirected adjacency over entity ids present in the graph."""
    adjacency: dict[str, set[str]] = {entity.id: set() for entity in investigation.entities}
    ids = set(adjacency)
    for relationship in investigation.relationships:
        source, target = relationship.source_id, relationship.target_id
        if source in ids and target in ids and source != target:
            adjacency[source].add(target)
            adjacency[target].add(source)
    return adjacency


def connected_components(investigation: Investigation) -> list[frozenset[str]]:
    """Return the connected components (clusters) of the graph, largest first.

    Ties in size break on the smallest member id, so the result is deterministic.
    """
    adjacency = _adjacency(investigation)
    seen: set[str] = set()
    components: list[frozenset[str]] = []
    for start in adjacency:
        if start in seen:
            continue
        stack = [start]
        current: set[str] = set()
        while stack:
            node = stack.pop()
            if node in current:
                continue
            current.add(node)
            seen.add(node)
            stack.extend(adjacency[node] - current)
        components.append(frozenset(current))
    components.sort(key=lambda component: (-len(component), min(component)))
    return components


@dataclass(frozen=True)
class Pivot:
    """An entity and its undirected degree (number of distinct neighbors)."""

    entity: Entity
    degree: int


def pivots(investigation: Investigation, *, limit: int | None = None) -> list[Pivot]:
    """Rank entities by degree, highest first; ties break on entity id.

    ``limit`` keeps only the top N. Entities with no edges are included (degree 0)
    so the ranking is complete unless truncated.
    """
    adjacency = _adjacency(investigation)
    ranked = sorted(
        investigation.entities,
        key=lambda entity: (-len(adjacency.get(entity.id, set())), entity.id),
    )
    result = [
        Pivot(entity=entity, degree=len(adjacency.get(entity.id, set()))) for entity in ranked
    ]
    return result[:limit] if limit is not None else result


def neighbors(investigation: Investigation, entity_id: str, *, hops: int = 1) -> set[str]:
    """Return entity ids within ``hops`` undirected steps of ``entity_id``.

    The seed itself is excluded from the result. An unknown seed yields an empty
    set; ``hops`` must be at least 1.
    """
    if hops < 1:
        raise ValueError("hops must be >= 1")
    adjacency = _adjacency(investigation)
    if entity_id not in adjacency:
        return set()
    frontier = {entity_id}
    reached = {entity_id}
    for _ in range(hops):
        nxt: set[str] = set()
        for node in frontier:
            nxt |= adjacency[node] - reached
        if not nxt:
            break
        reached |= nxt
        frontier = nxt
    return reached - {entity_id}


@dataclass(frozen=True)
class ValueCorrelation:
    """A normalized value shared by two or more entities, and where it appears."""

    value: str
    entity_ids: tuple[str, ...]


def _normalize(value: str) -> str:
    return value.strip().lower()


def correlate_by_value(
    investigation: Investigation, *, attributes: bool = True, min_entities: int = 2
) -> list[ValueCorrelation]:
    """Find values shared by two or more entities — the non-obvious links.

    Each entity contributes its own ``value`` and, when ``attributes`` is set,
    its attribute values. A normalized value carried by at least ``min_entities``
    distinct entities becomes a correlation. Results are sorted by descending
    number of entities, then by value, for determinism. A value shared only with
    itself (one entity) is never reported.
    """
    if min_entities < 2:
        raise ValueError("min_entities must be >= 2")
    by_value: dict[str, set[str]] = defaultdict(set)
    for entity in investigation.entities:
        by_value[_normalize(entity.value)].add(entity.id)
        if attributes:
            for attribute_value in entity.attributes.values():
                normalized = _normalize(attribute_value)
                if normalized:
                    by_value[normalized].add(entity.id)
    correlations = [
        ValueCorrelation(value=value, entity_ids=tuple(sorted(ids)))
        for value, ids in by_value.items()
        if len(ids) >= min_entities
    ]
    correlations.sort(key=lambda item: (-len(item.entity_ids), item.value))
    return correlations
