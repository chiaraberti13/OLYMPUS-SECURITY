"""Governance of the external engines Olympus drives (manifests, pins, presence).

Engines are *never* vendored: Olympus invokes them as external processes through
the adapters in :mod:`olympus.themis.adapters`. This package holds the data that
makes that dependency explicit and checkable — one ``engine.toml`` per engine,
validated by :mod:`olympus.engines.schema` — so a version pin, a checksum or a
"must be present" rule is a reviewed file, not a convention.
"""
