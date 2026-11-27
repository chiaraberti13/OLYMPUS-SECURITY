"""ARCH-4: the UI↔API contract is stable and versioned across surfaces.

A versioned contract identity (``schema_name`` @ ``schema_version``) is a public
compatibility promise. If one identity could map to two *different* JSON schemas
depending on the surface that serves it, the promise is hollow: a client that
pins ``olympus.finding-explanation@1.1.0`` from the published catalog could
receive a differently-shaped payload from the HTTP API.

These tests pin the invariant **one contract identity ⇒ one schema** across the
whole live API surface and the published schema catalog, so the drift that this
test was written to catch (the API advertising ``epistemic_class`` /
``confidence`` as free strings while the catalog constrained them to enums)
cannot regress.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from fastapi.routing import APIRoute

from olympus.schema_catalog import legacy_schema_bundle
from olympus.themis.api import ApiSettings, create_app


def _const(schema: dict[str, Any], field: str) -> str | None:
    descriptor = schema.get("properties", {}).get(field, {})
    value = descriptor.get("const") if isinstance(descriptor, dict) else None
    return value if isinstance(value, str) else None


def _api_response_contracts() -> dict[tuple[str, str], tuple[str, dict[str, Any]]]:
    """Map every versioned API response identity to (handler, validation schema)."""
    with TemporaryDirectory(prefix="olympus-arch4-") as temporary:
        root = Path(temporary)
        scope_directory = root / "scopes"
        scope_directory.mkdir()
        app = create_app(
            ApiSettings(
                database=root / "themis.sqlite3",
                scope_directory=scope_directory,
                api_key="arch4-contract-surface-key-32char",
            )
        )
        contracts: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}
        for route in app.routes:
            if not isinstance(route, APIRoute) or route.response_model is None:
                continue
            model = route.response_model
            schema_of = getattr(model, "model_json_schema", None)
            if schema_of is None:
                continue
            schema = model.model_json_schema(mode="validation")
            name = _const(schema, "schema_name")
            version = _const(schema, "schema_version")
            if name is None or version is None:
                continue
            key = (name, version)
            previous = contracts.get(key)
            if previous is not None and previous[1] != schema:
                raise AssertionError(
                    f"API identity {name}@{version} is served with two different schemas "
                    f"({previous[0]} and {route.name})"
                )
            contracts[key] = (route.name, schema)
    return contracts


def test_one_api_contract_identity_maps_to_one_schema() -> None:
    # Construction itself raises on an in-surface divergence; keep the check explicit.
    contracts = _api_response_contracts()
    assert contracts, "expected at least one versioned API response contract"
    # No two distinct identities may be built from the same name at the same version.
    names_by_version: dict[str, set[str]] = {}
    for name, version in contracts:
        names_by_version.setdefault(name, set()).add(version)
    # (A single version per name is not required — only one schema per (name, version).)
    assert names_by_version


def test_api_response_contracts_match_the_published_catalog() -> None:
    contracts = _api_response_contracts()
    catalog = legacy_schema_bundle()  # name -> raw validation schema

    checked: list[str] = []
    for (name, version), (handler, schema) in sorted(contracts.items()):
        if name not in catalog:
            # Versioned but not yet published in the catalog (honest ARCH-4 "Resta":
            # the per-tool API envelopes are still to be published). The in-surface
            # uniqueness invariant above still guards them.
            continue
        assert schema == catalog[name], (
            f"API route {handler!r} serves {name}@{version} with a schema that diverges "
            f"from the published catalog contract: the UI↔API contract is not stable"
        )
        checked.append(name)

    assert checked, "no shared contract identities were verified against the catalog"


def test_finding_explanation_is_one_contract_across_surfaces() -> None:
    # Direct regression guard for the divergence this gate was built to catch.
    contracts = _api_response_contracts()
    catalog = legacy_schema_bundle()
    key = ("olympus.finding-explanation", "1.1.0")
    assert key in contracts, "the API must still serve the finding-explanation contract"
    _handler, api_schema = contracts[key]
    assert api_schema == catalog["olympus.finding-explanation"], (
        "the API finding-explanation response must be byte-identical to the published "
        "catalog contract (enum-constrained epistemic_class and confidence)"
    )
