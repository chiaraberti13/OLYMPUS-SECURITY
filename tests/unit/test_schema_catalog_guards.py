"""The schema catalog's own integrity guards must fail closed.

``_validated_contracts`` / ``_constant`` are what stop an ambiguous or
mislabelled model from being published as a public contract: an unparsable
schema name, a duplicate identity, a registry name that disagrees with the
model's own ``schema_name``, or a model that does not pin its identity with a
string ``Literal``. These are the catalog's correctness guarantees, so pin that
each one raises rather than silently publishing a bad contract.
"""

from __future__ import annotations

from typing import Literal

import pytest
from pydantic import BaseModel

from olympus.schema_catalog import (
    PublishedContract,
    SchemaCatalogError,
    _constant,
    _validated_contracts,
)


class _GoodContract(BaseModel):
    schema_name: Literal["olympus.good"] = "olympus.good"
    schema_version: Literal["1.0.0"] = "1.0.0"
    value: int = 0


class _NoIdentity(BaseModel):
    value: int = 0


def test_constant_requires_a_properties_mapping() -> None:
    with pytest.raises(SchemaCatalogError, match="no properties mapping"):
        _constant({}, "schema_name")


def test_constant_requires_the_field_to_be_present() -> None:
    with pytest.raises(SchemaCatalogError, match="must declare one string Literal"):
        _constant({"properties": {}}, "schema_name")


def test_constant_requires_a_string_const() -> None:
    with pytest.raises(SchemaCatalogError, match="must declare one string Literal"):
        _constant({"properties": {"schema_name": {"type": "string"}}}, "schema_name")


def test_invalid_public_schema_name_is_rejected() -> None:
    bad = (PublishedContract("not-olympus", "output", _GoodContract),)
    with pytest.raises(SchemaCatalogError, match="invalid public schema name"):
        _validated_contracts(bad)


def test_duplicate_public_schema_name_is_rejected() -> None:
    duplicated = (
        PublishedContract("olympus.good", "output", _GoodContract),
        PublishedContract("olympus.good", "output", _GoodContract),
    )
    with pytest.raises(SchemaCatalogError, match="duplicate public schema name"):
        _validated_contracts(duplicated)


def test_registry_name_must_match_model_identity() -> None:
    mismatched = (PublishedContract("olympus.mismatch", "output", _GoodContract),)
    with pytest.raises(SchemaCatalogError, match="does not match model identity"):
        _validated_contracts(mismatched)


def test_model_without_a_pinned_identity_is_rejected() -> None:
    unpinned = (PublishedContract("olympus.no-identity", "output", _NoIdentity),)
    with pytest.raises(SchemaCatalogError, match="must declare one string Literal"):
        _validated_contracts(unpinned)
