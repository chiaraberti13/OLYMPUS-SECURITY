"""Published JSON Schemas are versioned, deterministic and current."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from olympus.core.contracts import ContractVersion
from olympus.schema_catalog import CATALOG_SCHEMA_NAME, catalog_files


def test_committed_schema_catalog_matches_models() -> None:
    for relative_path, expected in catalog_files().items():
        published = Path("schemas") / relative_path
        assert published.read_text(encoding="utf-8") == expected


def test_catalog_identifies_versioned_inputs_outputs_and_content() -> None:
    catalog = json.loads(catalog_files()[Path("catalog.json")])

    assert catalog["schema_name"] == CATALOG_SCHEMA_NAME
    names = [entry["name"] for entry in catalog["contracts"]]
    assert names == sorted(names)
    assert {entry["direction"] for entry in catalog["contracts"]} == {
        "input",
        "output",
        "shared",
    }
    for entry in catalog["contracts"]:
        ContractVersion.parse(entry["schema_version"])
        content = catalog_files()[Path(entry["path"])]
        assert hashlib.sha256(content.encode("utf-8")).hexdigest() == entry["sha256"]
        schema = json.loads(content)
        assert schema["$id"].endswith(f":{entry['name']}:{entry['schema_version']}")
