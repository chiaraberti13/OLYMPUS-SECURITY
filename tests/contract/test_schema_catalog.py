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


def test_committed_schema_catalog_has_no_orphan_files() -> None:
    # ``catalog_files`` emits exactly one file per contract at its *current*
    # version, so a schema file left behind by an earlier version bump (e.g. a
    # stale ``olympus.security-report/1.0.0.schema.json`` after the 1.1.0 bump)
    # is an orphan the staleness check above would never notice. Pin the whole
    # ``schemas/`` tree to what the generator produces.
    generated = {relative_path.as_posix() for relative_path in catalog_files()}
    root = Path("schemas")
    on_disk = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    assert on_disk == generated, {
        "orphan_files": sorted(on_disk - generated),
        "missing_files": sorted(generated - on_disk),
    }


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
