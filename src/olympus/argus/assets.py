"""Conversion of Argus reconnaissance snapshots to the shared asset contract."""

from __future__ import annotations

import json
from pathlib import Path

from olympus.argus.recon import DomainRecon
from olympus.core.enums import AssetType, Source
from olympus.core.fileio import atomic_write_text
from olympus.core.models import Asset


def recon_to_assets(recon: DomainRecon) -> list[Asset]:
    """Convert one passive snapshot into domain, host and IP assets."""
    assets = [
        Asset(
            asset_type=AssetType.DOMAIN,
            hostname=recon.domain,
            ip_addresses=[*recon.a_records, *recon.aaaa_records],
            source=Source.ARGUS,
            metadata={"spf": recon.spf or "", "dmarc": recon.dmarc or ""},
        )
    ]
    assets.extend(
        Asset(asset_type=AssetType.HOST, hostname=name, source=Source.ARGUS)
        for name in recon.subdomains
    )
    return assets


def export_assets(assets: list[Asset], output: Path) -> None:
    """Write assets atomically as a versioned JSON document."""
    payload = {
        "schema_name": "olympus.argus-assets",
        "schema_version": "1.0.0",
        "assets": [asset.model_dump(mode="json") for asset in assets],
    }
    atomic_write_text(
        output, json.dumps(payload, indent=2, sort_keys=True) + "\n", mode=0o600
    )
