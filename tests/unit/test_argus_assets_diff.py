"""Tests for Argus core asset export and snapshot change monitoring."""

import json
from pathlib import Path

import pytest

from olympus.argus.assets import export_assets, recon_to_assets
from olympus.argus.diff import SnapshotValidationError, diff_snapshots
from olympus.argus.recon import DomainRecon
from olympus.core.models import Asset


def _export(path: Path, subdomains: list[str]) -> None:
    recon = DomainRecon(
        domain="olympusdemocorp.example",
        a_records=["203.0.113.10"],
        subdomains=subdomains,
    )
    export_assets(recon_to_assets(recon), path)


def test_export_round_trips_through_core_asset(tmp_path: Path) -> None:
    output = tmp_path / "argus-assets.json"
    _export(output, ["portal.olympusdemocorp.example"])
    payload = json.loads(output.read_text(encoding="utf-8"))

    assets = [Asset.model_validate(item) for item in payload["assets"]]
    assert payload["schema_name"] == "olympus.argus-assets"
    assert [asset.hostname for asset in assets] == [
        "olympusdemocorp.example",
        "portal.olympusdemocorp.example",
    ]


def test_diff_reports_added_removed_and_unchanged(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _export(before, ["old.olympusdemocorp.example"])
    _export(after, ["new.olympusdemocorp.example"])

    result = diff_snapshots(before, after)

    assert result.added == ["new.olympusdemocorp.example"]
    assert result.removed == ["old.olympusdemocorp.example"]
    assert result.unchanged == ["olympusdemocorp.example"]


def test_diff_rejects_unversioned_or_wrong_schema(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps({"assets": []}), encoding="utf-8")
    _export(after, [])

    with pytest.raises(SnapshotValidationError, match="schema"):
        diff_snapshots(before, after)


def test_diff_rejects_malformed_assets_instead_of_silently_skipping(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    payload = {
        "schema_name": "olympus.argus-assets",
        "schema_version": "1.0.0",
        "assets": [{"hostname": "missing-required-asset-type.example"}],
    }
    before.write_text(json.dumps(payload), encoding="utf-8")
    _export(after, [])

    with pytest.raises(SnapshotValidationError, match="invalid asset at index 0"):
        diff_snapshots(before, after)


# ---------------------------------------------------------------------------
# Full attack-surface diff: hostnames + IP addresses (ROADMAP WEB-I)
# ---------------------------------------------------------------------------

from olympus.argus.diff import diff_assets  # noqa: E402
from olympus.core.enums import AssetType, Source  # noqa: E402


def _asset(hostname: str | None, ips: list[str]) -> Asset:
    return Asset(
        asset_type=AssetType.HOST,
        hostname=hostname,
        ip_addresses=ips,
        source=Source.ARGUS,
    )


def test_diff_assets_tracks_hostnames_and_ips() -> None:
    before = [_asset("old.example", ["192.0.2.1", "192.0.2.9"])]
    after = [_asset("new.example", ["192.0.2.2", "192.0.2.9"])]
    diff = diff_assets(before, after)
    assert diff.added == ["new.example"]
    assert diff.removed == ["old.example"]
    assert diff.ips_added == ["192.0.2.2"]
    assert diff.ips_removed == ["192.0.2.1"]
    assert diff.ips_unchanged == ["192.0.2.9"]
    assert diff.summary() == {
        "hosts_added": 1,
        "hosts_removed": 1,
        "hosts_unchanged": 0,
        "ips_added": 1,
        "ips_removed": 1,
        "ips_unchanged": 1,
    }


def test_diff_assets_normalises_hostnames() -> None:
    # Trailing dot and case must not read as a surface change.
    diff = diff_assets([_asset("API.Example.", [])], [_asset("api.example", [])])
    assert diff.added == [] and diff.removed == []
    assert diff.unchanged == ["api.example"]


def test_diff_assets_is_deterministic_and_sorted() -> None:
    before: list[Asset] = []
    after = [_asset("b.example", ["203.0.113.5", "203.0.113.1"]), _asset("a.example", [])]
    diff = diff_assets(before, after)
    assert diff.added == ["a.example", "b.example"]
    assert diff.ips_added == ["203.0.113.1", "203.0.113.5"]


def test_diff_snapshots_surfaces_ip_changes(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _export(before, ["portal.olympusdemocorp.example"])
    _export(after, ["portal.olympusdemocorp.example"])
    # Same hostnames across runs → no host change, and the recon IP is stable.
    result = diff_snapshots(before, after)
    assert result.added == [] and result.removed == []
    assert result.ips_removed == [] and result.ips_added == []
