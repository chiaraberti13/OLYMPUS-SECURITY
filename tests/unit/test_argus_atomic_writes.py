"""Argus persistence writes are atomic, owner-only, and symlink-safe (§5.2).

Every module that persists findings should go through
:func:`olympus.core.fileio.atomic_write_text`, which writes to an unpredictable
temporary file in the target directory, fsyncs it, and renames it into place
with owner-only (0600) permissions. This test verifies the behaviour end to end
on real Argus exporters, and guards against a regression to a plain
``path.write_text`` (which is non-atomic, world-readable by umask, and follows a
symlink at the target path).
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from olympus.argus.accounts import (
    AccountIntel,
    AccountScanResult,
    SiteCheck,
    export_account_intel,
)
from olympus.argus.assets import export_assets
from olympus.core.enums import AssetType, Source
from olympus.core.models import Asset


def _asset() -> Asset:
    return Asset(
        asset_id="AST-TEST-0001",
        asset_type=AssetType.HOST,
        hostname="lab.internal",
        source=Source.ARGUS,
    )


def _account_intel() -> AccountIntel:
    scan = AccountScanResult(
        handle="alice",
        checks=[
            SiteCheck(
                name="example",
                url="https://example.com/alice",
                exists=True,
                status_code=200,
            )
        ],
    )
    return AccountIntel(result=scan, assets=[_asset()], findings=[])


def test_account_export_is_owner_only(tmp_path: Path) -> None:
    destination = tmp_path / "intel.json"
    export_account_intel(_account_intel(), destination)
    assert destination.exists()
    mode = stat.S_IMODE(destination.stat().st_mode)
    assert mode == 0o600, f"expected owner-only 0600, got {oct(mode)}"


def test_account_export_writes_valid_json(tmp_path: Path) -> None:
    destination = tmp_path / "intel.json"
    export_account_intel(_account_intel(), destination)
    payload = json.loads(destination.read_text())
    assert payload  # a real serialized bundle, not empty


def test_export_creates_missing_parent_directories(tmp_path: Path) -> None:
    destination = tmp_path / "nested" / "deep" / "intel.json"
    export_account_intel(_account_intel(), destination)
    assert destination.is_file()


def test_export_leaves_no_temporary_file_behind(tmp_path: Path) -> None:
    destination = tmp_path / "intel.json"
    export_account_intel(_account_intel(), destination)
    # atomic_write_text uses a `.<name>.` mkstemp prefix; none must survive.
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "intel.json"]
    assert leftovers == []


def test_export_overwrites_atomically_without_following_a_symlink(tmp_path: Path) -> None:
    """A target that is a symlink to an outside file must not be written through."""
    outside = tmp_path / "outside.json"
    outside.write_text("untouched", encoding="utf-8")
    link = tmp_path / "intel.json"
    link.symlink_to(outside)

    export_assets([_asset()], link)

    # The rename replaces the symlink itself with a real file; the link target
    # outside is left exactly as it was.
    assert outside.read_text() == "untouched"
    assert not link.is_symlink()
    assert json.loads(link.read_text())["schema_name"] == "olympus.argus-assets"


def test_assets_export_is_owner_only(tmp_path: Path) -> None:
    destination = tmp_path / "assets.json"
    export_assets([_asset()], destination)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "module_name",
    [
        "olympus.argus.accounts",
        "olympus.argus.dns_records",
        "olympus.argus.mac",
        "olympus.argus.web",
        "olympus.argus.email_osint",
        "olympus.argus.whois",
        "olympus.argus.myip",
        "olympus.argus.ip_osint",
        "olympus.argus.phone",
        "olympus.argus.graph",
        "olympus.argus.assets",
        "olympus.argus.fronting",
    ],
)
def test_persistence_modules_use_the_atomic_helper(module_name: str) -> None:
    """Guard: no Argus persistence module falls back to a plain path.write_text."""
    import importlib

    module = importlib.import_module(module_name)
    source = Path(module.__file__).read_text(encoding="utf-8")  # type: ignore[arg-type]
    assert "atomic_write_text" in source, f"{module_name} no longer uses the atomic helper"
    assert ".write_text(" not in source, f"{module_name} still has a plain .write_text call"
