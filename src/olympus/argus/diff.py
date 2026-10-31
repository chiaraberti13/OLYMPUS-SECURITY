"""Attack-surface change monitoring for Argus asset snapshots (ROADMAP ``WEB-I``).

Comparing two recon snapshots answers the question a defender actually asks
between runs: *what changed on my attack surface?* This module is the single,
tested place that decides that, over the modelled surface of a
:class:`~olympus.core.models.Asset`: its **hostnames** (subdomains) and its
**IP addresses**. Ports and services are not first-class fields on the asset
contract, so they are deliberately **not** inferred here — an honest surface diff
never invents a dimension the data does not carry.

The core, :func:`diff_assets`, is pure and offline: it compares two already-loaded
asset lists and talks to no network, so it is deterministic and unit-testable
without files. :func:`diff_snapshots` is the file-reading wrapper that validates
each versioned snapshot first; it preserves the original hostname-level contract
(``added``/``removed``/``unchanged``) and adds the IP-level changes alongside.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from olympus.core.contracts import ContractCompatibilityError, validate_contract_header
from olympus.core.models import Asset


class SnapshotValidationError(ValueError):
    """Raised when an input is not a compatible versioned Argus asset snapshot."""


@dataclass(frozen=True)
class AssetDiff:
    """Attack-surface changes between two Argus snapshots.

    ``added``/``removed``/``unchanged`` are **hostnames** (subdomains), kept under
    those stable keys for backward compatibility; the ``ips_*`` fields carry the
    IP-address changes. Every list is sorted, so the diff is deterministic.
    """

    added: list[str]
    removed: list[str]
    unchanged: list[str]
    ips_added: list[str] = field(default_factory=list)
    ips_removed: list[str] = field(default_factory=list)
    ips_unchanged: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        """Counts a defender reads first: host and IP additions/removals."""
        return {
            "hosts_added": len(self.added),
            "hosts_removed": len(self.removed),
            "hosts_unchanged": len(self.unchanged),
            "ips_added": len(self.ips_added),
            "ips_removed": len(self.ips_removed),
            "ips_unchanged": len(self.ips_unchanged),
        }


def _normalise_host(hostname: str) -> str:
    """Case-fold and strip a trailing dot so ``A.example.`` and ``a.example`` match."""
    return hostname.strip().lower().rstrip(".")


def _surface(assets: Sequence[Asset]) -> tuple[set[str], set[str]]:
    """Project assets to their modelled surface: hostnames and IP addresses."""
    hostnames = {_normalise_host(asset.hostname) for asset in assets if asset.hostname}
    ips = {ip.strip() for asset in assets for ip in asset.ip_addresses if ip.strip()}
    return hostnames, ips


def diff_assets(before: Sequence[Asset], after: Sequence[Asset]) -> AssetDiff:
    """Return deterministic surface changes between two already-loaded asset lists.

    Pure and offline: hostnames and IP addresses present in ``after`` but not
    ``before`` are *added*, those in ``before`` but not ``after`` are *removed*,
    and the intersection is *unchanged*.
    """
    old_hosts, old_ips = _surface(before)
    new_hosts, new_ips = _surface(after)
    return AssetDiff(
        added=sorted(new_hosts - old_hosts),
        removed=sorted(old_hosts - new_hosts),
        unchanged=sorted(old_hosts & new_hosts),
        ips_added=sorted(new_ips - old_ips),
        ips_removed=sorted(old_ips - new_ips),
        ips_unchanged=sorted(old_ips & new_ips),
    )


def _load_assets(path: Path) -> list[Asset]:
    """Load and validate the assets from one versioned Argus snapshot file."""
    payload: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("assets"), list):
        raise SnapshotValidationError(f"invalid Argus asset snapshot: {path}")
    try:
        validate_contract_header(payload, schema_name="olympus.argus-assets")
    except ContractCompatibilityError as exc:
        raise SnapshotValidationError(f"incompatible snapshot {path}: {exc}") from exc

    assets: list[Asset] = []
    for index, item in enumerate(payload["assets"]):
        try:
            assets.append(Asset.model_validate(item))
        except ValidationError as exc:
            raise SnapshotValidationError(
                f"invalid asset at index {index} in snapshot {path}: {exc}"
            ) from exc
    return assets


def diff_snapshots(before: Path, after: Path) -> AssetDiff:
    """Return deterministic surface changes between two exported snapshot files."""
    return diff_assets(_load_assets(before), _load_assets(after))
