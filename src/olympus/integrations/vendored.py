"""Locate the temporary legacy Vulnerability Assessment Platform boundary.

The full, unmodified VAP source currently lives under ``vendor/`` while its
remaining runtime surfaces migrate to native THEMIS. These helpers put the vendored
tool's root on ``sys.path`` on demand (only when the operator actually runs it)
so importing ``olympus`` never pulls in the heavy upstream dependency stacks.

The vendor directory is discovered relative to this file, or overridden with the
``OLYMPUS_VENDOR_DIR`` environment variable (useful when Olympus is installed
outside its source tree).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

VAP_DIR = "vulnerability-assessment-platform"


class VendoredToolNotFoundError(RuntimeError):
    """Raised when a vendored tool's source cannot be located on disk."""


def vendor_root() -> Path:
    """Return the repository's ``vendor/`` directory."""
    override = os.environ.get("OLYMPUS_VENDOR_DIR", "").strip()
    if override:
        return Path(override)
    # src/olympus/integrations/vendored.py -> repo root is three parents up
    # from the ``olympus`` package directory.
    return Path(__file__).resolve().parents[3] / "vendor"


def tool_path(name: str) -> Path:
    """Return the on-disk root of a vendored tool, or raise if it is missing."""
    path = vendor_root() / name
    if not path.is_dir():
        raise VendoredToolNotFoundError(
            f"vendored tool {name!r} not found at {path}. Set OLYMPUS_VENDOR_DIR to the "
            "directory that contains the vendored upstream tools."
        )
    return path


def optional_tool_path(name: str) -> Path | None:
    """Return a vendored tool's root, or ``None`` when it is not installed.

    An Olympus installed from a wheel legitimately has no ``vendor/`` tree: the
    upstream source is not packaged. Diagnostics must report that as a fact
    about the environment, not fail with a traceback, so they use this instead
    of :func:`tool_path`.
    """
    try:
        return tool_path(name)
    except VendoredToolNotFoundError:
        return None


def ensure_on_path(name: str) -> Path:
    """Put a vendored tool's root on ``sys.path`` (idempotently) and return it."""
    path = tool_path(name)
    entry = str(path)
    if entry not in sys.path:
        sys.path.insert(0, entry)
    return path
