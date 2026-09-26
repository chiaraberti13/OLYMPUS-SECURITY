"""Central platform requirements for explicitly marked test suites."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile

import pytest


def _can_drop_privileges() -> bool:
    """Probe the exact ownership transition required by the root-only test."""
    if os.name != "posix" or getattr(os, "geteuid", lambda: -1)() != 0:
        return False
    workspace = tempfile.mkdtemp(prefix="olympus-pytest-chown-")
    try:
        import pwd

        identity = pwd.getpwnam("nobody")
        os.chown(workspace, identity.pw_uid, identity.pw_gid)
        os.chown(workspace, os.geteuid(), os.getegid())
    except (ImportError, KeyError, OSError):
        return False
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
    return True


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Skip platform-specific tests when their kernel contract is unavailable."""
    if os.name != "posix":
        skip = pytest.mark.skip(reason="requires POSIX process isolation")
        for item in items:
            if item.get_closest_marker("posix_only"):
                item.add_marker(skip)

    if not sys.platform.startswith("linux"):
        skip = pytest.mark.skip(reason="requires Linux-specific kernel interfaces")
        for item in items:
            if item.get_closest_marker("linux_only"):
                item.add_marker(skip)

    if not _can_drop_privileges():
        skip = pytest.mark.skip(reason="requires a privileged parent able to chown the workspace")
        for item in items:
            if item.get_closest_marker("root_only"):
                item.add_marker(skip)
