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
    """Classify suites, enforce opt-in, and check platform requirements."""
    suite_directories = {
        "unit": "unit",
        "contract": "contract",
        "integration": "integration",
        "container": "container",
        "live_lab": "live_lab",
    }
    for item in items:
        try:
            relative_path = item.path.relative_to(item.config.rootpath / "tests")
        except ValueError:
            continue
        if relative_path.parts:
            suite = relative_path.parts[0]
            marker_name = suite_directories.get(suite)
            if marker_name:
                item.add_marker(getattr(pytest.mark, marker_name))

    selected_suites = {
        suite for item in items for suite in suite_directories if item.get_closest_marker(suite)
    }
    if "container" in selected_suites and os.getenv("OLYMPUS_RUN_CONTAINER_TESTS") != "1":
        raise pytest.UsageError(
            "container tests require explicit opt-in: OLYMPUS_RUN_CONTAINER_TESTS=1"
        )
    if "live_lab" in selected_suites:
        if os.getenv("OLYMPUS_RUN_LIVE_LAB_TESTS") != "1":
            raise pytest.UsageError(
                "live-lab tests require explicit opt-in: OLYMPUS_RUN_LIVE_LAB_TESTS=1"
            )
        if os.getenv("OLYMPUS_LIVE_LAB_AUTHORIZATION") != "I_HAVE_AUTHORIZATION":
            raise pytest.UsageError(
                "live-lab tests require OLYMPUS_LIVE_LAB_AUTHORIZATION="
                "I_HAVE_AUTHORIZATION after verifying the target scope"
            )

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
