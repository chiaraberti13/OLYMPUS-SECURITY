"""Guard: no CLI default may write into the source tree.

Write defaults used to point at ``examples/output/...`` — repository-relative
paths into the committed sample dataset. Running the CLI from a checkout
appended real engagement data to committed example files, and the test suite
modified tracked files simply by running. These tests pin the fix in place.

Read defaults are a different matter: pointing ``--scope`` or ``--rules`` at the
shipped demo dataset is the documented way to try Olympus out, and reading
changes nothing. They are listed explicitly below so a *new* default under
``examples/`` cannot be waved through as "probably an input".
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from olympus.core.paths import audit_log_path, output_path, state_dir

#: Every CLI module that declares default paths.
_CLI_MODULES = (
    "olympus.apollo.cli",
    "olympus.argus.cli",
    "olympus.artemis.cli",
    "olympus.helios.cli",
    "olympus.hermes.cli",
    "olympus.integrations.cli",
    "olympus.minerva.cli",
    "olympus.proteus.cli",
    "olympus.vulcan.cli",
)

#: Defaults that only ever *read* the shipped sample dataset.
_READ_ONLY_INPUTS = frozenset(
    {
        ("olympus.apollo.cli", "DEFAULT_RULES_DIR"),
        ("olympus.argus.cli", "DEFAULT_ACCOUNT_SCOPE_PATH"),
        ("olympus.argus.cli", "DEFAULT_IP_SCOPE_PATH"),
        ("olympus.argus.cli", "DEFAULT_MAC_SCOPE_PATH"),
        ("olympus.argus.cli", "DEFAULT_PHONE_SCOPE_PATH"),
        ("olympus.argus.cli", "DEFAULT_SCOPE_PATH"),
        ("olympus.argus.cli", "DEFAULT_SITES_PATH"),
        ("olympus.artemis.cli", "DEFAULT_METABASE_SCOPE"),
        ("olympus.artemis.cli", "DEFAULT_SCOPE"),
        ("olympus.helios.cli", "DEFAULT_SCOPE"),
        ("olympus.proteus.cli", "DEFAULT_SCOPE"),
    }
)

#: Defaults naming durable deployment state: not a deliverable the operator
#: asked for, and not a log, but state a server must keep across working
#: directories (credential registers, queues). Listed explicitly so a report
#: default cannot be moved out of the working directory unnoticed.
_STATE_FILES = frozenset(
    {
        ("olympus.integrations.cli", "DEFAULT_IDENTITY_REGISTER"),
    }
)

#: The tree a write default must never point into.
_REPO_ROOT = Path(__file__).resolve().parents[2]

_LOG_SUFFIXES = frozenset({".log", ".ndjson"})


def _all_defaults() -> list[tuple[str, str, Path]]:
    """Return every ``DEFAULT_*`` path constant the CLI modules expose."""
    found: list[tuple[str, str, Path]] = []
    for module_name in _CLI_MODULES:
        module = importlib.import_module(module_name)
        for name in sorted(dir(module)):
            if not name.startswith("DEFAULT_"):
                continue
            value = getattr(module, name)
            if isinstance(value, str) and ("/" in value or Path(value).suffix):
                value = Path(value)
            if isinstance(value, Path):
                found.append((module_name, name, value))
    return found


def _write_defaults() -> list[tuple[str, str, Path]]:
    """Return the defaults that name a file Olympus writes."""
    return [item for item in _all_defaults() if (item[0], item[1]) not in _READ_ONLY_INPUTS]


def test_the_guard_actually_covers_the_defaults() -> None:
    """A guard that silently matched nothing would pass forever."""
    write_defaults = _write_defaults()

    assert len(write_defaults) >= 20
    assert {module for module, _, _ in write_defaults} == set(_CLI_MODULES)


def test_the_read_only_allowlist_is_neither_stale_nor_overbroad() -> None:
    """Every allowlisted default must exist and genuinely be a sample input."""
    by_key = {(module, name): value for module, name, value in _all_defaults()}

    assert set(by_key) >= _READ_ONLY_INPUTS, "the allowlist names defaults that no longer exist"
    assert set(by_key) >= _STATE_FILES, "the state-file list names defaults that no longer exist"
    for key in _READ_ONLY_INPUTS:
        assert by_key[key].is_relative_to(Path("examples/input")), (
            f"{key[0]}.{key[1]} is allowlisted as a sample input but does not read one"
        )


@pytest.mark.parametrize(("module_name", "name", "value"), _write_defaults())
def test_no_default_write_path_points_into_the_repository(
    module_name: str, name: str, value: Path
) -> None:
    resolved = value.resolve() if value.is_absolute() else (Path.cwd() / value).resolve()

    for forbidden in (_REPO_ROOT / "examples", _REPO_ROOT / "src", _REPO_ROOT / "tests"):
        assert not resolved.is_relative_to(forbidden), (
            f"{module_name}.{name} writes into {forbidden.name}/ inside the checkout"
        )


@pytest.mark.parametrize(("module_name", "name", "value"), _write_defaults())
def test_audit_logs_default_outside_the_working_directory(
    module_name: str, name: str, value: Path
) -> None:
    """Logs are written implicitly, so they must not depend on where you stand."""
    if value.suffix not in _LOG_SUFFIXES:
        return

    assert value.is_absolute(), f"{module_name}.{name} is a relative audit-log default"
    assert value.is_relative_to(state_dir())


@pytest.mark.parametrize(("module_name", "name", "value"), _write_defaults())
def test_reports_default_to_a_plain_name_in_the_working_directory(
    module_name: str, name: str, value: Path
) -> None:
    """A deliverable belongs where the operator ran the command."""
    if value.suffix in _LOG_SUFFIXES:
        return
    if (module_name, name) in _STATE_FILES:
        assert value.is_absolute(), f"{module_name}.{name} is a relative state-file default"
        assert value.is_relative_to(state_dir())
        return

    assert not value.is_absolute(), f"{module_name}.{name} is an absolute report default"
    assert value.parent == Path(), f"{module_name}.{name} nests the report in a subdirectory"


def test_state_dir_prefers_an_explicit_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_STATE_DIR", "/var/lib/olympus")

    assert state_dir() == Path("/var/lib/olympus")
    assert audit_log_path("x.log") == Path("/var/lib/olympus/audit/x.log")


def test_state_dir_follows_xdg_then_falls_back_to_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLYMPUS_STATE_DIR", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", "/xdg/state")
    assert state_dir() == Path("/xdg/state/olympus")

    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    assert state_dir() == Path.home() / ".local" / "state" / "olympus"


def test_state_dir_ignores_a_blank_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_STATE_DIR", "   ")
    monkeypatch.setenv("XDG_STATE_HOME", "/xdg/state")

    assert state_dir() == Path("/xdg/state/olympus")


def test_state_dir_expands_a_user_relative_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_STATE_DIR", "~/olympus-state")

    assert state_dir() == Path.home() / "olympus-state"


def test_path_helpers_reject_anything_but_a_plain_filename() -> None:
    for bad in ("", ".", "..", "sub/dir.log", "..\\escape.log", "/absolute.log"):
        with pytest.raises(ValueError, match="plain filename"):
            audit_log_path(bad)
        with pytest.raises(ValueError, match="plain filename"):
            output_path(bad)
