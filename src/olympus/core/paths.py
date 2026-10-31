"""Where Olympus writes when the operator did not say where.

Two kinds of file need two different homes, and neither may be inside the
source tree:

* **Audit and block logs** are written *implicitly*, as a side effect of a
  scope violation. The operator never asked for them and would not think to
  point ``--log`` somewhere, so they go to a per-user state directory that
  survives across working directories and never lands in a checkout.
* **Reports and exports** are the deliverable the operator asked for, so their
  default is a plain filename in the current directory — where the command was
  run, and where they will be looked for.
* **Registers and other durable state** belong to the deployment rather than to
  a run. Like logs they go to the state directory, so a server does not lose
  its credentials because it was started from a different directory.

Defaults used to be ``examples/output/...``: paths relative to the process's
working directory that pointed straight into this repository's sample dataset.
Running the CLI from a checkout appended real engagement data to committed
example files, and the test suite modified tracked files as it ran.

The state directory follows the XDG base-directory spec and can be overridden
outright with ``OLYMPUS_STATE_DIR``. Note that CLI defaults read it once, at
import time — it is a deployment setting, not something to change mid-process.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Environment variable that overrides the state directory outright.
STATE_DIR_ENV = "OLYMPUS_STATE_DIR"

#: XDG variable consulted when :data:`STATE_DIR_ENV` is unset.
XDG_STATE_HOME_ENV = "XDG_STATE_HOME"


def state_dir() -> Path:
    """Return the per-user directory for state Olympus writes implicitly."""
    override = os.environ.get(STATE_DIR_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get(XDG_STATE_HOME_ENV, "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return base / "olympus"


def audit_log_path(name: str) -> Path:
    """Return the default path for an implicitly written audit or block log."""
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError(f"audit log name must be a plain filename: {name!r}")
    return state_dir() / "audit" / name


def state_file_path(name: str) -> Path:
    """Return the default path for durable state Olympus keeps for itself.

    A credential register or a queue is not a deliverable and not a log: it is
    the deployment's own state, and it must not depend on the working directory
    the operator happened to be in.
    """
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError(f"state file name must be a plain filename: {name!r}")
    return state_dir() / name


def output_path(name: str) -> Path:
    """Return the default path for a report the operator explicitly asked for.

    Relative, so it resolves against the working directory at write time.
    """
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        raise ValueError(f"output name must be a plain filename: {name!r}")
    return Path(name)
