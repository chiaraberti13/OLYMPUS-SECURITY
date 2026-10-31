"""Environment diagnostics used by the ``doctor`` commands.

Every check is read-only, bounded, and secret-safe: it reports whether a
binary, service, module, directory, or configuration value is *present* and (for
binaries) a version string, but never prints the value of a secret — only
whether the variable is set.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Check:
    """One diagnostic result."""

    name: str
    ok: bool
    detail: str = ""
    optional: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable view."""
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "optional": self.optional}


@dataclass
class Report:
    """A named group of checks."""

    title: str
    checks: list[Check] = field(default_factory=list)

    def add(self, check: Check) -> None:
        self.checks.append(check)

    def ok(self) -> bool:
        """True if every non-optional check passed."""
        return all(c.ok for c in self.checks if not c.optional)

    def to_dict(self) -> dict[str, object]:
        return {"title": self.title, "ok": self.ok(), "checks": [c.to_dict() for c in self.checks]}


def binary_version(binary: str, flag: str = "--version") -> str | None:
    """Return the first line of ``binary <flag>`` output, or ``None`` on failure."""
    path = shutil.which(binary)
    if not path:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [path, flag], capture_output=True, text=True, timeout=8, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (completed.stdout or completed.stderr or "").strip().splitlines()
    return output[0].strip() if output else path


def check_binary(binary: str, *, optional: bool = True, version_flag: str = "--version") -> Check:
    """Check that an external binary is on PATH, capturing its version when present."""
    path = shutil.which(binary)
    if not path:
        return Check(f"binary:{binary}", False, "not installed / not on PATH", optional)
    version = binary_version(binary, version_flag) or path
    return Check(f"binary:{binary}", True, version, optional)


def check_python_module(module: str, *, optional: bool = False) -> Check:
    """Check that a Python module is importable (without importing it)."""
    present = importlib.util.find_spec(module) is not None
    return Check(f"python:{module}", present, "importable" if present else "missing", optional)


def check_tcp(host: str, port: int, *, name: str = "", optional: bool = True) -> Check:
    """Check that a TCP service accepts a connection (e.g. Redis)."""
    label = name or f"tcp:{host}:{port}"
    try:
        with socket.create_connection((host, port), timeout=3):
            return Check(label, True, f"reachable at {host}:{port}", optional)
    except OSError:
        return Check(label, False, f"unreachable at {host}:{port}", optional)


def check_writable_dir(path: str, *, optional: bool = False) -> Check:
    """Check that a directory is writable, or could be created writable.

    A diagnostic reports; it does not change the system. This used to
    ``mkdir(parents=True)`` the target, so merely asking ``doctor`` how things
    looked created a ``reports/`` directory in whatever directory the command
    ran from. A missing directory is now reported against the nearest existing
    ancestor instead, and nothing is created.
    """
    import tempfile
    from pathlib import Path

    target = Path(path)
    if not target.exists():
        ancestor = next((parent for parent in target.parents if parent.exists()), None)
        if ancestor is None:
            return Check(f"dir:{path}", False, "does not exist (no reachable parent)", optional)
        if os.access(ancestor, os.W_OK | os.X_OK):
            return Check(
                f"dir:{path}", True, f"does not exist yet (creatable under {ancestor})", optional
            )
        return Check(
            f"dir:{path}", False, f"does not exist and {ancestor} is not writable", optional
        )
    if not target.is_dir():
        return Check(f"dir:{path}", False, "exists but is not a directory", optional)
    try:
        # Probe rather than trust the mode bits: read-only mounts and ACLs both
        # make os.access optimistic. The probe file cleans itself up.
        with tempfile.NamedTemporaryFile(dir=target, prefix=".olympus-doctor-"):
            pass
    except OSError as exc:
        return Check(f"dir:{path}", False, f"not writable ({exc.__class__.__name__})", optional)
    return Check(f"dir:{path}", True, "writable", optional)


def check_env_set(var: str, *, optional: bool = True, secret: bool = False) -> Check:
    """Check whether an environment variable is set.

    For ``secret=True`` the value is never printed — only whether it is set.
    """
    value = os.environ.get(var)
    is_set = bool(value)
    if not is_set:
        detail = "not set"
    elif secret:
        detail = "set"
    else:
        detail = value or ""
    return Check(f"env:{var}", is_set, detail, optional)
