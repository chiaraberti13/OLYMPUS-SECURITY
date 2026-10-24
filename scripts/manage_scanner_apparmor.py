#!/usr/bin/env python3
"""Provision the versioned THEMIS scanner AppArmor policy safely.

The helper deliberately performs no package installation and never invokes a
shell. ``install`` is idempotent (``apparmor_parser -r``) and fails closed when
AppArmor, the parser, root privileges or the expected policy are unavailable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

PROFILE_NAME = "olympus-themis-scanner"
PROFILE_VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "deploy/security/olympus-themis-scanner.apparmor"
APPARMOR_ENABLED = Path("/sys/module/apparmor/parameters/enabled")
APPARMOR_PROFILES = Path("/sys/kernel/security/apparmor/profiles")
_MAX_POLICY_BYTES = 128 * 1024


class ProvisioningError(RuntimeError):
    """An AppArmor prerequisite or postcondition was not satisfied."""


@dataclass(frozen=True)
class AppArmorStatus:
    available: bool
    parser: str | None
    profile: str
    version: str
    policy_sha256: str
    loaded_mode: str | None


def _read_policy(path: Path) -> tuple[str, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProvisioningError(f"policy cannot be inspected: {exc}") from exc
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ProvisioningError("policy must be a regular file, not a symlink")
    if metadata.st_size > _MAX_POLICY_BYTES:
        raise ProvisioningError("policy exceeds the 128 KiB safety limit")
    try:
        raw = path.read_bytes()
        source = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ProvisioningError(f"policy cannot be read as UTF-8: {exc}") from exc
    version_marker = f"# Policy version: {PROFILE_VERSION}"
    declaration = re.compile(
        rf"^profile\s+{re.escape(PROFILE_NAME)}\s+"
        r"flags=\(attach_disconnected,mediate_deleted\)\s*\{\s*$",
        re.MULTILINE,
    )
    if version_marker not in source or len(declaration.findall(source)) != 1:
        raise ProvisioningError("policy identity or version does not match the trusted contract")
    return source, hashlib.sha256(raw).hexdigest()


def _apparmor_available(enabled_path: Path = APPARMOR_ENABLED) -> bool:
    if platform.system() != "Linux":
        return False
    try:
        return enabled_path.read_text(encoding="ascii").strip() == "Y"
    except OSError:
        return False


def _loaded_mode(profiles_path: Path = APPARMOR_PROFILES) -> str | None:
    try:
        profiles = profiles_path.read_text(encoding="utf-8")
    except OSError:
        return None
    prefix = f"{PROFILE_NAME} ("
    for line in profiles.splitlines():
        if line.startswith(prefix) and line.endswith(")"):
            return line[len(prefix) : -1]
    return None


def _find_parser() -> str | None:
    candidate = shutil.which("apparmor_parser")
    if candidate is None:
        return None
    try:
        path = Path(candidate).resolve(strict=True)
        metadata = path.stat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        return None
    return str(path)


def inspect(policy: Path = DEFAULT_POLICY) -> AppArmorStatus:
    """Return deterministic readiness state without mutating the host."""
    _, digest = _read_policy(policy)
    return AppArmorStatus(
        available=_apparmor_available(),
        parser=_find_parser(),
        profile=PROFILE_NAME,
        version=PROFILE_VERSION,
        policy_sha256=digest,
        loaded_mode=_loaded_mode(),
    )


def install(policy: Path = DEFAULT_POLICY) -> AppArmorStatus:
    """Load or replace the trusted policy and require enforcing when observable."""
    status = inspect(policy)
    if not status.available:
        raise ProvisioningError("AppArmor is not enabled on this Linux host")
    if status.parser is None:
        raise ProvisioningError("apparmor_parser is unavailable; install the host AppArmor tools")
    if os.geteuid() != 0:
        raise ProvisioningError("install requires root; rerun this command through sudo")
    try:
        subprocess.run(  # noqa: S603 - executable is resolved and root-owned, argv is fixed
            [status.parser, "-r", "-W", str(policy.resolve(strict=True))],
            check=True,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ProvisioningError(f"apparmor_parser rejected the policy: {exc}") from exc
    installed = inspect(policy)
    if installed.loaded_mode is not None and installed.loaded_mode != "enforce":
        raise ProvisioningError(
            f"profile postcondition failed: expected enforce, got {installed.loaded_mode}"
        )
    return installed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "install"))
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY,
        help="trusted AppArmor policy (defaults to the versioned repository profile)",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = install(args.policy) if args.action == "install" else inspect(args.policy)
    except ProvisioningError as exc:
        print(json.dumps({"error": str(exc), "status": "failed"}, sort_keys=True))
        return 2
    ready = result.available and result.parser is not None
    outcome = "installed" if args.action == "install" else ("ready" if ready else "unavailable")
    print(json.dumps({"status": outcome, **asdict(result)}, sort_keys=True))
    if args.action == "status" and not ready:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
