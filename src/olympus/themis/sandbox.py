"""Process-level isolation policy for Themis scanner subprocesses.

A scanner is untrusted code driven by untrusted remote output: it must not be
able to spend the host's CPU, exhaust its memory, fill its disk, fork without
bound, or read anything the control plane owns. This module turns those
requirements into one validated policy that :mod:`olympus.themis.runner` applies
to every child process:

* **Unprivileged execution.** When the parent runs as ``root``, the child drops
  to a dedicated account (``THEMIS_SANDBOX_USER``, ``nobody`` by default) between
  ``fork`` and ``exec``. If the account cannot be resolved the run is refused
  rather than silently performed as root; ``THEMIS_SANDBOX_ALLOW_ROOT=true`` is
  the explicit, documented opt-out.
* **Resource limits.** CPU time, address space, process count, file
  descriptors, file size and core dumps are bounded with ``setrlimit`` in the
  child, so a violation is enforced by the kernel and not by a cooperating
  scanner.
* **Isolated scratch space.** Each run gets a private ``0700`` directory used as
  the child's working directory, ``TMPDIR`` and ``HOME``, removed when the run
  ends. Combined with the file-size limit that bounds temporary-space use.

The container runtime still *applies* seccomp/AppArmor, read-only-root and
namespace controls. This module verifies the mandatory OCI/kernel properties
before live execution; control/scan network separation remains a deployment
concern — see ``docs/themis-sandbox.md``.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from olympus.themis.config import ThemisConfigError, get

#: Bounds every configurable limit is validated against. Keeping them explicit
#: means a typo in the environment fails loudly instead of disabling a limit.
CPU_SECONDS_RANGE = (1, 86_400)
MEMORY_BYTES_RANGE = (64 * 1024 * 1024, 64 * 1024 * 1024 * 1024)
MAX_PROCESSES_RANGE = (1, 4_096)
OPEN_FILES_RANGE = (16, 65_536)
FILE_SIZE_BYTES_RANGE = (1024 * 1024, 64 * 1024 * 1024 * 1024)
GRACE_SECONDS_RANGE = (0.05, 60.0)

DEFAULT_SANDBOX_USER = "nobody"

SCANNER_RUNTIME_ATTESTATION = Path("/etc/olympus/scanner-runtime.json")
SCANNER_RUNTIME_ATTESTATION_SHA256 = (
    "79242404f2f10aedf7b61e9fb2d7f1846d2e039d3a5739ddebba2fb11786b205"
)
CONTAINER_RUNTIME_MARKERS = (Path("/.dockerenv"), Path("/run/.containerenv"))


class SandboxError(RuntimeError):
    """Raised when the required isolation cannot be established."""


@dataclass(frozen=True)
class ScannerIsolationStatus:
    """Kernel and image properties required before any live scanner starts."""

    runtime_marker: str | None
    attestation_sha256: str | None
    root_read_only: bool
    capabilities_empty: bool
    no_new_privileges: bool
    seccomp_filtering: bool

    @property
    def ready(self) -> bool:
        return all(
            (
                self.runtime_marker is not None,
                self.attestation_sha256 == SCANNER_RUNTIME_ATTESTATION_SHA256,
                self.root_read_only,
                self.capabilities_empty,
                self.no_new_privileges,
                self.seccomp_filtering,
            )
        )

    def missing(self) -> tuple[str, ...]:
        checks = (
            (self.runtime_marker is not None, "OCI runtime marker"),
            (
                self.attestation_sha256 == SCANNER_RUNTIME_ATTESTATION_SHA256,
                "pinned scanner image attestation",
            ),
            (self.root_read_only, "read-only root filesystem"),
            (self.capabilities_empty, "empty effective capability set"),
            (self.no_new_privileges, "no-new-privileges"),
            (self.seccomp_filtering, "seccomp filter"),
        )
        return tuple(label for ok, label in checks if not ok)


@dataclass(frozen=True)
class UnprivilegedIdentity:
    """The account a scanner child drops to before ``exec``."""

    name: str
    uid: int
    gid: int
    groups: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.uid <= 0 or self.gid < 0:
            raise SandboxError(f"{self.name!r} is not an unprivileged account (uid={self.uid})")


@dataclass(frozen=True)
class SandboxPolicy:
    """Validated resource, identity and termination policy for one child."""

    cpu_seconds: int = 900
    memory_bytes: int = 2 * 1024 * 1024 * 1024
    max_processes: int = 256
    open_files: int = 512
    file_size_bytes: int = 512 * 1024 * 1024
    grace_seconds: float = 5.0
    user: str = DEFAULT_SANDBOX_USER
    allow_root: bool = False
    #: Injected seam so tests can exercise the drop decision on any host.
    effective_uid: int = field(default_factory=lambda: os.geteuid() if os.name == "posix" else -1)

    def __post_init__(self) -> None:
        _check_int("cpu_seconds", self.cpu_seconds, CPU_SECONDS_RANGE)
        _check_int("memory_bytes", self.memory_bytes, MEMORY_BYTES_RANGE)
        _check_int("max_processes", self.max_processes, MAX_PROCESSES_RANGE)
        _check_int("open_files", self.open_files, OPEN_FILES_RANGE)
        _check_int("file_size_bytes", self.file_size_bytes, FILE_SIZE_BYTES_RANGE)
        low, high = GRACE_SECONDS_RANGE
        if not low <= self.grace_seconds <= high:
            raise SandboxError(f"grace_seconds must be between {low:g} and {high:g}")
        if not self.user.strip() or len(self.user) > 64:
            raise SandboxError("sandbox user must be a non-empty name of at most 64 characters")

    @classmethod
    def from_environment(cls) -> SandboxPolicy:
        """Build the policy from ``THEMIS_SANDBOX_*``, falling back to defaults."""
        defaults = cls()
        try:
            return cls(
                cpu_seconds=_env_int("THEMIS_SANDBOX_CPU_SECONDS", defaults.cpu_seconds),
                memory_bytes=_env_int("THEMIS_SANDBOX_MEMORY_BYTES", defaults.memory_bytes),
                max_processes=_env_int("THEMIS_SANDBOX_MAX_PROCESSES", defaults.max_processes),
                open_files=_env_int("THEMIS_SANDBOX_OPEN_FILES", defaults.open_files),
                file_size_bytes=_env_int(
                    "THEMIS_SANDBOX_FILE_SIZE_BYTES", defaults.file_size_bytes
                ),
                grace_seconds=_env_float("THEMIS_SANDBOX_GRACE_SECONDS", defaults.grace_seconds),
                user=get("THEMIS_SANDBOX_USER", defaults.user).strip() or defaults.user,
                allow_root=_env_flag("THEMIS_SANDBOX_ALLOW_ROOT"),
            )
        except ThemisConfigError as exc:
            raise SandboxError(str(exc)) from exc

    def resolve_identity(self) -> UnprivilegedIdentity | None:
        """Return the account to drop to, or ``None`` when already unprivileged.

        Raises :class:`SandboxError` when the process is privileged and no
        unprivileged account is available: running a scanner as root is a
        decision an operator has to make explicitly, never a fallback.
        """
        if os.name != "posix" or self.effective_uid != 0:
            return None
        try:
            import pwd

            entry = pwd.getpwnam(self.user)
        except (ImportError, KeyError):
            if self.allow_root:
                return None
            raise SandboxError(
                f"refusing to run a scanner as root: unprivileged account {self.user!r} does "
                "not exist. Create it, set THEMIS_SANDBOX_USER to an existing account, or set "
                "THEMIS_SANDBOX_ALLOW_ROOT=true to accept the risk explicitly."
            ) from None
        if entry.pw_uid == 0:
            if self.allow_root:
                return None
            raise SandboxError(
                f"refusing to run a scanner as root: THEMIS_SANDBOX_USER={self.user!r} is uid 0"
            )
        return UnprivilegedIdentity(name=entry.pw_name, uid=entry.pw_uid, gid=entry.pw_gid)

    def rlimits(self) -> tuple[tuple[int, int, int], ...]:
        """Return ``(resource, soft, hard)`` triples to apply inside the child."""
        import resource as resource_module

        limits: list[tuple[int, int, int]] = [
            # A small hard-limit margin lets the kernel deliver SIGXCPU and the
            # process die from it, instead of being SIGKILLed at the same instant.
            (resource_module.RLIMIT_CPU, self.cpu_seconds, self.cpu_seconds + 5),
            (resource_module.RLIMIT_AS, self.memory_bytes, self.memory_bytes),
            (resource_module.RLIMIT_NOFILE, self.open_files, self.open_files),
            (resource_module.RLIMIT_FSIZE, self.file_size_bytes, self.file_size_bytes),
            (resource_module.RLIMIT_CORE, 0, 0),
        ]
        nproc = getattr(resource_module, "RLIMIT_NPROC", None)
        if nproc is not None:  # not available on every POSIX platform
            limits.append((nproc, self.max_processes, self.max_processes))
        return tuple(limits)

    def describe(self) -> dict[str, object]:
        """Return the redaction-safe policy summary recorded with a run."""
        return {
            "cpu_seconds": self.cpu_seconds,
            "memory_bytes": self.memory_bytes,
            "max_processes": self.max_processes,
            "open_files": self.open_files,
            "file_size_bytes": self.file_size_bytes,
            "grace_seconds": self.grace_seconds,
        }


def apply_resource_limits(policy: SandboxPolicy) -> None:
    """Lower this process's resource limits; runs in the child between fork and exec.

    Only the limits are applied here. The privilege drop is handled by
    ``subprocess`` itself (``user``/``group``/``extra_groups``), whose C
    implementation runs before this hook — so ``setuid`` is never refused by
    ``RLIMIT_NPROC``, and lowering a limit afterwards needs no privilege.
    Keep this function to plain syscall wrappers: it executes after ``fork`` in
    a process that may hold locks taken by other threads.
    """
    import resource as resource_module

    for limit, soft, hard in policy.rlimits():
        resource_module.setrlimit(limit, (soft, hard))


def inspect_scanner_isolation(
    *,
    status_path: Path = Path("/proc/self/status"),
    mountinfo_path: Path = Path("/proc/self/mountinfo"),
    attestation_path: Path = SCANNER_RUNTIME_ATTESTATION,
    runtime_markers: tuple[Path, ...] = CONTAINER_RUNTIME_MARKERS,
) -> ScannerIsolationStatus:
    """Inspect the current process without trusting an environment toggle.

    The marker and attestation are useful only together with kernel state. An
    untrusted adapter cannot add files to the read-only image, grant itself
    capabilities, disable ``no_new_privs`` or replace the seccomp filter.
    """
    import hashlib
    import sys

    if not sys.platform.startswith("linux"):
        return ScannerIsolationStatus(None, None, False, False, False, False)

    marker = next((path for path in runtime_markers if _trusted_root_file(path)), None)
    attestation_sha256: str | None = None
    if _trusted_root_file(attestation_path):
        try:
            payload = attestation_path.read_bytes()
        except OSError:
            payload = b""
        if len(payload) <= 4_096:
            attestation_sha256 = hashlib.sha256(payload).hexdigest()

    status = _read_bounded_text(status_path, 128 * 1024)
    fields = {
        key.strip(): value.strip()
        for line in status.splitlines()
        if ":" in line
        for key, value in [line.split(":", 1)]
    }
    capabilities_empty = fields.get("CapEff") == "0000000000000000"
    no_new_privileges = fields.get("NoNewPrivs") == "1"
    try:
        seccomp_filters = int(fields.get("Seccomp_filters", "0"), 10)
    except ValueError:
        seccomp_filters = 0
    seccomp_filtering = fields.get("Seccomp") == "2" and seccomp_filters >= 1

    root_read_only = False
    for line in _read_bounded_text(mountinfo_path, 2 * 1024 * 1024).splitlines():
        fields_before_separator = line.split(" - ", 1)[0].split()
        if len(fields_before_separator) >= 6 and fields_before_separator[4] == "/":
            root_read_only = "ro" in fields_before_separator[5].split(",")
            break

    return ScannerIsolationStatus(
        runtime_marker=str(marker) if marker is not None else None,
        attestation_sha256=attestation_sha256,
        root_read_only=root_read_only,
        capabilities_empty=capabilities_empty,
        no_new_privileges=no_new_privileges,
        seccomp_filtering=seccomp_filtering,
    )


def require_scanner_isolation() -> None:
    """Fail closed unless the live worker has every mandatory OCI safeguard."""
    status = inspect_scanner_isolation()
    if status.ready:
        return
    missing = ", ".join(status.missing())
    raise SandboxError(
        "live scanner execution requires the hardened Olympus worker container; "
        f"missing: {missing}. Use docker compose with the scanner overlay."
    )


def _trusted_root_file(path: Path) -> bool:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0
    )


def _read_bounded_text(path: Path, max_bytes: int) -> str:
    try:
        with path.open("rb") as handle:
            payload = handle.read(max_bytes + 1)
    except OSError:
        return ""
    if len(payload) > max_bytes:
        return ""
    return payload.decode("utf-8", "replace")


def _check_int(name: str, value: int, bounds: tuple[int, int]) -> None:
    low, high = bounds
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise SandboxError(f"{name} must be an integer between {low} and {high}")


def _env_int(name: str, default: int) -> int:
    raw = get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw, 10)
    except ValueError:
        raise SandboxError(f"{name} must be an integer; got {raw!r}") from None


def _env_float(name: str, default: float) -> float:
    raw = get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        raise SandboxError(f"{name} must be a number; got {raw!r}") from None


def _env_flag(name: str) -> bool:
    raw = get(name, "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise SandboxError(f"{name} must be one of true/false, 1/0, yes/no, or on/off; got {raw!r}")
