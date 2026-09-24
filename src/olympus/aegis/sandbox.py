"""Process-level isolation policy for AEGIS scanner subprocesses.

A scanner is untrusted code driven by untrusted remote output: it must not be
able to spend the host's CPU, exhaust its memory, fill its disk, fork without
bound, or read anything the control plane owns. This module turns those
requirements into one validated policy that :mod:`olympus.aegis.runner` applies
to every child process:

* **Unprivileged execution.** When the parent runs as ``root``, the child drops
  to a dedicated account (``AEGIS_SANDBOX_USER``, ``nobody`` by default) between
  ``fork`` and ``exec``. If the account cannot be resolved the run is refused
  rather than silently performed as root; ``AEGIS_SANDBOX_ALLOW_ROOT=true`` is
  the explicit, documented opt-out.
* **Resource limits.** CPU time, address space, process count, file
  descriptors, file size and core dumps are bounded with ``setrlimit`` in the
  child, so a violation is enforced by the kernel and not by a cooperating
  scanner.
* **Isolated scratch space.** Each run gets a private ``0700`` directory used as
  the child's working directory, ``TMPDIR`` and ``HOME``, removed when the run
  ends. Combined with the file-size limit that bounds temporary-space use.

What this module deliberately does not do: seccomp/AppArmor confinement, a
read-only root filesystem, and control/scan network separation are deployment
concerns handled by the container runtime — see ``docs/aegis-sandbox.md``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from olympus.aegis.config import AegisConfigError, get

#: Bounds every configurable limit is validated against. Keeping them explicit
#: means a typo in the environment fails loudly instead of disabling a limit.
CPU_SECONDS_RANGE = (1, 86_400)
MEMORY_BYTES_RANGE = (64 * 1024 * 1024, 64 * 1024 * 1024 * 1024)
MAX_PROCESSES_RANGE = (1, 4_096)
OPEN_FILES_RANGE = (16, 65_536)
FILE_SIZE_BYTES_RANGE = (1024 * 1024, 64 * 1024 * 1024 * 1024)
GRACE_SECONDS_RANGE = (0.05, 60.0)

DEFAULT_SANDBOX_USER = "nobody"


class SandboxError(RuntimeError):
    """Raised when the required isolation cannot be established."""


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
        """Build the policy from ``AEGIS_SANDBOX_*``, falling back to defaults."""
        defaults = cls()
        try:
            return cls(
                cpu_seconds=_env_int("AEGIS_SANDBOX_CPU_SECONDS", defaults.cpu_seconds),
                memory_bytes=_env_int("AEGIS_SANDBOX_MEMORY_BYTES", defaults.memory_bytes),
                max_processes=_env_int("AEGIS_SANDBOX_MAX_PROCESSES", defaults.max_processes),
                open_files=_env_int("AEGIS_SANDBOX_OPEN_FILES", defaults.open_files),
                file_size_bytes=_env_int("AEGIS_SANDBOX_FILE_SIZE_BYTES", defaults.file_size_bytes),
                grace_seconds=_env_float("AEGIS_SANDBOX_GRACE_SECONDS", defaults.grace_seconds),
                user=get("AEGIS_SANDBOX_USER", defaults.user).strip() or defaults.user,
                allow_root=_env_flag("AEGIS_SANDBOX_ALLOW_ROOT"),
            )
        except AegisConfigError as exc:
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
                "not exist. Create it, set AEGIS_SANDBOX_USER to an existing account, or set "
                "AEGIS_SANDBOX_ALLOW_ROOT=true to accept the risk explicitly."
            ) from None
        if entry.pw_uid == 0:
            if self.allow_root:
                return None
            raise SandboxError(
                f"refusing to run a scanner as root: AEGIS_SANDBOX_USER={self.user!r} is uid 0"
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
