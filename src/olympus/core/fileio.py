"""Bounded regular-file reads and durable atomic local writes."""

from __future__ import annotations

import os
import stat
import tempfile
from contextlib import suppress
from pathlib import Path

try:
    _NOFOLLOW = os.O_NOFOLLOW
except AttributeError:  # pragma: no cover - Windows lacks this flag
    _NOFOLLOW = 0


class UnsafeWriteTarget(ValueError):
    """Raised when a write destination fails a pre-write safety check."""


def ensure_write_target(
    path: Path, *, base: Path | None = None, overwrite: bool = True
) -> Path:
    """Validate a write destination *before* any bytes are written (§5.2).

    Three checks, each closing a real footgun for an operator-supplied path:

    * **Symlink target** — an existing symlink *at* ``path`` is rejected; writing
      through it would clobber whatever it points at.
    * **Traversal / escape** — when ``base`` is given, the destination with every
      existing component resolved (so a symlinked parent is followed) must stay
      inside the resolved ``base``. A ``../../etc/passwd`` or a symlinked
      directory that points outside the tree is refused here, not after the
      write has already happened.
    * **Collision** — with ``overwrite=False`` an existing destination is a hard
      error, so a create-only write cannot silently replace a file.

    Returns ``path`` unchanged so it can be inlined at a call site.
    """
    if path.is_symlink():
        raise UnsafeWriteTarget(f"refusing to write through a symlink: {path}")
    if not overwrite and path.exists():
        raise UnsafeWriteTarget(f"refusing to overwrite an existing file: {path}")
    if base is not None:
        resolved_base = base.resolve()
        resolved = path.resolve()  # follows existing (possibly symlinked) parents
        if resolved != resolved_base and resolved_base not in resolved.parents:
            raise UnsafeWriteTarget(
                f"write destination escapes the allowed base {resolved_base}: {path}"
            )
    return path


def read_regular_bytes(path: Path, *, max_bytes: int, label: str = "input") -> bytes:
    """Read at most ``max_bytes`` from one non-symlink regular file.

    The descriptor is validated after opening, closing the check/use gap for a
    path swapped to a directory or device. Platforms with ``O_NOFOLLOW`` also
    reject a final-component symlink in the open operation itself.
    """
    if not 1 <= max_bytes <= 1_000_000_000:
        raise ValueError("max_bytes must be between 1 and 1000000000")
    if path.is_symlink():
        raise OSError(f"{label} must not be a symlink: {path}")
    descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError(f"{label} must be a regular file: {path}")
        if metadata.st_size > max_bytes:
            raise ValueError(f"{label} exceeds the {max_bytes} byte limit: {path}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            content = handle.read(max_bytes + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(content) > max_bytes:
        raise ValueError(f"{label} grew beyond the {max_bytes} byte limit: {path}")
    return content


def read_regular_text(path: Path, *, max_bytes: int, label: str = "input") -> str:
    """Read bounded UTF-8 text from one non-symlink regular file."""
    try:
        return read_regular_bytes(path, max_bytes=max_bytes, label=label).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8: {path}") from exc


def atomic_write_bytes(
    path: Path, content: bytes, *, mode: int | None = None, overwrite: bool = True
) -> None:
    """Replace ``path`` with a unique, fsynced temporary file in its directory.

    With ``overwrite=False`` the destination is created *exclusively*: the temp
    file is hard-linked into place with :func:`os.link`, which fails if the
    destination already exists. Unlike a pre-write existence check this is
    race-free — two writers cannot both believe the path was free — so a
    create-only artifact can never clobber an existing file.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        if mode is not None:
            os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            temporary.replace(path)
        else:
            # os.link is atomic and refuses an existing destination; the temp
            # file is then unlinked, leaving exactly the destination behind.
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise UnsafeWriteTarget(
                    f"refusing to overwrite an existing file: {path}"
                ) from exc
            finally:
                temporary.unlink(missing_ok=True)
        _fsync_directory(path.parent)
    except BaseException:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_text(
    path: Path,
    content: str,
    *,
    mode: int | None = None,
    encoding: str = "utf-8",
    overwrite: bool = True,
) -> None:
    """Encode and durably persist one local text artifact.

    ``overwrite=False`` creates the file exclusively; see
    :func:`atomic_write_bytes`.
    """
    atomic_write_bytes(path, content.encode(encoding), mode=mode, overwrite=overwrite)


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:  # pragma: no cover - not every platform permits directory fsync
        return
    try:
        os.fsync(descriptor)
    except OSError:  # pragma: no cover - filesystem-dependent durability support
        pass
    finally:
        os.close(descriptor)
