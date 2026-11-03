"""Is each engine really here, the right one, at the pinned version? (no network, no target)

``check_all`` inspects the host against the manifests: the executable must be on ``PATH``,
answer its ``presence_probe``, be the engine the adapter expects (``httpx`` is also the
name of an unrelated Python HTTP client), match the pin (the commit for git engines, the
version for the rest) and have its pinned data dependencies in place. Anything that is not
fine comes with the exact install command derived from the manifest.

All I/O is injected (:class:`Environment`) so the checks are deterministic offline and the
probe can run through the same sandboxed runner scanners use.
"""

from __future__ import annotations

import importlib
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from olympus.core.exit_codes import ExitCode
from olympus.engines.loader import load_all, load_all_data
from olympus.engines.schema import EngineManifest
from olympus.integrations.scanners import by_name
from olympus.themis.base import ScannerAdapter, _safe_line

Which = Callable[[str], str | None]
#: Runs a fixed argv, returns ``(exit_code, combined_output)``; never raises.
Probe = Callable[[list[str]], tuple[int, str]]
#: ``git rev-parse HEAD`` of a checkout directory, or ``None`` when it is not one.
GitHead = Callable[[str], str | None]

_VERSION_TOKEN = re.compile(r"(?<![\w.])v?(\d+\.\d+(?:\.\d+)*[A-Za-z0-9]*)")
_ENTRYPOINT_PREFIX = "olympus."


class EngineState(StrEnum):
    PRESENT = "present"
    MISSING = "missing"
    UNUSABLE = "unusable"
    WRONG_TOOL = "wrong-tool"
    VERSION_MISMATCH = "version-mismatch"
    COMMIT_MISMATCH = "commit-mismatch"
    DATA_PROBLEM = "data-problem"
    REQUIRES_PRODUCT = "requires-product"


@dataclass(frozen=True)
class Environment:
    """Everything the checks need from the host, injectable for tests."""

    which: Which
    probe: Probe
    git_head: GitHead
    environ: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    #: Address-space limit the Themis sandbox would apply to a scanner on this host.
    sandbox_memory_bytes: int = 2 * 1024**3


@dataclass(frozen=True)
class DataStatus:
    name: str
    ok: bool
    expected_commit: str
    found_commit: str | None
    install_command: str


@dataclass(frozen=True)
class EngineStatus:
    name: str
    state: EngineState
    mandatory: bool
    pinned_version: str | None = None
    detected_version: str | None = None
    #: ``match`` / ``reported`` / ``mismatch`` / ``unknown`` / ``None`` (not checked).
    version_check: str | None = None
    path: str | None = None
    detail: str = ""
    install_command: str | None = None
    configured: bool | None = None
    data: tuple[DataStatus, ...] = ()
    in_scanner_image: bool = False
    #: Non-blocking observations (e.g. the sandbox memory limit is below what the engine needs).
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.state is EngineState.PRESENT

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "state": self.state.value,
            "ok": self.ok,
            "mandatory": self.mandatory,
            "pinned_version": self.pinned_version,
            "detected_version": self.detected_version,
            "version_check": self.version_check,
            "path": self.path,
            "detail": self.detail,
            "install_command": self.install_command,
            "configured": self.configured,
            "in_scanner_image": self.in_scanner_image,
            "notes": list(self.notes),
            "data": [
                {
                    "name": item.name,
                    "ok": item.ok,
                    "expected_commit": item.expected_commit,
                    "found_commit": item.found_commit,
                    "install_command": item.install_command,
                }
                for item in self.data
            ],
        }


@dataclass(frozen=True)
class Verdict:
    exit_code: ExitCode
    blocking: tuple[str, ...]
    optional_missing: tuple[str, ...]


def adapter_for(manifest: EngineManifest) -> ScannerAdapter | None:
    """Instantiate the manifest's adapter, refusing entrypoints outside ``olympus.``."""
    if manifest.adapter is None:
        return None
    module_name, _, class_name = manifest.adapter.entrypoint.partition(":")
    if not module_name.startswith(_ENTRYPOINT_PREFIX):
        raise ValueError(f"adapter entrypoint {manifest.adapter.entrypoint!r} is outside olympus.*")
    adapter_class = getattr(importlib.import_module(module_name), class_name)
    if not (isinstance(adapter_class, type) and issubclass(adapter_class, ScannerAdapter)):
        raise ValueError(f"{manifest.adapter.entrypoint} is not a ScannerAdapter")
    instance: ScannerAdapter = adapter_class()
    return instance


def _version_line(output: str) -> str:
    """The line that carries the version (banners come first and say nothing)."""
    lines = [_safe_line(line, 500) for line in output.splitlines() if line.strip()]
    for line in lines:
        if _VERSION_TOKEN.search(line):
            return line
    return lines[0] if lines else ""


def _version_check(manifest: EngineManifest, text: str) -> str:
    tokens = [match.group(1).lower() for match in _VERSION_TOKEN.finditer(text)]
    if not tokens:
        return "unknown"
    engine = manifest.engine
    pinned = (engine.pinned_version or "").lower().removeprefix("v")
    if pinned and any(token == pinned or token.startswith(pinned + "-") for token in tokens):
        return "match"
    reported = (engine.reported_version or "").lower().removeprefix("v")
    if reported and reported in tokens:
        return "reported"
    return "mismatch"


def _inspect_data(manifest: EngineManifest, env: Environment) -> tuple[DataStatus, ...]:
    available = load_all_data()
    statuses: list[DataStatus] = []
    for name in manifest.engine.requires_data:
        dependency = available[name]
        source = dependency.data.source
        found = env.git_head(str(source.checkout_path))
        statuses.append(
            DataStatus(
                name=name,
                ok=found == source.commit,
                expected_commit=str(source.commit),
                found_commit=found,
                install_command=dependency.install_command(),
            )
        )
    return tuple(statuses)


def _memory_notes(name: str, manifest: EngineManifest, env: Environment) -> tuple[str, ...]:
    adapter = manifest.adapter
    if adapter is None or adapter.min_memory_bytes is None:
        return ()
    if env.sandbox_memory_bytes >= adapter.min_memory_bytes:
        return ()
    return (
        f"the sandbox allows {env.sandbox_memory_bytes / 1024**3:.0f} GiB of address space but "
        f"{name} needs {adapter.min_memory_bytes / 1024**3:.0f} GiB with its full data set; "
        "raise THEMIS_SANDBOX_MEMORY_BYTES (the sandbox limit is never raised automatically)",
    )


def inspect_engine(name: str, manifest: EngineManifest, env: Environment) -> EngineStatus:
    """Check one engine against its manifest; never touches a target or the network."""
    engine, source = manifest.engine, manifest.engine.source
    spec = by_name(name)
    shipped = bool(spec and spec.in_scanner_image)
    install = manifest.install_command()
    base = {
        "name": name,
        "mandatory": engine.mandatory,
        "pinned_version": engine.pinned_version,
        "in_scanner_image": shipped,
    }
    if engine.distribution == "api":
        missing = [var for var in source.env_vars if not env.environ.get(var, "").strip()]
        return EngineStatus(
            **base,  # type: ignore[arg-type]
            state=EngineState.REQUIRES_PRODUCT,
            configured=not missing,
            detail=f"external product: {source.requires_product}"
            + (f"; unset: {', '.join(missing)}" if missing else ""),
        )

    binary = engine.presence_probe[0]
    path = env.which(binary)
    if path is None:
        return EngineStatus(
            **base,  # type: ignore[arg-type]
            state=EngineState.MISSING,
            detail=f"'{binary}' is not on PATH",
            install_command=install,
        )
    code, output = env.probe(list(engine.presence_probe))
    text = _version_line(output)
    if code != 0:
        return EngineStatus(
            **base,  # type: ignore[arg-type]
            state=EngineState.UNUSABLE,
            path=path,
            detail=f"probe {engine.presence_probe} exited {code}: {text[:200]}",
            install_command=install,
        )
    adapter = adapter_for(manifest)
    if adapter is not None and text and not adapter.recognises(text):
        return EngineStatus(
            **base,  # type: ignore[arg-type]
            state=EngineState.WRONG_TOOL,
            path=path,
            detected_version=text,
            detail=f"'{binary}' on PATH is not the {name} engine",
            install_command=install,
        )
    check = _version_check(manifest, output)
    data = _inspect_data(manifest, env)
    common = {**base, "path": path, "detected_version": text or None, "data": data}
    if engine.distribution == "git":
        head = env.git_head(str(source.checkout_path))
        if head != source.commit:
            return EngineStatus(
                **common,  # type: ignore[arg-type]
                state=EngineState.COMMIT_MISMATCH,
                version_check=check,
                detail=f"checkout {source.checkout_path} is at {head}, pinned {source.commit}",
                install_command=install,
            )
    elif check == "mismatch":
        return EngineStatus(
            **common,  # type: ignore[arg-type]
            state=EngineState.VERSION_MISMATCH,
            version_check=check,
            detail=f"detected {text!r}, pinned {engine.pinned_version}",
            install_command=install,
        )
    if any(not item.ok for item in data):
        bad = next(item for item in data if not item.ok)
        return EngineStatus(
            **common,  # type: ignore[arg-type]
            state=EngineState.DATA_PROBLEM,
            version_check=check,
            detail=(
                f"data dependency {bad.name} is at {bad.found_commit}, pinned {bad.expected_commit}"
            ),
            install_command=bad.install_command,
        )
    return EngineStatus(
        **common,  # type: ignore[arg-type]
        state=EngineState.PRESENT,
        version_check=check,
        notes=_memory_notes(name, manifest, env),
    )


def check_all(env: Environment, only: tuple[str, ...] = ()) -> list[EngineStatus]:
    manifests = load_all()
    names = sorted(only) if only else sorted(manifests)
    unknown = [name for name in names if name not in manifests]
    if unknown:
        raise KeyError(", ".join(unknown))
    return [inspect_engine(name, manifests[name], env) for name in names]


def verdict(statuses: list[EngineStatus], *, strict: bool = False) -> Verdict:
    """Blocking = a mandatory engine that is not fine (and, strict, any engine the image ships)."""
    blocking = [
        status.name
        for status in statuses
        if not status.ok
        and status.state is not EngineState.REQUIRES_PRODUCT
        and (status.mandatory or (strict and status.in_scanner_image))
    ]
    optional = [
        status.name
        for status in statuses
        if not status.ok
        and status.state is not EngineState.REQUIRES_PRODUCT
        and status.name not in blocking
    ]
    return Verdict(
        exit_code=ExitCode.ENGINE_MISSING if blocking else ExitCode.OK,
        blocking=tuple(blocking),
        optional_missing=tuple(optional),
    )
