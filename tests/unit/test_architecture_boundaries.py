"""Architecture boundary guards (ROADMAP ``DEV-A``).

Olympus follows a hexagonal layering: ``domain`` is pure, immutable logic with
**no I/O and no framework imports**; ``application`` coordinates use cases;
``adapters`` hold the concrete infrastructure wired in at the edges (see
``docs/architecture/adr-002-athena-target-architecture.md`` and the project
conventions). The shared data contract in ``olympus.core`` is likewise the heart
of the platform and must stay framework-free so every surface can consume it.

Those boundaries were documented and followed, but nothing *enforced* them in
CI, so an accidental ``import fastapi`` in a domain module or a reverse import
from a lower layer could slip in unnoticed. These tests close that gap: they
parse the real import graph with :mod:`ast` and fail the build on

* a domain module importing a web/CLI/TUI/DB/network framework or the network
  client, or reaching *up* into ``application``/``adapters``/``cli``/``api``/
  ``web``/``tui`` (an inverted dependency);
* a core contract module importing one of those frameworks.

The guards are deliberately true of the code as it stands today; they only
prevent regressions, never force a refactor.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "olympus"

#: Third-party frameworks and I/O stacks that must never reach a pure layer.
#: Pydantic is intentionally absent: it is the data-contract library, used for
#: pure validation, not I/O.
FORBIDDEN_FRAMEWORKS: frozenset[str] = frozenset(
    {
        "typer",
        "click",
        "textual",
        "rich",
        "fastapi",
        "starlette",
        "uvicorn",
        "sqlalchemy",
        "alembic",
        "celery",
        "redis",
        "httpx",
        "requests",
        "aiohttp",
        "reportlab",
    }
)

#: Standard-library modules that mean direct network / process / database / disk
#: access — the hallmark of infrastructure, never of pure domain logic.
FORBIDDEN_IO: frozenset[str] = frozenset(
    {
        "socket",
        "ssl",
        "subprocess",
        "sqlite3",
        "asyncio",
        "selectors",
        "smtplib",
        "ftplib",
        "telnetlib",
        "http.client",
        "urllib.request",
    }
)

#: Olympus' own network client is infrastructure; a pure layer must not import it.
FORBIDDEN_INTERNAL: frozenset[str] = frozenset({"olympus.core.http"})

#: Layer names a lower layer must never import *from* (an inverted dependency).
UPPER_LAYERS: tuple[str, ...] = ("application", "adapters", "cli", "api", "web", "tui")

#: The shared data-contract kernel: pure contracts every surface consumes.
CORE_CONTRACT_MODULES: tuple[str, ...] = (
    "models.py",
    "contracts.py",
    "enums.py",
    "ids.py",
    "errors.py",
    "exit_codes.py",
    "coverage.py",
)


def _imported_modules(path: Path) -> set[str]:
    """Return every fully-qualified module name imported by one source file.

    Relative imports are resolved against the file's package so a
    ``from . import x`` is comparable to an absolute dotted name.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    try:  # package parts are only needed to resolve relative imports
        package_parts = path.relative_to(SRC.parent).with_suffix("").parts[:-1]
    except ValueError:  # a file outside the source tree (e.g. a tmp_path sample)
        package_parts = ()
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import: resolve to an absolute module
                base = list(package_parts[: len(package_parts) - (node.level - 1)])
                module = ".".join([*base, node.module] if node.module else base)
            else:
                module = node.module or ""
            if module:
                found.add(module)
    return found


def _matches(module: str, needles: frozenset[str]) -> bool:
    """True if ``module`` equals or is a submodule of any needle."""
    return any(module == needle or module.startswith(f"{needle}.") for needle in needles)


def _domain_packages() -> list[Path]:
    """Every ``domain`` package under src/olympus (future-proof discovery)."""
    return sorted(p for p in SRC.glob("**/domain") if p.is_dir())


def _reverse_import(module: str) -> bool:
    """True if ``module`` is an Olympus upper-layer module (an inverted import)."""
    if not module.startswith("olympus."):
        return False
    return any(f".{layer}" in f".{module}." for layer in UPPER_LAYERS)


def test_at_least_one_domain_package_is_guarded() -> None:
    # A guard over an empty set would pass vacuously; make the coverage explicit.
    assert _domain_packages(), "no domain package found to guard"


def test_domain_layers_are_pure_and_never_import_infrastructure() -> None:
    violations: list[str] = []
    for package in _domain_packages():
        for source in package.rglob("*.py"):
            for module in _imported_modules(source):
                rel = source.relative_to(SRC.parent)
                if _matches(module, FORBIDDEN_FRAMEWORKS):
                    violations.append(f"{rel}: forbidden framework import {module!r}")
                elif _matches(module, FORBIDDEN_IO):
                    violations.append(f"{rel}: forbidden I/O import {module!r}")
                elif _matches(module, FORBIDDEN_INTERNAL):
                    violations.append(f"{rel}: forbidden network-client import {module!r}")
    assert not violations, "domain purity violations:\n" + "\n".join(violations)


def test_domain_layers_never_import_upper_layers() -> None:
    violations: list[str] = []
    for package in _domain_packages():
        for source in package.rglob("*.py"):
            for module in _imported_modules(source):
                if _reverse_import(module):
                    rel = source.relative_to(SRC.parent)
                    violations.append(f"{rel}: inverted dependency on {module!r}")
    assert not violations, "reverse-import violations:\n" + "\n".join(violations)


def test_core_contract_kernel_stays_framework_free() -> None:
    violations: list[str] = []
    for name in CORE_CONTRACT_MODULES:
        source = SRC / "core" / name
        assert source.is_file(), f"missing core contract module {name}"
        for module in _imported_modules(source):
            if _matches(module, FORBIDDEN_FRAMEWORKS) or _matches(module, FORBIDDEN_IO):
                violations.append(f"core/{name}: forbidden import {module!r}")
            elif _matches(module, FORBIDDEN_INTERNAL):
                violations.append(f"core/{name}: forbidden network-client import {module!r}")
    assert not violations, "core contract purity violations:\n" + "\n".join(violations)


def test_guard_detects_a_planted_violation(tmp_path: Path) -> None:
    """The guard must actually catch a forbidden import, not pass vacuously."""
    planted = tmp_path / "domain_sample.py"
    planted.write_text(
        "from __future__ import annotations\nimport fastapi\nfrom olympus.x.adapters import A\n",
        encoding="utf-8",
    )
    modules = _imported_modules(planted)
    assert any(_matches(m, FORBIDDEN_FRAMEWORKS) for m in modules)
    assert any(_reverse_import(m) for m in modules)
