"""Keep the threat model and CODEOWNERS honest against the real repository.

The threat model names a concrete module for every control it claims. This test
asserts each named module still imports, so the document cannot drift into
describing a control that no longer exists — the same discipline used for the
maturity ledger and the scanner matrix.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_THREAT_MODEL = _ROOT / "docs" / "threat-model.md"
_CODEOWNERS = _ROOT / ".github" / "CODEOWNERS"

#: `olympus.<...>` dotted module paths mentioned anywhere in the document.
_MODULE = re.compile(r"`(olympus\.[a-z_][a-z0-9_.]+)`")

#: The security-critical modules whose ownership CODEOWNERS must assert, as file
#: paths. If a guard's ownership is dropped, a change to it could merge
#: unreviewed.
_OWNED_PATHS = (
    "/src/olympus/core/addresses.py",
    "/src/olympus/core/pinning.py",
    "/src/olympus/core/execution.py",
    "/src/olympus/core/policy.py",
    "/src/olympus/aegis/sandbox.py",
    "/src/olympus/core/sbom.py",
    "/src/olympus/core/lockfile.py",
)


#: Config *filenames* look like dotted modules (olympus.policy.toml); exclude them.
_FILE_SUFFIXES = (".toml", ".json", ".yaml", ".yml", ".md", ".txt", ".cfg", ".ini")


def _named_modules() -> set[str]:
    text = _THREAT_MODEL.read_text(encoding="utf-8")
    return {
        name
        for name in _MODULE.findall(text)
        if not name.endswith(_FILE_SUFFIXES)
    }


def test_threat_model_exists() -> None:
    assert _THREAT_MODEL.is_file()


def test_every_named_module_is_importable() -> None:
    problems: list[str] = []
    for dotted in sorted(_named_modules()):
        module = _longest_importable_prefix(dotted)
        if module is None:
            problems.append(dotted)
    assert not problems, f"threat model names modules that do not import: {problems}"


def _longest_importable_prefix(dotted: str) -> str | None:
    parts = dotted.split(".")
    while len(parts) >= 2:
        candidate = ".".join(parts)
        try:
            importlib.import_module(candidate)
            return candidate
        except ModuleNotFoundError:
            parts.pop()
    return None


def test_threat_model_references_the_key_controls() -> None:
    modules = _named_modules()
    for expected in (
        "olympus.core.addresses",   # SSRF guard
        "olympus.core.pinning",     # DNS rebinding
        "olympus.aegis.sandbox",    # host isolation
        "olympus.core.policy",      # bounds
        "olympus.core.lockfile",    # supply chain
        "olympus.integrations.maturity",  # catalogue honesty
    ):
        assert expected in modules, f"threat model no longer covers {expected}"


def test_threat_model_admits_open_gaps() -> None:
    """The 'not yet covered' section is a control; it must not quietly vanish."""
    text = _THREAT_MODEL.read_text(encoding="utf-8")
    assert "What is NOT yet covered" in text
    assert "seccomp" in text  # a known, named open item


# --- CODEOWNERS ------------------------------------------------------------- #


def test_codeowners_exists_and_has_a_default_owner() -> None:
    text = _CODEOWNERS.read_text(encoding="utf-8")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    assert any(ln.startswith("* ") for ln in lines), "no catch-all owner in CODEOWNERS"
    assert all("@" in ln for ln in lines), "a CODEOWNERS rule has no owner"


@pytest.mark.parametrize("path", _OWNED_PATHS)
def test_security_critical_paths_have_an_explicit_owner(path: str) -> None:
    text = _CODEOWNERS.read_text(encoding="utf-8")
    owned = {
        ln.split()[0]
        for ln in text.splitlines()
        if ln.strip() and not ln.startswith("#") and "@" in ln
    }
    assert path in owned, f"{path} has no explicit CODEOWNERS owner"


def test_owned_security_paths_exist_in_the_tree() -> None:
    """A CODEOWNERS rule for a moved/deleted file silently stops protecting it."""
    for path in _OWNED_PATHS:
        assert (_ROOT / path.lstrip("/")).is_file(), f"CODEOWNERS points at a missing file: {path}"
