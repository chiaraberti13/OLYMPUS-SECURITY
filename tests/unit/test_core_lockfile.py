"""The hash-pinned constraints generator (offline, via an injected fetcher)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core import lockfile

runner = CliRunner()


def _metadata(*digests: str, yanked_digest: str | None = None) -> str:
    urls = [
        {"filename": f"pkg-{i}.whl", "digests": {"sha256": d}}
        for i, d in enumerate(digests)
    ]
    if yanked_digest is not None:
        urls.append(
            {"filename": "pkg-yanked.whl", "yanked": True, "digests": {"sha256": yanked_digest}}
        )
    return json.dumps({"urls": urls})


# --- release_hashes_from_metadata ------------------------------------------ #


def test_hashes_are_extracted_and_sorted() -> None:
    body = _metadata("bbb", "aaa")
    assert lockfile.release_hashes_from_metadata("x", "1.0", body) == ["aaa", "bbb"]


def test_yanked_files_are_never_pinned() -> None:
    body = _metadata("good", yanked_digest="poisoned")
    assert lockfile.release_hashes_from_metadata("x", "1.0", body) == ["good"]


def test_metadata_without_files_is_an_error() -> None:
    with pytest.raises(lockfile.LockfileError, match="no files"):
        lockfile.release_hashes_from_metadata("x", "1.0", json.dumps({"urls": []}))


def test_metadata_without_a_digest_is_an_error() -> None:
    body = json.dumps({"urls": [{"filename": "p.whl", "digests": {}}]})
    with pytest.raises(lockfile.LockfileError, match="no SHA-256"):
        lockfile.release_hashes_from_metadata("x", "1.0", body)


def test_invalid_json_is_an_error() -> None:
    with pytest.raises(lockfile.LockfileError, match="invalid PyPI metadata"):
        lockfile.release_hashes_from_metadata("x", "1.0", "not json")


# --- render_constraints ----------------------------------------------------- #


def test_single_hash_is_rendered_inline() -> None:
    out = lockfile.render_constraints({"x": "1.0"}, {"x": ["deadbeef"]}, header=False)
    assert out == "x==1.0 --hash=sha256:deadbeef\n"


def test_multiple_hashes_use_pip_continuations() -> None:
    out = lockfile.render_constraints(
        {"pkg": "2.0"}, {"pkg": ["aaa", "bbb", "ccc"]}, header=False
    )
    assert out == (
        "pkg==2.0 \\\n"
        "    --hash=sha256:aaa \\\n"
        "    --hash=sha256:bbb \\\n"
        "    --hash=sha256:ccc\n"
    )
    # The last line must NOT carry a trailing backslash (pip would break).
    assert not out.rstrip("\n").endswith("\\")


def test_requirements_are_sorted() -> None:
    out = lockfile.render_constraints(
        {"zeta": "1", "alpha": "1"},
        {"zeta": ["z"], "alpha": ["a"]},
        header=False,
    )
    assert out.index("alpha") < out.index("zeta")


def test_render_fails_when_a_package_has_no_hashes() -> None:
    with pytest.raises(lockfile.LockfileError, match="no hashes resolved"):
        lockfile.render_constraints({"x": "1.0"}, {}, header=False)


def test_header_documents_the_install_command() -> None:
    out = lockfile.render_constraints({"x": "1.0"}, {"x": ["a"]}, header=True)
    assert "--require-hashes" in out
    assert out.count("\n") > 1


# --- generate_lockfile with an injected fetcher (no network) ---------------- #


def test_generate_lockfile_uses_the_real_closure() -> None:
    seen: list[tuple[str, str]] = []

    def fake_fetch(name: str, version: str) -> str:
        seen.append((name, version))
        return _metadata(f"hash-of-{name}")

    document = lockfile.generate_lockfile(fetcher=fake_fetch)
    # Every closure package was fetched and appears pinned with its hash.
    assert ("pydantic", _installed_version("pydantic")) in seen
    assert "pydantic==" in document
    assert "--hash=sha256:hash-of-pydantic" in document
    assert document.startswith("# Hash-pinned constraints")


def test_generate_lockfile_propagates_a_fetch_failure() -> None:
    def broken_fetch(name: str, version: str) -> str:
        raise lockfile.LockfileError("network down")

    with pytest.raises(lockfile.LockfileError, match="network down"):
        lockfile.generate_lockfile(fetcher=broken_fetch)


def _installed_version(name: str) -> str:
    from importlib.metadata import version

    return version(name)


# --- CLI -------------------------------------------------------------------- #


def test_lock_command_writes_a_file(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    monkeypatch.setattr(
        lockfile, "_http_fetch", lambda name, version: _metadata(f"h-{name}")
    )
    destination = tmp_path / "constraints.txt"
    result = runner.invoke(app, ["core", "lock", "--output", str(destination)])
    assert result.exit_code == 0, result.output
    body = destination.read_text()
    assert "--hash=sha256:h-pydantic" in body
    assert "--require-hashes" in body


def test_lock_command_reports_a_failure_with_exit_6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(name: str, version: str) -> str:
        raise lockfile.LockfileError("PyPI unreachable")

    monkeypatch.setattr(lockfile, "_http_fetch", boom)
    result = runner.invoke(app, ["core", "lock"])
    assert result.exit_code == 6
    assert "cannot generate lockfile" in result.output
