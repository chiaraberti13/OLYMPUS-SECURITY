"""The image smoke script and the CI job that runs it (no Docker needed)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

from olympus.engines.loader import load_all, load_all_data
from olympus.integrations.scanners import REGISTRY

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]


def _module():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "smoke_scanner_image", ROOT / "scripts" / "smoke_scanner_image.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _healthy(argv: list[str]) -> tuple[int, str]:
    if "git" in argv and "rev-parse" in argv:
        checkout = argv[argv.index("-C") + 1]
        for manifest in load_all().values():
            if manifest.engine.source.checkout_path == checkout:
                return 0, str(manifest.engine.source.commit)
        for dep in load_all_data().values():
            if dep.data.source.checkout_path == checkout:
                return 0, str(dep.data.source.commit)
    return 0, "ok"


def test_a_matching_image_passes() -> None:
    assert _module().smoke("img", _healthy) == []


def test_every_shipped_engine_is_probed_and_nothing_else() -> None:
    probed: list[str] = []

    def runner(argv: list[str]) -> tuple[int, str]:
        if "--entrypoint" in argv:
            probed.append(argv[argv.index("--entrypoint") + 1])
        return _healthy(argv)

    _module().smoke("img", runner)
    expected = {
        load_all()[spec.name].engine.presence_probe[0]
        for spec in REGISTRY
        if spec.in_scanner_image and spec.binary is not None
    }
    assert expected <= set(probed)
    assert "nikto" not in probed and "zap" not in probed  # not shipped


def test_a_failing_probe_and_a_wrong_commit_are_both_reported() -> None:
    def runner(argv: list[str]) -> tuple[int, str]:
        if argv[argv.index("--entrypoint") + 1] == "nuclei":
            return 127, "not found"
        if "rev-parse" in argv:
            return 0, "0" * 40
        return 0, "ok"

    problems = _module().smoke("img", runner)
    assert any(p.startswith("nuclei: presence probe") for p in problems)
    assert any(p.startswith("xsstrike: checkout is at") for p in problems)


def test_a_missing_notice_is_reported() -> None:
    def runner(argv: list[str]) -> tuple[int, str]:
        return (1, "") if argv[-2:] == ["-f", "/NOTICE"] else _healthy(argv)

    assert any("NOTICE" in p for p in _module().smoke("img", runner))


def test_main_usage_and_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    module = _module()
    assert module.main([]) == 2
    assert "usage" in capsys.readouterr().err


def test_ci_builds_the_image_on_pushes_and_pull_requests_then_smoke_tests_it() -> None:
    text = (ROOT / ".github" / "workflows" / "docker-build.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on") or workflow[True]  # PyYAML reads the key `on` as True
    assert {"push", "pull_request", "workflow_dispatch"} <= set(triggers)
    assert "docker/**" in triggers["push"]["paths"]
    assert triggers["pull_request"] is None
    assert workflow["jobs"]["gate"]["if"] == "always()"
    assert workflow["jobs"]["gate"]["needs"] == ["changes", "build"]
    assert workflow["jobs"]["build"]["needs"] == "changes"
    steps = [step.get("run", "") for step in workflow["jobs"]["build"]["steps"]]
    assert any("docker build" in s and "docker/Dockerfile.scanners" in s for s in steps)
    assert any("scripts/smoke_scanner_image.py" in s for s in steps)
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] is True


def test_a_wrong_template_commit_is_reported() -> None:
    def runner(argv: list[str]) -> tuple[int, str]:
        if "rev-parse" in argv and "/opt/nuclei-templates" in argv:
            return 0, "1" * 40
        return _healthy(argv)

    problems = _module().smoke("img", runner)
    assert any(p.startswith("nuclei-templates: checkout is at") for p in problems)


def test_probes_run_with_a_writable_home_and_git_trusts_the_root_owned_checkouts() -> None:
    seen: list[list[str]] = []

    def runner(argv: list[str]) -> tuple[int, str]:
        seen.append(argv)
        return _healthy(argv)

    _module().smoke("img", runner)
    assert all(argv[:5] == ["run", "--rm", "--env", "HOME=/tmp", "--entrypoint"] for argv in seen)
    git_calls = [argv for argv in seen if "rev-parse" in argv]
    assert git_calls and all(
        any(a.startswith("safe.directory=/opt/") for a in argv) for argv in git_calls
    )
