"""The shared fail-closed engine preflight decides, offline, whether a scan may launch.

Covers the decision logic (mandatory + named required; api engines never block), the
fail-closed guarantee proven with an injected environment whose probe raises if touched
(so a missing engine is decided with zero process/network I/O), and the CLI exit contract
(0 ready / 8 engine-missing / 2 unknown engine).
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.engines.doctor import EngineState, EngineStatus, Environment
from olympus.engines.loader import load_all
from olympus.engines.preflight import (
    PreflightVerdict,
    UnknownEngineError,
    preflight,
    required_engines,
)

runner = CliRunner()

_MANDATORY = {"nmap", "nuclei", "httpx"}


def _never_probe(argv: list[str]) -> tuple[int, str]:
    raise AssertionError(f"preflight must not run a process during the decision: {argv!r}")


def _all_missing_env() -> Environment:
    """A host where nothing is installed; the probe raises if the decision ever runs one.

    ``which`` returning ``None`` must be enough to decide "missing", so reaching ``probe``
    would be a fail-open bug (a network/process touch before the engine is confirmed present).
    """
    return Environment(
        which=lambda binary: None,
        probe=_never_probe,
        git_head=lambda directory: None,
        environ={},
    )


def _present(name: str, *, mandatory: bool = False) -> EngineStatus:
    return EngineStatus(name=name, state=EngineState.PRESENT, mandatory=mandatory)


# --------------------------------------------------------------------------- required set


def test_required_engines_is_the_mandatory_set_plus_named() -> None:
    manifests = load_all()
    assert set(required_engines(manifests, ())) == _MANDATORY
    assert set(required_engines(manifests, ("sqlmap",))) == _MANDATORY | {"sqlmap"}


def test_required_engines_rejects_an_unknown_name() -> None:
    with pytest.raises(UnknownEngineError, match="definitely-not-an-engine"):
        required_engines(load_all(), ("definitely-not-an-engine",))


# ----------------------------------------------------------------- fail-closed, offline


def test_preflight_blocks_every_missing_mandatory_engine_without_touching_a_process() -> None:
    verdict = preflight(_all_missing_env())
    assert verdict.exit_code is ExitCode.ENGINE_MISSING
    assert not verdict.ok
    assert {status.name for status in verdict.blocking} == _MANDATORY
    # The audit record carries the exact install command and no secret/target.
    audit = verdict.audit_metadata()
    assert set(audit["required_engines"]) == _MANDATORY  # type: ignore[arg-type]
    assert all(entry["install_command"] for entry in audit["blocking_engines"])  # type: ignore[union-attr,index]


def test_preflight_is_ready_when_every_required_engine_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "olympus.engines.preflight.inspect_engine",
        lambda name, manifest, env: _present(name, mandatory=name in _MANDATORY),
    )
    verdict = preflight(_all_missing_env(), engines=("sqlmap",))
    assert verdict.ok
    assert verdict.exit_code is ExitCode.OK
    assert verdict.blocking == ()
    assert set(verdict.required) == _MANDATORY | {"sqlmap"}


def test_an_api_engine_is_never_blocking(monkeypatch: pytest.MonkeyPatch) -> None:
    # nessus is an api/commercial engine: it has no local artifact and can never be required.
    def fake(name: str, manifest: object, env: object) -> EngineStatus:
        if name == "nessus":
            return EngineStatus(name=name, state=EngineState.REQUIRES_PRODUCT, mandatory=False)
        return _present(name, mandatory=name in _MANDATORY)

    monkeypatch.setattr("olympus.engines.preflight.inspect_engine", fake)
    verdict = preflight(_all_missing_env(), engines=("nessus",))
    assert verdict.ok  # the unreachable api product does not block the launch


def test_a_missing_named_engine_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(name: str, manifest: object, env: object) -> EngineStatus:
        if name == "sqlmap":
            return EngineStatus(
                name=name, state=EngineState.MISSING, mandatory=False, install_command="pip ..."
            )
        return _present(name, mandatory=name in _MANDATORY)

    monkeypatch.setattr("olympus.engines.preflight.inspect_engine", fake)
    verdict = preflight(_all_missing_env(), engines=("sqlmap",))
    assert verdict.exit_code is ExitCode.ENGINE_MISSING
    assert {status.name for status in verdict.blocking} == {"sqlmap"}


# ------------------------------------------------------------------------------ CLI


def test_cli_preflight_exits_8_on_a_clean_host() -> None:
    result = runner.invoke(app, ["engines", "preflight"])
    assert result.exit_code == int(ExitCode.ENGINE_MISSING)
    assert "preflight BLOCKED" in result.output
    # Each blocking engine is shown with its exact install command.
    assert "install:" in result.output


def test_cli_preflight_exits_0_when_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "olympus.engines.cli.preflight",
        lambda env, engines=(): PreflightVerdict(ExitCode.OK, ("nmap", "nuclei", "httpx"), ()),
    )
    result = runner.invoke(app, ["engines", "preflight"])
    assert result.exit_code == 0
    assert "preflight OK" in result.output


def test_cli_preflight_rejects_an_unknown_engine() -> None:
    result = runner.invoke(app, ["engines", "preflight", "--engine", "definitely-not-an-engine"])
    assert result.exit_code == int(ExitCode.USAGE)
    assert "unknown engine" in result.output


def test_scanner_readiness_flags_a_wrong_commit_data_dependency() -> None:
    # The point of the full scanner readiness (vs a bare PATH lookup): nuclei's binary can be
    # present and at the right version, yet the engine is NOT ready if its pinned data
    # dependency (nuclei-templates) is at the wrong commit — a bare `which` would miss it.
    from olympus.engines.loader import load_all_data, manifest_for
    from olympus.engines.preflight import scanner_readiness

    manifest = manifest_for("nuclei")
    templates_path = str(load_all_data()["nuclei-templates"].data.source.checkout_path)
    version = (manifest.engine.pinned_version or "").lstrip("v")

    def which(binary: str) -> str:
        return f"/usr/bin/{binary}"

    def probe(argv: list[str]) -> tuple[int, str]:
        return (0, f"nuclei {version}")

    def git_head(directory: str) -> str | None:
        # The templates checkout is at a different commit than the pin.
        return "0" * 40 if directory == templates_path else None

    env = Environment(which=which, probe=probe, git_head=git_head, environ={})
    status = scanner_readiness(env, "nuclei")
    assert status is not None
    assert not status.ok
    assert status.state is EngineState.DATA_PROBLEM


def test_scanner_readiness_is_none_for_an_ungoverned_scanner() -> None:
    from olympus.engines.preflight import scanner_readiness

    assert scanner_readiness(_all_missing_env(), "not-a-real-engine") is None
