"""The shared fail-closed engine preflight decides, offline, whether a scan may launch.

Covers the decision logic (mandatory + named required; api engines never block), the
fail-closed guarantee proven with an injected environment whose probe raises if touched
(so a missing engine is decided with zero process/network I/O), and the CLI exit contract
(0 ready / 8 engine-missing / 2 unknown engine).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.engines.doctor import EngineState, EngineStatus, Environment
from olympus.engines.loader import load_all
from olympus.engines.preflight import (
    EnginePreflightReport,
    PreflightVerdict,
    UnknownEngineError,
    build_preflight_report,
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


def test_table_output_reports_the_specific_blocker(monkeypatch, blocking_preflight):
    monkeypatch.setattr("olympus.engines.cli.preflight", lambda *a, **kw: blocking_preflight)
    result = runner.invoke(app, ["engines", "preflight", "--format", "table"])
    assert result.exit_code == 8
    assert f"REQUIRED: nmap ({blocking_preflight.blocking[0].state.value})" in result.output


def test_cli_preflight_exits_8_on_a_clean_host() -> None:
    result = runner.invoke(app, ["engines", "preflight"])
    assert result.exit_code == int(ExitCode.ENGINE_MISSING)
    assert "preflight BLOCKED" in result.output
    # Each blocking engine is shown with its exact install command.
    assert "install:" in result.output


def test_cli_preflight_exits_0_when_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "olympus.engines.cli.preflight",
        lambda env, engines=(), commands=(), allow_missing=False: PreflightVerdict(
            ExitCode.OK, ("nmap", "nuclei", "httpx"), ()
        ),
    )
    result = runner.invoke(app, ["engines", "preflight"])
    assert result.exit_code == 0
    assert "preflight OK" in result.output


def test_cli_preflight_json_output_is_a_versioned_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    # The preflight JSON gates CI/automation, so it is the versioned contract
    # olympus.engine-preflight, not an ad-hoc dict (TOOLS-4.1).
    monkeypatch.setattr(
        "olympus.engines.cli.preflight",
        lambda env, engines=(), commands=(), allow_missing=False: PreflightVerdict(
            ExitCode.OK, ("httpx", "nmap", "nuclei"), ()
        ),
    )
    result = runner.invoke(app, ["engines", "preflight", "--format", "json"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["schema_name"] == "olympus.engine-preflight"
    assert document["schema_version"] == "1.1.0"
    report = EnginePreflightReport.model_validate(document)
    assert report.ready is True
    assert report.required == ["httpx", "nmap", "nuclei"]
    assert report.blocking == []


def test_cli_preflight_json_reports_blocking_engines_with_install_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked = EngineStatus(
        name="nmap",
        state=EngineState.MISSING,
        mandatory=True,
        detail="'nmap' is not on PATH",
        install_command="git -C /opt/nmap fetch ...",
    )
    monkeypatch.setattr(
        "olympus.engines.cli.preflight",
        lambda env, engines=(), commands=(), allow_missing=False: PreflightVerdict(
            ExitCode.ENGINE_MISSING, ("nmap",), (blocked,)
        ),
    )
    result = runner.invoke(app, ["engines", "preflight", "--format", "json"])
    assert result.exit_code == int(ExitCode.ENGINE_MISSING)
    report = EnginePreflightReport.model_validate(json.loads(result.stdout))
    assert report.ready is False
    assert report.blocking[0].name == "nmap"
    assert report.blocking[0].state == "missing"
    assert report.blocking[0].install_command == "git -C /opt/nmap fetch ..."


def test_engine_preflight_is_a_published_output_contract() -> None:
    from olympus.schema_catalog import catalog_files

    catalog = json.loads(catalog_files()[Path("catalog.json")])
    entry = next(c for c in catalog["contracts"] if c["name"] == "olympus.engine-preflight")
    assert entry["direction"] == "output"
    assert entry["schema_version"] == "1.1.0"


def test_allow_missing_never_waives_a_named_or_mandatory_engine() -> None:
    # The opt-in is limited to OPTIONAL dependencies: an explicitly-named engine is always
    # required (TOOLS-4.1 "l'engine nominato esplicitamente è sempre richiesto"), so even with
    # ``allow_missing`` both the named engine and the mandatory baseline BLOCK (exit 8), and
    # nothing is degraded (today no manifest declares a command-pulled optional dependency).
    verdict = preflight(_all_missing_env(), engines=("katana",), allow_missing=True)
    assert verdict.exit_code is ExitCode.ENGINE_MISSING
    assert {s.name for s in verdict.blocking} == _MANDATORY | {"katana"}
    assert verdict.degraded == ()


def _synthetic_optional_manifest() -> object:
    """A governed engine required ONLY for ``themis.run`` (an optional command dependency)."""
    from olympus.engines.loader import parse_manifest

    return parse_manifest(
        """
[engine]
name = "demo"
category = "web"
upstream = "https://github.com/example/demo"
language = "Go"
license = "MIT"
distribution = "go"
pinned_version = "v1.2.3"
update_policy = "minor"
presence_probe = ["demo", "-version"]
capability = "web.scan"
required_for_commands = ["themis.run"]
[engine.source]
module = "github.com/example/demo/cmd/demo"
[adapter]
entrypoint = "olympus.themis.adapters.nuclei:NucleiAdapter"
timeout_seconds = 600
resource_profile = "network-heavy"
"""
    )


@pytest.mark.parametrize(
    "state",
    [
        EngineState.MISSING,
        EngineState.WRONG_TOOL,
        EngineState.UNUSABLE,
        EngineState.VERSION_MISMATCH,
        EngineState.COMMIT_MISMATCH,
        EngineState.DATA_PROBLEM,
    ],
)
def test_allow_missing_degrades_only_an_absent_optional_command_dependency(
    monkeypatch: pytest.MonkeyPatch,
    state: EngineState,
) -> None:
    # With the mandatory baseline present and ONLY a command-pulled optional dependency
    # missing, the opt-in degrades it (exit 5), never blocks — the one case ``allow_missing``
    # is for. Without the opt-in the same gap blocks (fail-closed).
    from olympus.engines.commands import THEMIS_RUN

    manifests = dict(load_all())
    manifests["demo"] = _synthetic_optional_manifest()  # type: ignore[assignment]
    monkeypatch.setattr("olympus.engines.preflight.load_all", lambda: manifests)
    monkeypatch.setattr(
        "olympus.engines.preflight.inspect_engine",
        lambda name, manifest, env: (
            EngineStatus(name=name, state=state, mandatory=False)
            if name == "demo"
            else _present(name, mandatory=name in _MANDATORY)
        ),
    )

    degraded_verdict = preflight(_all_missing_env(), commands=(THEMIS_RUN,), allow_missing=True)
    if state is EngineState.MISSING:
        audit = degraded_verdict.audit_metadata()
        assert audit["exit_code"] == 5
        assert audit["blocking_engines"] == []
        assert degraded_verdict.exit_code is ExitCode.PARTIAL
        assert degraded_verdict.blocking == ()
        assert {s.name for s in degraded_verdict.degraded} == {"demo"}
    else:
        assert degraded_verdict.exit_code is ExitCode.ENGINE_MISSING
        assert degraded_verdict.degraded == ()
        assert [(s.name, s.state) for s in degraded_verdict.blocking] == [("demo", state)]

    strict_verdict = preflight(_all_missing_env(), commands=(THEMIS_RUN,))
    assert strict_verdict.exit_code is ExitCode.ENGINE_MISSING
    assert {s.name for s in strict_verdict.blocking} == {"demo"}


def test_optional_only_missing_is_degraded_exit_5() -> None:
    # An optional-only gap (no mandatory missing) is degraded (exit 5), never blocking.
    status = EngineStatus(
        name="katana", state=EngineState.MISSING, mandatory=False, detail="not on PATH"
    )
    verdict = PreflightVerdict(ExitCode.PARTIAL, ("katana",), (), (status,))
    report = build_preflight_report(verdict)
    assert report.schema_version == "1.1.0"
    assert report.degraded[0].name == "katana" and report.blocking == []
    assert report.exit_code == int(ExitCode.PARTIAL)


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


def test_every_surface_reads_one_verdict_and_the_exit_vocabulary_is_closed() -> None:
    """Parity + exit-vocabulary contract (TOOLS-4.1 acceptance).

    CLI, API, Web and the worker never invent an exit code: they all read the single shared
    ``PreflightVerdict``. This pins that the versioned report (the API ``/engines/preflight``,
    the Web ``/tools`` block and ``engines preflight --format json`` all serialize it) and the
    audit record each interface writes echo *exactly* the verdict's code, that ``ready`` is true
    only for a clean pass, and that a preflight speaks **only** the canonical ``{0, 5, 8}`` slice
    of the 0-8 vocabulary — ready, degraded (an optional engine tolerated) and engine-missing
    (a mandatory/blocking gap), never anything else."""
    optional_status = EngineStatus(
        name="katana", state=EngineState.MISSING, mandatory=False, detail="not on PATH"
    )
    blocking_status = EngineStatus(
        name="nmap", state=EngineState.MISSING, mandatory=True, detail="not on PATH"
    )
    ready = PreflightVerdict(ExitCode.OK, ("nmap",), ())
    degraded = PreflightVerdict(ExitCode.PARTIAL, ("katana",), (), (optional_status,))
    blocking = PreflightVerdict(ExitCode.ENGINE_MISSING, ("nmap",), (blocking_status,))

    # The preflight's entire exit vocabulary is exactly these three canonical codes.
    assert {int(v.exit_code) for v in (ready, degraded, blocking)} == {0, 5, 8}

    for verdict, expected in ((ready, 0), (degraded, 5), (blocking, 8)):
        report = build_preflight_report(verdict)
        # The serialized surface shared by API, Web and the CLI JSON output.
        assert report.exit_code == expected
        # The audit record every interface writes from the same verdict.
        assert verdict.audit_metadata()["exit_code"] == expected
        # `ready` is true only for a clean pass — never for a degraded (exit 5) run.
        assert report.ready is (verdict.exit_code is ExitCode.OK)
