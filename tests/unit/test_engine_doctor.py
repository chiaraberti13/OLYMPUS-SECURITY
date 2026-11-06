"""The doctor: a clean host, a healthy host, and every way an engine can be wrong."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core.exit_codes import ExitCode
from olympus.engines import cli as engines_cli
from olympus.engines.doctor import (
    EngineState,
    EngineStatus,
    Environment,
    adapter_for,
    check_all,
    inspect_engine,
    verdict,
)
from olympus.engines.loader import ENGINES_ROOT, load_all, load_all_data, parse_manifest

pytestmark = pytest.mark.unit

NUCLEI_BANNER = "[INF] Nuclei Engine Version: v3.11.1"
VERSIONS = {
    "nmap": "Nmap version 7.992 ( https://nmap.org )",
    "nuclei": f"{NUCLEI_BANNER}\n[INF] Nuclei Config Directory: /x",
    "httpx": "  __ __\n[INF] Current Version: v1.11.0",
    "xsstrike": "XSStrike v3.1.5",
}
MANDATORY = ("nmap", "nuclei", "httpx")
API_ENGINES = {"zap", "openvas", "nessus", "burp", "acunetix"}


def _commit(name: str) -> str:
    return str(load_all()[name].engine.source.commit)


def _env(
    present: dict[str, str] | None = None,
    heads: dict[str, str] | None = None,
    environ: dict[str, str] | None = None,
    exits: dict[str, int] | None = None,
) -> Environment:
    present, heads, exits = present or {}, heads or {}, exits or {}

    def which(binary: str) -> str | None:
        return f"/usr/bin/{binary}" if binary in present else None

    def probe(argv: list[str]) -> tuple[int, str]:
        return exits.get(argv[0], 0), present.get(argv[0], "")

    return Environment(
        which=which, probe=probe, git_head=lambda path: heads.get(path), environ=environ or {}
    )


def _healthy() -> Environment:
    templates = load_all_data()["nuclei-templates"].data.source
    heads = {"/opt/nmap": _commit("nmap"), str(templates.checkout_path): str(templates.commit)}
    return _env(present={name: VERSIONS[name] for name in MANDATORY}, heads=heads)


def _status(name: str, env: Environment) -> EngineStatus:
    return inspect_engine(name, load_all()[name], env)


# --- a clean machine -------------------------------------------------------- #
def test_a_clean_machine_lists_every_mandatory_engine_with_its_exact_install_command() -> None:
    statuses = check_all(_env())
    result = verdict(statuses)
    assert result.exit_code is ExitCode.ENGINE_MISSING
    assert set(result.blocking) == set(MANDATORY)
    by_name = {status.name: status for status in statuses}
    assert by_name["nuclei"].install_command == (
        "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1"
    )
    nmap_install = str(by_name["nmap"].install_command)
    assert "git -C /opt/nmap fetch --depth 1 https://github.com/nmap/nmap " in nmap_install
    assert all(by_name[name].state is EngineState.MISSING for name in result.blocking)
    assert "sqlmap" in result.optional_missing and "sqlmap" not in result.blocking


def test_api_engines_are_reported_as_products_and_never_block() -> None:
    statuses = check_all(_env(environ={"THEMIS_ZAP_URL": "http://z"}))
    by_name = {status.name: status for status in statuses}
    assert by_name["zap"].state is EngineState.REQUIRES_PRODUCT
    assert by_name["zap"].configured is False  # the API key variable is unset
    assert "THEMIS_ZAP_API_KEY" in by_name["zap"].detail
    assert by_name["burp"].install_command is None
    assert not API_ENGINES & set(verdict(statuses, strict=True).blocking)


def test_secret_values_are_never_read_into_the_report() -> None:
    environ = {"THEMIS_ZAP_URL": "http://z", "THEMIS_ZAP_API_KEY": "sup3r-s3cret-value"}
    (status,) = check_all(_env(environ=environ), ("zap",))
    assert status.configured is True
    assert "sup3r-s3cret-value" not in json.dumps(status.to_dict())


# --- a healthy machine ------------------------------------------------------ #
def test_a_healthy_machine_passes_with_the_real_version_and_template_commit() -> None:
    statuses = check_all(_healthy(), MANDATORY)
    assert [status.state for status in statuses] == [EngineState.PRESENT] * 3
    nuclei = next(status for status in statuses if status.name == "nuclei")
    assert nuclei.version_check == "match"
    assert nuclei.detected_version == NUCLEI_BANNER
    assert nuclei.data[0].ok
    assert verdict(statuses).exit_code is ExitCode.OK


# --- runtime prerequisite commands (TOOLS-4.2) ------------------------------ #
def _testssl_env(*, hexdump: bool) -> Environment:
    # testssl is present and pinned; only the auxiliary command varies.
    present = {"testssl.sh": "testssl 3.2.4 from https://testssl.sh/"}
    if hexdump:
        present["hexdump"] = "hexdump from util-linux"
    return _env(present=present, heads={"/opt/testssl": _commit("testssl")})


def test_a_present_engine_missing_a_runtime_prerequisite_is_not_ready() -> None:
    # testssl.sh shells out to hexdump; without it the engine is present but
    # unusable, which must never read as ready (TOOLS-4.2, fail-closed).
    status = _status("testssl", _testssl_env(hexdump=False))
    assert status.state is EngineState.PREREQUISITE_MISSING
    assert not status.ok
    assert "hexdump" in status.detail
    if status.in_scanner_image:
        # not ok -> blocking under --strict for an engine the image ships
        assert "testssl" in verdict([status], strict=True).blocking


def test_a_present_engine_with_its_prerequisites_is_ready() -> None:
    status = _status("testssl", _testssl_env(hexdump=True))
    assert status.state is EngineState.PRESENT
    assert status.ok


# --- every way an engine can be wrong --------------------------------------- #
def test_a_different_version_than_the_pin_is_a_mismatch() -> None:
    status = _status("nuclei", _env(present={"nuclei": "[INF] Nuclei Engine Version: v3.9.0"}))
    assert status.state is EngineState.VERSION_MISMATCH and status.version_check == "mismatch"
    assert status.install_command is not None and "v3.11.1" in status.install_command


def test_the_python_httpx_is_not_the_projectdiscovery_probe() -> None:
    wrong = _status("httpx", _env(present={"httpx": "httpx, version 0.28.1"}))
    assert wrong.state is EngineState.WRONG_TOOL
    usage = _env(present={"httpx": "Usage: httpx [OPTIONS] URL"}, exits={"httpx": 2})
    assert _status("httpx", usage).state is EngineState.UNUSABLE


def test_a_probe_that_fails_is_unusable_not_present() -> None:
    status = _status("nmap", _env(present={"nmap": "boom"}, exits={"nmap": 127}))
    assert status.state is EngineState.UNUSABLE and "exited 127" in status.detail


def test_a_git_engine_is_judged_by_its_commit_not_by_the_string_it_prints() -> None:
    printed = {"xsstrike": VERSIONS["xsstrike"]}
    good = _status("xsstrike", _env(present=printed, heads={"/opt/xsstrike": _commit("xsstrike")}))
    assert good.state is EngineState.PRESENT and good.version_check == "reported"  # prints 3.1.5
    stale = _status("xsstrike", _env(present=printed, heads={"/opt/xsstrike": "0" * 40}))
    assert stale.state is EngineState.COMMIT_MISMATCH
    gone = _status("xsstrike", _env(present=printed))
    assert gone.state is EngineState.COMMIT_MISMATCH and "None" in gone.detail


def test_wrong_template_commit_is_a_data_problem_with_the_pinned_install_command() -> None:
    env = _env(present={"nuclei": VERSIONS["nuclei"]}, heads={"/opt/nuclei-templates": "1" * 40})
    status = _status("nuclei", env)
    assert status.state is EngineState.DATA_PROBLEM
    assert "79fb682760ab3d5b0e22afbb44709353cbebf023" in str(status.install_command)


def test_strict_extends_the_requirement_to_every_engine_the_image_ships() -> None:
    statuses = check_all(_healthy())
    assert verdict(statuses).exit_code is ExitCode.OK
    strict = verdict(statuses, strict=True)
    assert strict.exit_code is ExitCode.ENGINE_MISSING and "sqlmap" in strict.blocking
    assert "nikto" not in strict.blocking  # not shipped in the image


def test_an_unknown_engine_is_refused() -> None:
    with pytest.raises(KeyError):
        check_all(_env(), ("nope",))


def test_an_adapter_entrypoint_outside_olympus_is_never_imported() -> None:
    source = (ENGINES_ROOT / "nuclei" / "engine.toml").read_text(encoding="utf-8")
    hostile = parse_manifest(
        source.replace("olympus.themis.adapters.nuclei:NucleiAdapter", "os:system")
    )
    assert adapter_for(load_all()["nuclei"]) is not None
    with pytest.raises(ValueError, match="outside olympus"):
        adapter_for(hostile)


# --- the command ------------------------------------------------------------ #
@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_cli_doctor_exits_8_on_a_clean_machine_and_prints_the_install_commands(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engines_cli, "system_environment", lambda: _env())
    result = runner.invoke(app, ["engines", "doctor"])
    assert result.exit_code == ExitCode.ENGINE_MISSING
    nuclei_install = "install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1"
    assert nuclei_install in result.output
    assert "REQUIRED: nmap" in result.output


def test_cli_doctor_exits_0_when_the_mandatory_engines_are_present(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engines_cli, "system_environment", _healthy)
    result = runner.invoke(app, ["engines", "doctor", "--format", "json"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["blocking"] == [] and document["exit_code"] == 0
    assert {e["name"]: e["state"] for e in document["engines"]}["nuclei"] == "present"


def test_cli_doctor_strict_single_engine_and_usage(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engines_cli, "system_environment", _healthy)
    strict = runner.invoke(app, ["engines", "doctor", "--strict"])
    assert strict.exit_code == ExitCode.ENGINE_MISSING
    assert runner.invoke(app, ["engines", "doctor", "--engine", "nuclei"]).exit_code == 0
    bogus = runner.invoke(app, ["engines", "doctor", "--engine", "bogus"])
    assert bogus.exit_code == ExitCode.USAGE


def test_cli_list_shows_all_24_engines_in_both_formats(runner: CliRunner) -> None:
    rows = json.loads(runner.invoke(app, ["engines", "list", "--format", "json"]).stdout)
    assert len(rows) == 24
    assert {row["engine"] for row in rows if row["mandatory"]} == set(MANDATORY)
    table = runner.invoke(app, ["engines", "list"])
    assert table.exit_code == 0 and "24 engines" in table.output


def test_the_default_environment_uses_the_sandboxed_runner_and_a_safe_git_directory() -> None:
    environment = engines_cli.system_environment()
    assert environment.which("definitely-not-an-installed-engine") is None
    code, _text = environment.probe(["definitely-not-an-installed-engine"])
    assert code != 0
    assert environment.git_head(str(Path("/nonexistent-checkout-dir"))) is None


def test_a_sandbox_memory_limit_below_the_engine_need_is_noted_not_hidden() -> None:
    from dataclasses import replace

    low = replace(_healthy(), sandbox_memory_bytes=2 * 1024**3)
    (status,) = check_all(low, ("nuclei",))
    assert status.state is EngineState.PRESENT  # works with a small template set
    assert len(status.notes) == 1 and "needs 4 GiB" in status.notes[0]
    assert "THEMIS_SANDBOX_MEMORY_BYTES" in status.notes[0]
    enough = replace(_healthy(), sandbox_memory_bytes=4 * 1024**3)
    assert check_all(enough, ("nuclei",))[0].notes == ()
    assert check_all(low, ("nmap",))[0].notes == ()  # no declared need, nothing to say
