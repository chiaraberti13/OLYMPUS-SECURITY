"""Editable execution bounds, profile overlays, precedence, and the lab guard."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.core import policy as core_policy
from olympus.core.addresses import (
    NonGlobalAddressError,
    ensure_authorized_destination,
    is_authorized_destination,
    is_globally_routable,
    parse_address,
    resolve_authorized_addresses,
)
from olympus.core.execution import (
    MAX_CONCURRENCY,
    MAX_TIMEOUT_SECONDS,
    ExecutionPolicy,
)
from olympus.core.exit_codes import ExitCode

runner = CliRunner()

MINIMAL = """
schema_version = "1.0.0"
engagement = "demo-2026"

[bounds.default]
timeout_seconds = 10
max_concurrency = 4
retries = 1
jitter_ratio = 0.2

[bounds.aggressive]
max_concurrency = 16
retries = 3
"""

LAB = """
schema_version = "1.0.0"

[lab]
enabled = true
allowed_networks = ["10.10.0.0/16"]
activated_by = "operator@example.com"
activated_at = 2026-01-01T00:00:00Z
"""


@pytest.fixture(autouse=True)
def _isolated_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Never let a developer's real policy file leak into these tests."""
    monkeypatch.delenv(core_policy.POLICY_PATH_VARIABLE, raising=False)
    monkeypatch.delenv(core_policy.LAB_SIGNING_KEY_VARIABLE, raising=False)
    for key in core_policy.BOUND_CEILINGS:
        monkeypatch.delenv(core_policy.environment_variable(key), raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda _cls: tmp_path / "no-home"))
    monkeypatch.chdir(tmp_path)
    core_policy.reset_active_policy_cache()


def write_policy(tmp_path: Path, body: str, name: str = "olympus.policy.toml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    core_policy.reset_active_policy_cache()
    return path


# --------------------------------------------------------------------------- #
# Document parsing and profile overlays
# --------------------------------------------------------------------------- #


def test_absent_policy_falls_back_to_builtin_defaults() -> None:
    ruleset, source = core_policy.load_policy_with_source()
    assert source is None
    assert ruleset.bounds_for() == {
        "timeout_seconds": ExecutionPolicy().timeout_seconds,
        "deadline_seconds": ExecutionPolicy().deadline_seconds,
        "max_concurrency": ExecutionPolicy().max_concurrency,
        "retries": ExecutionPolicy().retries,
        "backoff_seconds": ExecutionPolicy().backoff_seconds,
        "min_interval_seconds": ExecutionPolicy().min_interval_seconds,
        "jitter_ratio": ExecutionPolicy().jitter_ratio,
    }


def test_named_profile_overlays_default_instead_of_replacing_it() -> None:
    ruleset = core_policy.parse_policy(MINIMAL)
    default = ruleset.bounds_for("default")
    aggressive = ruleset.bounds_for("aggressive")

    assert default["max_concurrency"] == 4
    assert aggressive["max_concurrency"] == 16
    assert aggressive["retries"] == 3
    # Inherited, not reset to the built-in default.
    assert aggressive["timeout_seconds"] == 10.0
    assert aggressive["jitter_ratio"] == 0.2


def test_profile_names_always_include_default() -> None:
    assert core_policy.parse_policy(MINIMAL).profile_names() == ("aggressive", "default")
    assert core_policy.parse_policy('schema_version = "1.0.0"').profile_names() == ("default",)


def test_unknown_profile_is_refused() -> None:
    ruleset = core_policy.parse_policy(MINIMAL)
    with pytest.raises(core_policy.PolicyError, match="unknown policy profile"):
        ruleset.bounds_for("nope")


def test_unknown_key_is_refused_rather_than_ignored() -> None:
    with pytest.raises(core_policy.PolicyError, match="timout_seconds"):
        core_policy.parse_policy("[bounds.default]\ntimout_seconds = 5\n")


def test_malformed_toml_is_a_policy_error() -> None:
    with pytest.raises(core_policy.PolicyError, match="invalid TOML policy"):
        core_policy.parse_policy("[bounds.default\ntimeout_seconds = 5\n")


def test_incompatible_schema_version_is_refused() -> None:
    with pytest.raises(core_policy.PolicyError, match="unsupported schema_version"):
        core_policy.parse_policy('schema_version = "2.0.0"')


# --------------------------------------------------------------------------- #
# Ceilings: a file may lower a bound, never raise it
# --------------------------------------------------------------------------- #


def test_value_above_the_compiled_ceiling_is_rejected_not_clamped() -> None:
    body = f"[bounds.default]\nmax_concurrency = {MAX_CONCURRENCY + 1}\n"
    with pytest.raises(core_policy.PolicyError, match="max_concurrency"):
        core_policy.parse_policy(body)

    body = f"[bounds.default]\ntimeout_seconds = {MAX_TIMEOUT_SECONDS + 1:g}\n"
    with pytest.raises(core_policy.PolicyError, match="timeout_seconds"):
        core_policy.parse_policy(body)


def test_value_below_the_floor_is_rejected() -> None:
    with pytest.raises(core_policy.PolicyError, match="timeout_seconds"):
        core_policy.parse_policy("[bounds.default]\ntimeout_seconds = 0.0\n")


def test_ceilings_mirror_the_execution_constants() -> None:
    assert core_policy.BOUND_CEILINGS["timeout_seconds"] == MAX_TIMEOUT_SECONDS
    assert core_policy.BOUND_CEILINGS["max_concurrency"] == MAX_CONCURRENCY
    # Integer bounds keep an integer ceiling so the JSON output stays honest.
    assert isinstance(core_policy.BOUND_CEILINGS["max_concurrency"], int)


def test_environment_override_above_the_ceiling_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        core_policy.environment_variable("max_concurrency"), str(MAX_CONCURRENCY + 1)
    )
    with pytest.raises(core_policy.PolicyError, match="out of range"):
        core_policy.resolve_bounds(ruleset=core_policy.parse_policy(MINIMAL))


def test_caller_override_above_the_ceiling_is_refused() -> None:
    with pytest.raises(core_policy.PolicyError, match="out of range"):
        core_policy.resolve_bounds(
            ruleset=core_policy.parse_policy(MINIMAL), max_concurrency=MAX_CONCURRENCY + 1
        )


# --------------------------------------------------------------------------- #
# Precedence: CLI -> environment -> profile -> [bounds.default] -> built-in
# --------------------------------------------------------------------------- #


def test_environment_beats_the_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(core_policy.environment_variable("max_concurrency"), "9")
    bounds = core_policy.resolve_bounds(ruleset=core_policy.parse_policy(MINIMAL))
    assert bounds["max_concurrency"] == 9


def test_caller_override_beats_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(core_policy.environment_variable("max_concurrency"), "9")
    bounds = core_policy.resolve_bounds(
        ruleset=core_policy.parse_policy(MINIMAL), max_concurrency=2
    )
    assert bounds["max_concurrency"] == 2


def test_none_override_defers_to_the_layers_below() -> None:
    bounds = core_policy.resolve_bounds(
        ruleset=core_policy.parse_policy(MINIMAL), max_concurrency=None
    )
    assert bounds["max_concurrency"] == 4


def test_unparseable_environment_override_is_a_policy_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(core_policy.environment_variable("retries"), "many")
    with pytest.raises(core_policy.PolicyError, match="expected integer"):
        core_policy.resolve_bounds(ruleset=core_policy.parse_policy(MINIMAL))


def test_unknown_bound_name_is_refused() -> None:
    with pytest.raises(core_policy.PolicyError, match="unknown execution bound"):
        core_policy.resolve_bounds(ruleset=core_policy.parse_policy(MINIMAL), speed_limit=3)


def test_resolve_execution_policy_builds_a_valid_execution_policy() -> None:
    policy = core_policy.resolve_execution_policy(
        "aggressive", authorized=True, ruleset=core_policy.parse_policy(MINIMAL)
    )
    assert isinstance(policy, ExecutionPolicy)
    assert policy.max_concurrency == 16
    assert policy.retries == 3
    assert policy.timeout_seconds == 10.0
    assert policy.authorized is True


def test_a_policy_file_cannot_grant_authorization() -> None:
    """Authorization stays a caller decision; no file may forge consent."""
    policy = core_policy.resolve_execution_policy(ruleset=core_policy.parse_policy(MINIMAL))
    assert policy.authorized is False
    with pytest.raises(PermissionError):
        policy.require_authorization("scan")


def test_integer_bounds_stay_integers() -> None:
    bounds = core_policy.resolve_bounds(ruleset=core_policy.parse_policy(MINIMAL))
    assert isinstance(bounds["max_concurrency"], int)
    assert isinstance(bounds["retries"], int)


# --------------------------------------------------------------------------- #
# Discovery and caching
# --------------------------------------------------------------------------- #


def test_explicit_path_that_does_not_exist_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(core_policy.PolicyError, match="does not exist"):
        core_policy.load_policy_with_source(tmp_path / "absent.toml")


def test_configured_path_that_does_not_exist_is_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(core_policy.POLICY_PATH_VARIABLE, str(tmp_path / "absent.toml"))
    with pytest.raises(core_policy.PolicyError, match="does not exist"):
        core_policy.load_policy_with_source()


def test_project_file_is_discovered(tmp_path: Path) -> None:
    write_policy(tmp_path, MINIMAL)
    ruleset, source = core_policy.load_policy_with_source()
    assert source == (tmp_path / "olympus.policy.toml").resolve()
    assert ruleset.engagement == "demo-2026"


def test_environment_path_wins_over_the_project_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_policy(tmp_path, MINIMAL)
    chosen = write_policy(tmp_path, "[bounds.default]\nretries = 5\n", name="other.toml")
    monkeypatch.setenv(core_policy.POLICY_PATH_VARIABLE, str(chosen))
    ruleset, source = core_policy.load_policy_with_source()
    assert source == chosen.resolve()
    assert ruleset.bounds_for()["retries"] == 5


def test_active_policy_reloads_after_the_file_changes(tmp_path: Path) -> None:
    write_policy(tmp_path, "[bounds.default]\nretries = 1\n")
    assert core_policy.active_policy().bounds_for()["retries"] == 1
    write_policy(tmp_path, "[bounds.default]\nretries = 4\n")
    assert core_policy.active_policy().bounds_for()["retries"] == 4


# --------------------------------------------------------------------------- #
# Lab profile and its activation record
# --------------------------------------------------------------------------- #


def test_lab_is_disabled_by_default() -> None:
    assert core_policy.parse_policy(MINIMAL).lab_networks() == ()


def test_enabling_the_lab_without_an_owner_is_refused() -> None:
    body = '[lab]\nenabled = true\nallowed_networks = ["10.10.0.0/16"]\n'
    with pytest.raises(core_policy.PolicyError, match="activated_by"):
        core_policy.parse_policy(body)


def test_enabling_the_lab_without_a_timestamp_is_refused() -> None:
    body = '[lab]\nenabled = true\nallowed_networks = ["10.10.0.0/16"]\nactivated_by = "operator"\n'
    with pytest.raises(core_policy.PolicyError, match="activated_at"):
        core_policy.parse_policy(body)


def test_enabling_the_lab_without_a_network_is_refused() -> None:
    body = '[lab]\nenabled = true\nactivated_by = "operator"\nactivated_at = 2026-01-01T00:00:00Z\n'
    with pytest.raises(core_policy.PolicyError, match="allowed_networks"):
        core_policy.parse_policy(body)


def _lab_with(networks: str) -> str:
    return (
        "[lab]\nenabled = true\n"
        f"allowed_networks = {networks}\n"
        'activated_by = "operator"\nactivated_at = 2026-01-01T00:00:00Z\n'
    )


@pytest.mark.parametrize(
    "network",
    [
        '["8.8.8.0/24"]',  # public space
        '["0.0.0.0/0"]',  # the default route
        '["::/0"]',  # the IPv6 default route
        '["169.254.0.0/16"]',  # link-local
        '["169.254.169.254/32"]',  # cloud instance metadata
        '["127.0.0.0/8"]',  # loopback
        '["fe80::/10"]',  # IPv6 link-local
        '["10.0.0.0/7"]',  # straddles RFC 1918 and public space
    ],
)
def test_lab_allowlist_refuses_ineligible_ranges(network: str) -> None:
    """An allowlist that may name anything is not an allowlist.

    ``is_global`` alone is not a sufficient test: ``169.254.169.254/32`` — the
    cloud instance-metadata endpoint — reports ``is_global = False``.
    """
    with pytest.raises(core_policy.PolicyError, match="not an eligible lab range"):
        core_policy.parse_policy(_lab_with(network))


@pytest.mark.parametrize(
    "network",
    ['["10.10.0.0/16"]', '["192.168.1.0/24"]', '["172.20.0.0/14"]', '["fd00:1234::/32"]'],
)
def test_lab_allowlist_accepts_declared_private_space(network: str) -> None:
    assert core_policy.parse_policy(_lab_with(network)).lab.enabled is True


def test_lab_allowlist_normalizes_a_host_bit_entry() -> None:
    """A CIDR written from a host address is normalized, not rejected."""
    ruleset = core_policy.parse_policy(_lab_with('["10.10.0.5/16"]'))
    assert ruleset.lab.allowed_networks == ("10.10.0.0/16",)


def test_lab_allowlist_refuses_a_malformed_network() -> None:
    with pytest.raises(core_policy.PolicyError, match="valid CIDR"):
        core_policy.parse_policy(_lab_with('["10.10.0.0/99"]'))


def test_lab_networks_are_parsed() -> None:
    ruleset = core_policy.parse_policy(LAB)
    assert ruleset.lab_networks() == (ipaddress.ip_network("10.10.0.0/16"),)


def test_activation_record_is_unsigned_without_a_key() -> None:
    record = core_policy.lab_activation_record(core_policy.parse_policy(LAB))
    assert record["signed"] is False
    assert record["signature"] is None
    assert record["algorithm"] is None
    assert record["activated_by"] == "operator@example.com"
    assert record["policy_digest"]


def test_activation_record_is_signed_when_a_key_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(core_policy.LAB_SIGNING_KEY_VARIABLE, "lab-signing-key")
    record = core_policy.lab_activation_record(core_policy.parse_policy(LAB))
    assert record["signed"] is True
    assert record["algorithm"] == "HMAC-SHA256"
    assert len(str(record["signature"])) == 64


def test_activation_signature_changes_with_the_document() -> None:
    first = core_policy.lab_activation_record(core_policy.parse_policy(LAB), signing_key="k")
    widened = LAB.replace('["10.10.0.0/16"]', '["10.10.0.0/16", "192.168.5.0/24"]')
    second = core_policy.lab_activation_record(core_policy.parse_policy(widened), signing_key="k")
    assert first["policy_digest"] != second["policy_digest"]
    assert first["signature"] != second["signature"]


# --------------------------------------------------------------------------- #
# The SSRF guard honours the lab allowlist, and only the lab allowlist
# --------------------------------------------------------------------------- #


def test_private_address_stays_blocked_without_a_lab(tmp_path: Path) -> None:
    address = parse_address("10.10.0.5")
    assert is_globally_routable(address) is False
    assert is_authorized_destination(address) is False
    with pytest.raises(NonGlobalAddressError):
        ensure_authorized_destination("10.10.0.5")


def test_declared_lab_range_becomes_reachable(tmp_path: Path) -> None:
    write_policy(tmp_path, LAB)
    assert is_authorized_destination(parse_address("10.10.0.5")) is True
    assert ensure_authorized_destination("10.10.0.5") == parse_address("10.10.0.5")


def test_lab_range_does_not_widen_other_private_space(tmp_path: Path) -> None:
    write_policy(tmp_path, LAB)
    assert is_authorized_destination(parse_address("127.0.0.1")) is False
    assert is_authorized_destination(parse_address("192.168.1.1")) is False
    assert is_authorized_destination(parse_address("10.20.0.5")) is False


def test_is_globally_routable_is_never_widened_by_the_lab(tmp_path: Path) -> None:
    """The pure predicate keeps its meaning; only the policy-aware one changes."""
    write_policy(tmp_path, LAB)
    assert is_globally_routable(parse_address("10.10.0.5")) is False


def test_ipv6_wrapper_around_a_lab_address_is_unwrapped(tmp_path: Path) -> None:
    write_policy(tmp_path, LAB)
    assert is_authorized_destination(parse_address("::ffff:10.10.0.5")) is True
    assert is_authorized_destination(parse_address("::ffff:10.20.0.5")) is False


def test_explicit_networks_argument_bypasses_the_policy_lookup() -> None:
    networks = (ipaddress.ip_network("172.20.0.0/16"),)
    assert is_authorized_destination(parse_address("172.20.1.1"), networks) is True
    assert is_authorized_destination(parse_address("10.10.0.5"), networks) is False


def test_resolver_honours_the_lab_allowlist(tmp_path: Path) -> None:
    write_policy(tmp_path, LAB)

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [(None, None, None, None, ("10.10.0.7", 0))]

    assert resolve_authorized_addresses("lab.internal", resolver) == ("10.10.0.7",)


def test_resolver_still_refuses_an_undeclared_private_answer(tmp_path: Path) -> None:
    write_policy(tmp_path, LAB)

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [(None, None, None, None, ("127.0.0.1", 0))]

    with pytest.raises(NonGlobalAddressError):
        resolve_authorized_addresses("lab.internal", resolver)


# --------------------------------------------------------------------------- #
# olympus policy show | validate | diff | edit
# --------------------------------------------------------------------------- #


def test_policy_show_reports_the_effective_bounds(tmp_path: Path) -> None:
    path = write_policy(tmp_path, MINIMAL)
    result = runner.invoke(app, ["policy", "show", "--profile", "aggressive"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["profile"] == "aggressive"
    assert payload["bounds"]["max_concurrency"] == 16
    assert payload["source"] == str(path.resolve())
    assert payload["lab"]["enabled"] is False


def test_policy_show_accepts_an_explicit_file(tmp_path: Path) -> None:
    path = write_policy(tmp_path, MINIMAL, name="engagement.toml")
    result = runner.invoke(app, ["policy", "show", "--file", str(path)])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["engagement"] == "demo-2026"


def test_policy_validate_is_blocking_on_a_bad_document(tmp_path: Path) -> None:
    path = write_policy(tmp_path, "[bounds.default]\nmax_concurrency = 999\n")
    result = runner.invoke(app, ["policy", "validate", "--file", str(path)])
    assert result.exit_code == int(ExitCode.USAGE)
    assert "invalid policy" in result.output


def test_policy_validate_reports_a_valid_document(tmp_path: Path) -> None:
    write_policy(tmp_path, MINIMAL)
    result = runner.invoke(app, ["policy", "validate"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "valid"
    assert payload["profiles"] == ["aggressive", "default"]
    assert payload["lab_enabled"] is False


def test_policy_validate_refuses_an_unknown_profile(tmp_path: Path) -> None:
    write_policy(tmp_path, MINIMAL)
    result = runner.invoke(app, ["policy", "validate", "--profile", "ghost"])
    assert result.exit_code == int(ExitCode.USAGE)


def test_policy_diff_lists_only_what_changed(tmp_path: Path) -> None:
    write_policy(tmp_path, MINIMAL)
    result = runner.invoke(app, ["policy", "diff", "--profile", "aggressive"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    changed = {entry["bound"]: entry for entry in payload["changed"]}
    assert changed["max_concurrency"]["effective"] == 16
    assert changed["max_concurrency"]["origin"] == "[bounds.aggressive]"
    assert changed["jitter_ratio"]["origin"] == "[bounds.default]"
    # timeout_seconds is 10 in the file and 10 by default: not a change.
    assert "timeout_seconds" not in changed


def test_policy_diff_attributes_an_environment_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    write_policy(tmp_path, MINIMAL)
    monkeypatch.setenv(core_policy.environment_variable("retries"), "5")
    result = runner.invoke(app, ["policy", "diff"])
    assert result.exit_code == 0, result.output
    changed = {entry["bound"]: entry for entry in json.loads(result.stdout)["changed"]}
    assert changed["retries"]["effective"] == 5
    assert changed["retries"]["origin"].startswith("environment:")


def test_policy_edit_creates_a_valid_template(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.delenv("EDITOR", raising=False)
    target = tmp_path / "olympus.policy.toml"
    result = runner.invoke(app, ["policy", "edit", "--file", str(target), "--no-open"])
    assert result.exit_code == 0, result.output
    assert target.exists()
    # The shipped template must itself pass validation.
    ruleset = core_policy.parse_policy(target.read_text(encoding="utf-8"))
    assert ruleset.profile_names() == ("aggressive", "default")
    assert ruleset.lab.enabled is False


def test_policy_edit_never_overwrites_an_existing_file(tmp_path: Path) -> None:
    target = write_policy(tmp_path, MINIMAL, name="keep.toml")
    result = runner.invoke(app, ["policy", "edit", "--file", str(target), "--no-open"])
    assert result.exit_code == 0, result.output
    assert target.read_text(encoding="utf-8") == MINIMAL


def test_policy_show_surfaces_the_lab_activation_record(tmp_path: Path) -> None:
    write_policy(tmp_path, LAB)
    result = runner.invoke(app, ["policy", "show"])
    assert result.exit_code == 0, result.output
    lab = json.loads(result.stdout)["lab"]
    assert lab["enabled"] is True
    assert lab["allowed_networks"] == ["10.10.0.0/16"]
    assert lab["activated_by"] == "operator@example.com"


def test_athena_ip_literal_target_honours_the_lab(tmp_path: Path) -> None:
    """An IP literal inside a declared lab range passes Athena's SSRF gate."""
    from olympus.athena.scope import SsrfBlockedError, ensure_target_allowed

    write_policy(tmp_path, LAB)
    assert ensure_target_allowed("url", "https://10.10.0.5/", ("10.10.0.5",)) == "10.10.0.5"

    with pytest.raises(SsrfBlockedError):
        ensure_target_allowed("url", "https://127.0.0.1/", ("127.0.0.1",))


def test_athena_ip_literal_target_stays_blocked_without_a_lab() -> None:
    from olympus.athena.scope import SsrfBlockedError, ensure_target_allowed

    with pytest.raises(SsrfBlockedError):
        ensure_target_allowed("url", "https://10.10.0.5/", ("10.10.0.5",))
