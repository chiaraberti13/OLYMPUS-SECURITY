"""The command line comes from the manifest allow-list; values can never add flags."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from olympus.engines.argv import MAX_VALUE_LENGTH, ArgvError, build_argv
from olympus.engines.loader import manifest_for

pytestmark = pytest.mark.unit

NUCLEI = manifest_for("nuclei")


def test_nuclei_argv_is_exactly_the_manifest_allow_list_plus_the_values() -> None:
    argv = build_argv(NUCLEI, {"-target": "http://127.0.0.1:8099", "-templates": "/opt/t"})
    assert argv == [
        "nuclei",
        "-target",
        "http://127.0.0.1:8099",
        "-templates",
        "/opt/t",
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-no-interactsh",
        "-omit-raw",
        "-omit-template",
    ]


def test_an_optional_flag_may_be_left_out_but_a_required_one_may_not() -> None:
    assert "-templates" not in build_argv(NUCLEI, {"-target": "http://127.0.0.1"})
    with pytest.raises(ArgvError, match="required flag -target"):
        build_argv(NUCLEI, {})


@pytest.mark.parametrize(
    "flag", ["-update-templates", "-ut", "-config", "-l", "-proxy", "--anything", "-jsonl"]
)
def test_a_flag_the_manifest_does_not_allow_as_a_value_flag_is_refused(flag: str) -> None:
    with pytest.raises(ArgvError, match="not allowed by the manifest"):
        build_argv(NUCLEI, {"-target": "http://127.0.0.1", flag: "x"})


@pytest.mark.parametrize(
    "value",
    ["-update-templates", "--config", "-", "-l /etc/passwd", "", "a\nb", "a\rb", "a\x00b"],
)
def test_a_value_cannot_look_like_a_flag_or_carry_control_characters(value: str) -> None:
    with pytest.raises(ArgvError):
        build_argv(NUCLEI, {"-target": value})


def test_oversized_values_are_refused() -> None:
    with pytest.raises(ArgvError, match="exceeds"):
        build_argv(NUCLEI, {"-target": "h" * (MAX_VALUE_LENGTH + 1)})


def test_shell_syntax_in_a_value_stays_one_inert_argument() -> None:
    hostile = "http://127.0.0.1/;touch /tmp/pwned && $(id) `id` | cat"
    argv = build_argv(NUCLEI, {"-target": hostile})
    assert argv[argv.index("-target") + 1] == hostile  # one element, never interpreted
    assert argv.count(hostile) == 1


@given(
    st.text(min_size=1, max_size=200).filter(
        lambda text: not text.startswith("-") and not any(c in text for c in "\x00\r\n")
    )
)
def test_any_safe_value_becomes_exactly_one_argument(value: str) -> None:
    argv = build_argv(NUCLEI, {"-target": value})
    allowed = {"nuclei", *NUCLEI.adapter.static_flags, *NUCLEI.adapter.value_flags}  # type: ignore[union-attr]
    assert [item for item in argv if item not in allowed] == [value] or value in allowed
    assert len(argv) == 1 + 2 + len(NUCLEI.adapter.static_flags)  # type: ignore[union-attr]


def test_an_engine_without_an_allow_list_cannot_build_a_command() -> None:
    with pytest.raises(ArgvError, match="declares no allowed flags"):
        build_argv(manifest_for("sqlmap"), {})
    with pytest.raises(ArgvError, match="no adapter"):
        build_argv(manifest_for("zap"), {})


def test_manifest_flag_lists_are_validated() -> None:
    from olympus.engines.loader import ENGINES_ROOT, ManifestError, parse_manifest

    raw = (ENGINES_ROOT / "nuclei" / "engine.toml").read_text(encoding="utf-8")
    bad_cases = {
        'static_flags = ["-jsonl", "-target"]': "once",  # also a value flag
        'optional_flags = ["-jsonl"]': "subset",
        'static_flags = ["jsonl"]': "String should match",  # not a flag
        'static_flags = ["-jsonl; id"]': "String should match",
    }
    for replacement, message in bad_cases.items():
        key = replacement.split(" =")[0]
        mutated = "\n".join(
            replacement if line.startswith(key + " =") else line for line in raw.splitlines()
        )
        with pytest.raises(ManifestError, match=message):
            parse_manifest(mutated)


def test_the_nuclei_adapter_builds_its_command_only_through_the_manifest() -> None:
    from olympus.themis.adapters.nuclei import NucleiAdapter
    from olympus.themis.model import ScanRequest

    request = ScanRequest(
        scanner="nuclei", target="http://127.0.0.1:8099", target_kind="url", allowed=("127.0.0.1",)
    )
    argv = NucleiAdapter().build_argv("127.0.0.1", request)
    assert argv == build_argv(NUCLEI, {"-target": "http://127.0.0.1:8099"}) or "-templates" in argv
    flags = {item for item in argv if item.startswith("-")}
    assert flags <= {*NUCLEI.adapter.static_flags, *NUCLEI.adapter.value_flags}  # type: ignore[union-attr]
