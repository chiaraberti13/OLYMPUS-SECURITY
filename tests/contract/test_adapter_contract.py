"""Reusable adapter contract (ROADMAP ``DEV-B``).

A Themis scanner adapter is a plugin: it builds an argument vector, runs an
external binary in the sandbox, and parses untrusted output into findings. Every
adapter must honour the same contract so a *new* adapter — added to the registry
without touching the core — is held to the identical safety and correctness
invariants automatically.

These tests parametrise over **every registered adapter** (``registry.implemented``)
and assert that shared contract, entirely offline (no binary is executed, no
target is contacted):

* **identity** — the adapter's ``name`` matches its registry key and the shared
  catalogue, and it declares a binary;
* **argv is a vector, never a shell string** — ``build_argv`` returns a
  non-empty ``list[str]`` and a target-derived token stays a single argument, so
  it can never be re-interpreted as a flag or a shell fragment (SEC-H / shell
  safety);
* **hostile output is handled** — ``parse`` returns a ``list[Finding]`` or
  raises a handled ``ParseError``/``ValueError`` for adversarial output, never an
  unhandled exception or a fabricated finding;
* **honest identity and simulation** — ``run`` rejects a mismatched scanner, and
  ``simulate`` yields clearly-labelled, non-real findings.

Because the suite is driven by the registry, a newly registered adapter is
contract-checked with no extra wiring — exactly the DEV-B goal.
"""

from __future__ import annotations

import pytest

from olympus.core.models import Finding
from olympus.integrations.scanners import by_name
from olympus.themis.base import ParseError, ScannerAdapter
from olympus.themis.model import ScanRequest
from olympus.themis.registry import get_adapter, implemented
from olympus.themis.runner import CommandOutput

ADAPTER_NAMES = implemented()

#: Target-controlled / malformed scanner output a parser must survive. A flag-like
#: token and control bytes probe argument- and terminal-injection defenses; deep
#: nesting probes the recursion/complexity guard.
HOSTILE_OUTPUTS: tuple[str, ...] = (
    "",
    "not json at all\n",
    "\x00\x1b[31minjected\x1b[0m\n",
    "{" * 400,
    "[]",
    "command not found\n",
    '{"unexpected":"shape"}\n' * 5,
    '{"severity": {"weird": ["nested", 1, null]}}\n',
    "../../etc/passwd\n",
)


def _request(scanner: str) -> ScanRequest:
    """A minimal, authorized-scope request; no network is ever touched here."""
    return ScanRequest(
        scanner=scanner,
        target="127.0.0.1",
        target_kind="host",
        allowed=("127.0.0.1",),
    )


def _output(stdout: str) -> CommandOutput:
    return CommandOutput(exit_code=0, stdout=stdout, stderr="")


def test_registry_is_not_empty() -> None:
    # A parametrised suite over an empty registry would pass vacuously.
    assert ADAPTER_NAMES, "no implemented adapters to contract-test"


@pytest.mark.parametrize("name", ADAPTER_NAMES)
def test_adapter_identity_matches_registry_and_catalogue(name: str) -> None:
    adapter = get_adapter(name)
    assert isinstance(adapter, ScannerAdapter)
    assert adapter.name == name, "adapter.name must equal its registry key"
    assert adapter.binary, "an execution adapter must declare its binary"
    # The runnable adapter is a real entry in the shared scanner catalogue.
    assert by_name(name) is not None, f"{name} is not in the scanner catalogue"


@pytest.mark.parametrize("name", ADAPTER_NAMES)
def test_build_argv_is_a_string_vector(name: str) -> None:
    argv = get_adapter(name).build_argv("127.0.0.1", _request(name))
    assert isinstance(argv, list) and argv, "argv must be a non-empty list"
    assert all(isinstance(token, str) for token in argv), "every argv token must be a str"
    assert all(token for token in argv), "argv tokens must be non-empty"


@pytest.mark.parametrize("name", ADAPTER_NAMES)
def test_host_is_carried_as_an_atomic_argv_token(name: str) -> None:
    """The scanned host travels as a whole argv token, never a shell fragment.

    A target-derived value is placed into the vector verbatim (possibly wrapped,
    e.g. ``http://<host>``) and is never split on whitespace into several shell
    words. Rejecting *flag-like* hosts is a separate, upstream concern
    (``host_of``/``_normalize_host`` before the adapter runs); here the contract
    is simply that the vector keeps the token atomic.
    """
    host = "127.0.0.1"
    argv = get_adapter(name).build_argv(host, _request(name))
    carriers = [token for token in argv if host in token]
    assert carriers, f"{name}: the host token disappeared from argv"
    for token in carriers:
        assert " " not in token, f"{name}: host token split by whitespace in {token!r}"


@pytest.mark.parametrize("name", ADAPTER_NAMES)
def test_parse_survives_hostile_output(name: str) -> None:
    adapter = get_adapter(name)
    request = _request(name)
    for payload in HOSTILE_OUTPUTS:
        try:
            result = adapter.parse(_output(payload), "127.0.0.1", request)
        except (ParseError, ValueError):
            continue  # a handled, honest rejection is contract-compliant
        assert isinstance(result, list), f"{name}: parse must return a list"
        assert all(isinstance(item, Finding) for item in result), (
            f"{name}: parse must only ever yield Finding objects"
        )


@pytest.mark.parametrize("name", ADAPTER_NAMES)
def test_run_rejects_a_mismatched_scanner(name: str) -> None:
    adapter = get_adapter(name)
    wrong = ScanRequest(scanner="not-this-adapter", target="127.0.0.1", allowed=("127.0.0.1",))
    with pytest.raises(ValueError, match="does not match adapter"):
        adapter.run(wrong)


@pytest.mark.parametrize("name", ADAPTER_NAMES)
def test_simulate_yields_only_clearly_labelled_findings(name: str) -> None:
    findings = get_adapter(name).simulate("127.0.0.1", _request(name))
    assert findings, "simulate must return at least one illustrative finding"
    assert all("SIMULATION" in finding.title for finding in findings), (
        "simulated findings must be unmistakably labelled, never passed off as real"
    )
