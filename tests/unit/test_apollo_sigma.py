"""Faithful-subset Sigma rule import into Apollo (§3.3).

No YAML dependency is added: a small strict indentation parser reads the subset.
These tests confirm a valid rule converts, that everything outside the
exact-match subset is refused with a reason, and the CLI writes an Apollo rule.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.apollo.rules import DetectionRule, load_rule
from olympus.apollo.sigma import SigmaImportError, parse_sigma_yaml, sigma_to_rule
from olympus.cli import app

runner = CliRunner()

_VALID = """title: Suspicious PowerShell
id: 1234abcd-0000-1111-2222-333344445555
status: experimental
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image: powershell.exe
        User: SYSTEM
    condition: selection
tags:
    - attack.t1059.001
    - attack.execution
"""


def test_valid_sigma_converts_to_an_apollo_rule() -> None:
    rule = sigma_to_rule(_VALID)
    assert isinstance(rule, DetectionRule)
    assert rule.event_type == "windows.process_creation"
    assert rule.severity.value == "high"
    assert rule.conditions == {"Image": "powershell.exe", "User": "SYSTEM"}
    assert rule.mitre_attack == ["T1059.001"]
    assert rule.rule_id.startswith("APL-SIGMA-")


def test_parser_rejects_tabs_and_flow_collections() -> None:
    with pytest.raises(SigmaImportError, match="tabs"):
        parse_sigma_yaml("title:\tx\n")
    with pytest.raises(SigmaImportError, match="unsupported YAML construct"):
        parse_sigma_yaml("detection: {selection: x}\n")


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        (
            "title: x\nlogsource:\n    product: windows\ndetection:\n"
            "    selection:\n        CommandLine|contains: whoami\n    condition: selection\n",
            "field modifier not supported",
        ),
        (
            "title: x\nlogsource:\n    product: windows\ndetection:\n"
            "    selection:\n        Image:\n            - a.exe\n            - b.exe\n"
            "    condition: selection\n",
            "value list",
        ),
        (
            "title: x\nlogsource:\n    product: windows\ndetection:\n"
            "    selection:\n        Image: a.exe\n    filter:\n        User: s\n"
            "    condition: selection and not filter\n",
            "single named selection",
        ),
        (
            "title: x\nlogsource:\n    product: windows\ndetection:\n"
            "    selection:\n        Image: '*.exe'\n    condition: selection\n",
            "wildcard",
        ),
        (
            "title: x\ndetection:\n    selection:\n        Image: a.exe\n"
            "    condition: selection\n",
            "logsource",
        ),
    ],
)
def test_unfaithful_sigma_is_refused_with_a_reason(document: str, expected: str) -> None:
    with pytest.raises(SigmaImportError, match=expected):
        sigma_to_rule(document)


def test_cli_sigma_import_writes_a_loadable_apollo_rule(tmp_path: Path) -> None:
    sigma = tmp_path / "rule.yml"
    sigma.write_text(_VALID, encoding="utf-8")
    output = tmp_path / "apollo-rule.json"

    result = runner.invoke(app, ["apollo", "sigma-import", str(sigma), "--output", str(output)])
    assert result.exit_code == 0, result.output

    import stat

    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    # The written rule loads back through Apollo's own strict loader.
    rule = load_rule(output)
    assert rule.conditions == {"Image": "powershell.exe", "User": "SYSTEM"}

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_name"] == "olympus.apollo-rule"


def test_cli_sigma_import_reports_an_unsupported_rule(tmp_path: Path) -> None:
    sigma = tmp_path / "rule.yml"
    sigma.write_text(
        "title: x\nlogsource:\n    product: windows\ndetection:\n"
        "    selection:\n        CommandLine|contains: whoami\n    condition: selection\n",
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["apollo", "sigma-import", str(sigma), "--output", str(tmp_path / "out.json")]
    )
    assert result.exit_code == 2
    assert "field modifier not supported" in result.output
