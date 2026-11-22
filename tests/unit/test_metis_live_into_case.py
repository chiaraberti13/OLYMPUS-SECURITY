"""``--into-case`` for the live CTI pullers (BLUE-3 operational last mile).

The three live pullers (TAXII, MISP, OpenCTI) can import their normalized IOCs
straight into a Metis case with the pull's provenance, in one command, instead
of the two-step pull → file → ``case *-import``. These tests drive the real CLI
commands with a *monkeypatched* pinned transport (so no socket is opened) and a
temporary case database, and assert the case ends up with the expected IOCs and
provenance — the same content the two-step flow would produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.cli import app
from olympus.metis import cli as metis_cli
from olympus.metis.cases import CaseStore
from olympus.metis.opencti import OpenCtiResponse
from olympus.metis.taxii import TaxiiResponse

pytestmark = pytest.mark.unit

runner = CliRunner()

TOKEN_ENV = "OLYMPUS_CTI_TOKEN"  # noqa: S105 - an env var name, not a credential


def _case(tmp_path: Path) -> tuple[Path, str]:
    database = tmp_path / "cases.sqlite3"
    with CaseStore(database) as store:
        case_id = store.create_case("Live CTI")
    return database, case_id


def _stix_bundle_response() -> TaxiiResponse:
    objects = [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--1",
            "pattern": "[domain-name:value = 'evil.tld']",
            "pattern_type": "stix",
        },
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--2",
            "pattern": "[ipv4-addr:value = '203.0.113.7']",
            "pattern_type": "stix",
        },
    ]
    body = {"objects": objects, "more": False}
    return TaxiiResponse(200, json.dumps(body).encode("utf-8"), {})


class _FakeTaxii:
    def get(self, url: str, headers: object, *, timeout: float) -> TaxiiResponse:
        return _stix_bundle_response()


def test_taxii_poll_into_case_imports_iocs_with_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, case_id = _case(tmp_path)
    monkeypatch.setattr(metis_cli, "PinnedTaxiiTransport", lambda **_: _FakeTaxii())

    result = runner.invoke(
        app,
        [
            "metis",
            "taxii",
            "poll",
            "https://feed.example/taxii2/api1",
            "col-1",
            "--into-case",
            str(database),
            "--case-id",
            case_id,
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["indicators"] == 2
    assert payload["imported"] == 2

    document = CaseStore(database).load_case(case_id)
    values = {indicator.value for indicator in document.indicators}
    assert values == {"evil.tld", "203.0.113.7"}
    # Provenance is the pull's source label, carried onto every imported IOC.
    assert all(i.source == "taxii://feed.example/col-1" for i in document.indicators)


class _FakeOpenCti:
    def post(self, url: str, body: bytes, headers: object, *, timeout: float) -> OpenCtiResponse:
        page = {
            "data": {
                "indicators": {
                    "edges": [
                        {
                            "node": {
                                "pattern": "[domain-name:value = 'bad.tld']",
                                "pattern_type": "stix",
                                "revoked": False,
                                "updated_at": "2026-11-22T00:00:00Z",
                            }
                        }
                    ],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        }
        return OpenCtiResponse(200, json.dumps(page).encode("utf-8"), {})


def test_opencti_pull_into_case_imports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database, case_id = _case(tmp_path)
    monkeypatch.setattr(metis_cli, "PinnedOpenCtiTransport", lambda **_: _FakeOpenCti())
    monkeypatch.setenv(TOKEN_ENV, "t0k")

    result = runner.invoke(
        app,
        [
            "metis",
            "opencti",
            "pull",
            "https://opencti.example",
            "--token-env",
            TOKEN_ENV,
            "--into-case",
            str(database),
            "--case-id",
            case_id,
            "--confidence",
            "70",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["imported"] == 1
    document = CaseStore(database).load_case(case_id)
    assert {i.value for i in document.indicators} == {"bad.tld"}
    assert all(i.confidence == 70 for i in document.indicators)
    assert all(i.source == "opencti://opencti.example" for i in document.indicators)


def test_into_case_requires_case_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database, _ = _case(tmp_path)
    monkeypatch.setattr(metis_cli, "PinnedTaxiiTransport", lambda **_: _FakeTaxii())
    result = runner.invoke(
        app,
        [
            "metis",
            "taxii",
            "poll",
            "https://feed.example/taxii2/api1",
            "col-1",
            "--into-case",
            str(database),
        ],
    )
    assert result.exit_code != 0
    assert "case-id" in result.output


def test_into_case_unknown_case_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _ = _case(tmp_path)
    monkeypatch.setattr(metis_cli, "PinnedTaxiiTransport", lambda **_: _FakeTaxii())
    result = runner.invoke(
        app,
        [
            "metis",
            "taxii",
            "poll",
            "https://feed.example/taxii2/api1",
            "col-1",
            "--into-case",
            str(database),
            "--case-id",
            "case-doesnotexist000000000000",
        ],
    )
    assert result.exit_code != 0  # unknown case -> fail-closed, nothing imported
