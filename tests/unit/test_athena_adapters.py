"""Tests for Athena tool adapters, registry, SQLite repository, and reporting."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from olympus.athena.adapters.report import VulcanReportRenderer
from olympus.athena.adapters.sqlite import (
    ResultTooLargeError,
    SqliteAssessmentRepository,
)
from olympus.athena.adapters.tools.dns_records import DnsRecordsAdapter
from olympus.athena.adapters.tools.web_headers import WebHeadersAdapter
from olympus.athena.adapters.tools.whois import WhoisAdapter
from olympus.athena.application.registry import (
    UnknownAdapterError,
    available_adapters,
    resolve_adapters,
)
from olympus.athena.domain.assessment import Assessment, Job
from olympus.athena.domain.contracts import AssessmentResult, load_plan
from olympus.athena.ports import ToolRequest
from olympus.core.enums import Severity, Source
from olympus.core.http import HttpRequestError, HttpResponse
from olympus.core.models import Finding


def _public_dns(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
    return [(2, 1, 6, "", ("93.184.216.34", 0))]


class _NoCancel:
    def is_cancelled(self) -> bool:
        return False


class _Cancelled:
    def is_cancelled(self) -> bool:
        return True


class _Http:
    def __init__(self, response: HttpResponse | None = None, raise_error: bool = False) -> None:
        self._response = response
        self._raise = raise_error

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        if self._raise:
            raise HttpRequestError("down")
        assert self._response is not None
        return self._response


def _request(kind: str = "domain", value: str = "example.com") -> ToolRequest:
    return ToolRequest(
        target_kind=kind, target_value=value, allowed_domains=("example.com",), timeout_seconds=30
    )


# -- web-headers adapter --------------------------------------------------- #
def test_web_headers_adapter_ok() -> None:
    http = _Http(HttpResponse(status_code=200, headers={"Server": "nginx"}, body=""))
    adapter = WebHeadersAdapter(http, resolver=_public_dns)
    assert adapter.name == "web-headers"
    assert adapter.capabilities
    result = adapter.run(_request(kind="url", value="https://example.com"), _NoCancel())
    assert result.ok
    assert result.assets and result.findings


def test_web_headers_adapter_out_of_scope() -> None:
    http = _Http(HttpResponse(status_code=200, headers={}, body=""))
    result = WebHeadersAdapter(http, resolver=_public_dns).run(
        _request(kind="url", value="https://evil.test"), _NoCancel()
    )
    assert not result.ok
    assert result.error_code == "out_of_scope"


def test_web_headers_adapter_cancelled() -> None:
    http = _Http(HttpResponse(status_code=200, headers={}, body=""))
    result = WebHeadersAdapter(http, resolver=_public_dns).run(_request(), _Cancelled())
    assert result.error_code == "cancelled"


def test_web_headers_adapter_unreachable() -> None:
    result = WebHeadersAdapter(_Http(raise_error=True), resolver=_public_dns).run(
        _request(), _NoCancel()
    )
    assert result.error_code == "unreachable"


def test_web_headers_adapter_ssrf() -> None:
    http = _Http(HttpResponse(status_code=200, headers={}, body=""))
    result = WebHeadersAdapter(http, resolver=_public_dns).run(
        ToolRequest("url", "http://127.0.0.1", ("example.com",), 30), _NoCancel()
    )
    assert result.error_code == "ssrf_blocked"


def test_web_headers_adapter_invalid_target() -> None:
    http = _Http(HttpResponse(status_code=200, headers={}, body=""))
    result = WebHeadersAdapter(http, resolver=_public_dns).run(
        ToolRequest("domain", "nodot", ("example.com",), 30), _NoCancel()
    )
    assert result.error_code == "invalid_target"


def test_web_headers_adapter_blocks_hostname_resolving_private() -> None:
    def _private_dns(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [(2, 1, 6, "", ("127.0.0.1", 0))]

    http = _Http(HttpResponse(status_code=200, headers={}, body=""))
    result = WebHeadersAdapter(http, resolver=_private_dns).run(
        _request(kind="url", value="https://example.com"), _NoCancel()
    )
    assert result.error_code == "ssrf_blocked"


# -- dns adapter ----------------------------------------------------------- #
def test_dns_adapter_ok() -> None:
    body = json.dumps({"Answer": [{"data": "203.0.113.9"}]})
    http = _Http(HttpResponse(status_code=200, headers={}, body=body))
    result = DnsRecordsAdapter(http).run(_request(), _NoCancel())
    assert result.ok and result.assets


def test_dns_adapter_unreachable() -> None:
    result = DnsRecordsAdapter(_Http(raise_error=True)).run(_request(), _NoCancel())
    assert result.error_code == "unreachable"


# -- whois adapter --------------------------------------------------------- #
def test_whois_adapter_ok() -> None:
    body = json.dumps({"ldhName": "example.com", "status": ["active"]})
    http = _Http(HttpResponse(status_code=200, headers={}, body=body))
    result = WhoisAdapter(http).run(_request(), _NoCancel())
    assert result.ok and result.assets


def test_whois_adapter_failure() -> None:
    http = _Http(HttpResponse(status_code=404, headers={}, body=""))
    result = WhoisAdapter(http).run(_request(), _NoCancel())
    assert result.error_code == "lookup_failed"


# -- registry -------------------------------------------------------------- #
def test_registry() -> None:
    assert set(available_adapters()) == {"web-headers", "dns", "whois", "aegis"}
    http = _Http(HttpResponse(status_code=200, headers={}, body="{}"))
    runners = resolve_adapters(("dns", "whois"), http)
    assert set(runners) == {"dns", "whois"}
    with pytest.raises(UnknownAdapterError):
        resolve_adapters(("nope",), http)


# -- sqlite repository ----------------------------------------------------- #
def _plan_dict() -> dict[str, object]:
    return {
        "engagement_id": "ENG-1",
        "name": "demo",
        "targets": [{"kind": "domain", "value": "example.com"}],
        "adapters": ["dns"],
        "scope": {"allowed_domains": ["example.com"]},
        "authorization": {
            "engagement_id": "ENG-1",
            "approval_reference": "T",
            "confirmed": True,
        },
    }


def test_sqlite_plan_roundtrip(tmp_path: Path) -> None:
    repo = SqliteAssessmentRepository(tmp_path / "db" / "athena.db")
    plan = load_plan(_plan_dict())
    plan_id = repo.save_plan(plan)
    assert repo.save_plan(plan) == plan_id  # idempotent
    loaded = repo.load_plan(plan_id)
    assert loaded is not None and loaded.digest() == plan.digest()
    assert repo.load_plan("PLAN-missing") is None
    repo.close()


def test_sqlite_result_cap(tmp_path: Path) -> None:
    repo = SqliteAssessmentRepository(tmp_path / "athena.db")
    plan = load_plan(_plan_dict())
    plan_id = repo.save_plan(plan)
    job = Job(job_id="J1", adapter="dns", target_kind="domain", target_value="example.com")
    repo.save_assessment(Assessment(assessment_id="A1", plan_id=plan_id, jobs=(job,)))
    document = AssessmentResult(
        assessment_id="A1",
        job=job.to_contract("A1").model_copy(update={"state": "succeeded"}),
    ).canonical_json()
    rid = repo.save_result("A1", "J1", document)
    loaded = repo.load_result(rid)
    assert loaded is not None
    assert json.loads(loaded)["schema_name"] == "olympus.athena.result"
    assert repo.load_result("RES-missing") is None
    with pytest.raises(ResultTooLargeError):
        repo.save_result("A1", "J1", "x" * 2_000_000)
    repo.close()


def test_sqlite_transition_missing_assessment(tmp_path: Path) -> None:
    from olympus.athena.domain.assessment import AssessmentState

    repo = SqliteAssessmentRepository(tmp_path / "athena.db")
    with pytest.raises(LookupError):
        repo.transition_assessment("ghost", AssessmentState.RUNNING)
    repo.close()


def test_sqlite_audit_rows(tmp_path: Path) -> None:
    repo = SqliteAssessmentRepository(tmp_path / "athena.db")
    plan_id = repo.save_plan(load_plan(_plan_dict()))
    repo.save_assessment(Assessment(assessment_id="A1", plan_id=plan_id))
    repo.append_audit("A1", 0, "t", "created", "planned", None, json.dumps({"count": "1"}))
    events = repo.audit_events("A1")
    assert events and events[0]["action"] == "created"
    repo.close()


# -- report renderer ------------------------------------------------------- #
def test_report_renderer() -> None:
    finding = Finding(asset_id="AST-1", source=Source.ARGUS, title="x", severity=Severity.LOW)
    renderer = VulcanReportRenderer("ENG-1")
    assert "ENG-1" in renderer.render([finding], "markdown")
    payload = json.loads(renderer.render([finding], "json"))
    assert payload["engagement"] == "ENG-1"


class _MarkedHttp:
    """An HTTP client that only records which transport an adapter received."""

    def __init__(self, label: str) -> None:
        self.label = label

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        raise AssertionError("this stub is only used for identity checks")


def test_target_and_service_adapters_get_separate_transports() -> None:
    target = _MarkedHttp("target")
    service = _MarkedHttp("service")

    runners = resolve_adapters(("web-headers", "dns", "whois"), target, service_http=service)

    # The web adapter connects to the engagement's own hosts...
    assert runners["web-headers"]._http is target
    # ...while DoH and RDAP go to fixed third-party services that are never in
    # the engagement scope. Sharing one scoped client would break both.
    assert runners["dns"]._http is service
    assert runners["whois"]._http is service


def test_service_hosts_cover_every_endpoint_the_lookup_adapters_use() -> None:
    from urllib.parse import urlsplit

    from olympus.argus import dns_records, whois
    from olympus.athena.application.registry import SERVICE_HOSTS

    used = {
        urlsplit(url).hostname
        for url in (dns_records._CLOUDFLARE, dns_records._GOOGLE, whois._RDAP_URL)
    }

    assert used <= set(SERVICE_HOSTS)


def test_service_policy_and_engagement_policy_do_not_overlap() -> None:
    from olympus.athena.application.registry import SERVICE_HOSTS
    from olympus.athena.scope import (
        TargetOutOfScopeError,
        scoped_address_policy,
    )

    def resolver(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    service_policy = scoped_address_policy(SERVICE_HOSTS, resolver=resolver)
    engagement_policy = scoped_address_policy(("example.com",), resolver=resolver)

    assert service_policy("dns.google") == ("93.184.216.34",)
    with pytest.raises(TargetOutOfScopeError):
        service_policy("example.com")
    with pytest.raises(TargetOutOfScopeError):
        engagement_policy("dns.google")
