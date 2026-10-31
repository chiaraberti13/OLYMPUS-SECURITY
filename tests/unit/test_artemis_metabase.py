"""Unit tests for the Artemis Metabase CVE-2026-72898 exposure check."""

import json
from pathlib import Path

from olympus.artemis.http import HttpClientError, HttpResponse
from olympus.artemis.metabase import CVE_ID, MetabaseReport, detect_metabase
from olympus.core.coverage import FailureKind, RunStatus
from olympus.core.enums import Severity
from olympus.core.execution import ExecutionPolicy

ASSET = "AST-2026-00001"
BASE = "https://target.example"


def _scope(tmp_path: Path) -> Path:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "engagement": "t",
                "allowed_origins": [BASE],
                "allowed_path_prefixes": ["/api"],
                "allowed_ip_networks": ["192.0.2.0/24"],
            }
        ),
        encoding="utf-8",
    )
    return path


class _Resolver:
    def resolve(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        return ["192.0.2.10"]


class _Transport:
    def __init__(self, responses: dict[str, HttpResponse], *, error: bool = False) -> None:
        self._responses = responses
        self._error = error

    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del addresses, timeout, max_bytes
        if self._error:
            raise HttpClientError("boom")
        for suffix, response in self._responses.items():
            if url.endswith(suffix):
                return response
        return HttpResponse(url, 404, {}, b"")


def _properties(url_base: str, tag: str) -> dict[str, HttpResponse]:
    body = json.dumps({"version": {"tag": tag}}).encode()
    return {
        "/api/session/properties": HttpResponse(
            f"{url_base}/api/session/properties", 200, {}, body
        ),
        "/api/session/reset_password": HttpResponse(
            f"{url_base}/api/session/reset_password", 405, {}, b""
        ),
    }


def _run(tmp_path: Path, transport: _Transport) -> MetabaseReport:
    return detect_metabase(
        ASSET,
        BASE,
        _scope(tmp_path),
        tmp_path / "log",
        _Resolver(),
        transport,
        policy=ExecutionPolicy(authorized=True, timeout_seconds=5.0, deadline_seconds=60.0),
    )


def test_flags_affected_version_as_critical(tmp_path: Path) -> None:
    report = _run(tmp_path, _Transport(_properties(BASE, "v0.60.10")))
    assert len(report.findings) == 1
    assert report.findings[0].severity is Severity.CRITICAL
    assert CVE_ID in report.findings[0].title
    assert report.findings[0].cvss == 9.8
    assert any("reset_password" in e for e in report.findings[0].evidence)
    assert report.status is RunStatus.FINDINGS
    assert report.coverage.complete is True


def test_patched_version_is_low_severity(tmp_path: Path) -> None:
    report = _run(tmp_path, _Transport(_properties(BASE, "v0.60.17")))
    assert report.findings[0].severity is Severity.LOW


def test_boundary_highest_affected_is_critical(tmp_path: Path) -> None:
    report = _run(tmp_path, _Transport(_properties(BASE, "v0.62.8")))
    assert report.findings[0].severity is Severity.CRITICAL


def test_non_metabase_endpoint_is_a_clean_answer(tmp_path: Path) -> None:
    """The host answered and is not Metabase: full coverage, no findings."""
    transport = _Transport(
        {"/api/session/properties": HttpResponse(f"{BASE}/api/session/properties", 200, {}, b"hi")}
    )
    report = _run(tmp_path, transport)

    assert report.findings == ()
    assert report.identified is False
    assert report.coverage.complete is True
    assert report.status is RunStatus.CLEAN


def test_missing_endpoint_is_a_clean_answer(tmp_path: Path) -> None:
    transport = _Transport(
        {"/api/session/properties": HttpResponse(f"{BASE}/api/session/properties", 404, {}, b"")}
    )
    report = _run(tmp_path, transport)

    assert report.findings == ()
    assert report.status is RunStatus.CLEAN


def test_transport_error_is_reported_as_failed_not_clean(tmp_path: Path) -> None:
    """An unreachable target must never produce the same output as a safe one."""
    report = _run(tmp_path, _Transport({}, error=True))

    assert report.findings == ()
    assert report.identified is False
    assert report.status is RunStatus.FAILED
    assert report.coverage.reasons == {FailureKind.TRANSPORT_ERROR: 1}
    assert report.coverage.errors and "boom" in report.coverage.errors[0]


def test_unreachable_vulnerable_endpoint_is_partial(tmp_path: Path) -> None:
    """The instance was identified but the second probe failed: partial, not clean."""

    class _HalfBroken(_Transport):
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            if url.endswith("/api/session/reset_password"):
                raise HttpClientError("connection reset")
            return super().get(url, addresses, timeout, max_bytes)

    report = _run(tmp_path, _HalfBroken(_properties(BASE, "v0.60.17")))

    assert report.identified is True
    assert report.status is RunStatus.PARTIAL
    assert report.coverage.reasons == {FailureKind.TRANSPORT_ERROR: 1}


def test_unparseable_version_is_low_severity(tmp_path: Path) -> None:
    report = _run(tmp_path, _Transport(_properties(BASE, "nightly")))
    assert len(report.findings) == 1
    assert report.findings[0].severity is Severity.LOW
