"""Tests for Artemis authorized content/directory discovery."""

import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis.content import (
    DiscoveredPath,
    WordlistError,
    discover_content,
    discoveries_to_findings,
    load_wordlist,
)
from olympus.artemis.http import HttpClientError, HttpResponse
from olympus.cli import app
from olympus.core.coverage import FailureKind, RunStatus
from olympus.core.execution import (
    CancellationRequested,
    CancellationToken,
    ExecutionPolicy,
)

runner = CliRunner()

BASE = "https://portal.olympusdemocorp.example/app"


def _policy() -> ExecutionPolicy:
    return ExecutionPolicy(authorized=True, timeout_seconds=5.0, deadline_seconds=60.0)


def _write_scope(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "engagement": "olympus-demo-corp-2026",
                "allowed_origins": ["https://portal.olympusdemocorp.example"],
                "allowed_path_prefixes": ["/app"],
                "allowed_ip_networks": ["192.0.2.0/24"],
            }
        ),
        encoding="utf-8",
    )
    return path


def _wordlist(path: Path, words: list[str]) -> Path:
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
    return path


class _Resolver:
    def resolve(self, hostname: str, port: int) -> list[str]:
        del hostname, port
        return ["192.0.2.10"]


class _Transport:
    """Serves 200 for /app/admin and /app/.env, 404 for everything else."""

    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        del addresses, timeout, max_bytes
        if url.endswith("/app/admin"):
            return HttpResponse(url, 200, {}, b"admin console")
        if url.endswith("/app/.env"):
            return HttpResponse(url, 200, {}, b"SECRET=redacted")
        return HttpResponse(url, 404, {}, b"not found")


def test_load_wordlist_dedupes_and_skips_comments(tmp_path: Path) -> None:
    path = _wordlist(tmp_path / "w.txt", ["# comment", "admin", "", "/admin", "login"])
    assert load_wordlist(path) == ["admin", "login"]


def test_load_wordlist_rejects_empty(tmp_path: Path) -> None:
    path = _wordlist(tmp_path / "w.txt", ["# only comments"])
    with pytest.raises(WordlistError):
        load_wordlist(path)


def test_discover_reports_only_existing_paths(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path / "scope.json")
    report = discover_content(
        BASE,
        ["admin", "login", ".env", "missing"],
        scope,
        tmp_path / "blocked.log",
        _Resolver(),
        _Transport(),
        policy=_policy(),
    )
    paths = {d.path: d.status for d in report.discovered}
    assert paths == {"admin": 200, ".env": 200}
    assert report.coverage.planned == 4
    assert report.coverage.completed == 4
    assert report.status is RunStatus.FINDINGS


def test_sensitive_paths_are_escalated_to_low() -> None:
    discovered = [
        DiscoveredPath(path="admin", url=f"{BASE}/admin", status=200, length=13),
        DiscoveredPath(path=".env", url=f"{BASE}/.env", status=200, length=15),
    ]
    findings = {f.title: f for f in discoveries_to_findings("AST-1", discovered)}
    env_finding = next(f for t, f in findings.items() if ".env" in t)
    assert env_finding.severity.value == "low"
    assert env_finding.remediation  # sensitive paths carry remediation


def test_out_of_scope_base_is_reported_as_failed_not_clean(tmp_path: Path) -> None:
    """Every candidate blocked is a run that covered nothing, not a clean one."""
    scope = _write_scope(tmp_path / "scope.json")
    log = tmp_path / "blocked.log"
    # /admin-area is outside the authorized /app prefix -> every candidate blocked.
    report = discover_content(
        "https://portal.olympusdemocorp.example/admin-area",
        ["admin", ".env"],
        scope,
        log,
        _Resolver(),
        _Transport(),
        policy=_policy(),
    )
    assert report.discovered == ()
    assert report.coverage.completed == 0
    assert report.coverage.reasons == {FailureKind.SCOPE_DENIED: 2}
    assert report.status is RunStatus.FAILED
    assert log.exists()  # blocked candidates are audited


def test_transport_failures_are_counted_not_dropped(tmp_path: Path) -> None:
    class _Flaky:
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del addresses, timeout, max_bytes
            if url.endswith("/admin"):
                return HttpResponse(url, 200, {}, b"admin console")
            raise HttpClientError("connection reset by peer")

    report = discover_content(
        BASE,
        ["admin", "login", "backup"],
        _write_scope(tmp_path / "scope.json"),
        tmp_path / "blocked.log",
        _Resolver(),
        _Flaky(),
        policy=_policy(),
    )

    assert [d.path for d in report.discovered] == ["admin"]
    assert report.coverage.completed == 1
    assert report.coverage.failed == 2
    assert report.coverage.reasons == {FailureKind.TRANSPORT_ERROR: 2}
    # A finding was produced, but coverage was lost: partial outranks findings.
    assert report.status is RunStatus.PARTIAL
    assert any("connection reset" in sample for sample in report.coverage.errors)


def test_deadline_records_the_candidates_never_tried(tmp_path: Path) -> None:
    class _Slow:
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del addresses, timeout, max_bytes
            time.sleep(0.15)
            return HttpResponse(url, 404, {}, b"")

    report = discover_content(
        BASE,
        ["a", "b", "c", "d", "e"],
        _write_scope(tmp_path / "scope.json"),
        tmp_path / "blocked.log",
        _Resolver(),
        _Slow(),
        policy=ExecutionPolicy(authorized=True, timeout_seconds=1.0, deadline_seconds=0.3),
    )

    assert report.coverage.skipped > 0
    assert report.coverage.reasons[FailureKind.DEADLINE_EXCEEDED] == report.coverage.skipped
    assert report.status is not RunStatus.CLEAN


def test_cancellation_stops_discovery_and_is_raised(tmp_path: Path) -> None:
    token = CancellationToken()

    class _CancelAfterFirst:
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del addresses, timeout, max_bytes
            token.cancel()
            return HttpResponse(url, 404, {}, b"")

    with pytest.raises(CancellationRequested):
        discover_content(
            BASE,
            ["a", "b", "c"],
            _write_scope(tmp_path / "scope.json"),
            tmp_path / "blocked.log",
            _Resolver(),
            _CancelAfterFirst(),
            policy=_policy(),
            cancellation=token,
        )


def test_rate_limit_jitter_stays_within_the_configured_band() -> None:
    policy = ExecutionPolicy(
        authorized=True,
        timeout_seconds=1.0,
        min_interval_seconds=1.0,
        jitter_ratio=0.25,
    )

    assert policy.next_interval(lambda: 0.0) == pytest.approx(0.75)
    assert policy.next_interval(lambda: 1.0) == pytest.approx(1.25)
    assert policy.next_interval(lambda: 0.5) == pytest.approx(1.0)
    # Without jitter the interval is exactly what the operator asked for.
    plain = ExecutionPolicy(authorized=True, min_interval_seconds=2.0)
    assert plain.next_interval(lambda: 0.0) == 2.0


def test_cli_content_requires_authorization(tmp_path: Path) -> None:
    scope = _write_scope(tmp_path / "scope.json")
    wl = _wordlist(tmp_path / "w.txt", ["admin"])
    result = runner.invoke(
        app,
        ["artemis", "content", "--url", BASE, "--wordlist", str(wl), "--scope", str(scope)],
    )
    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output


def test_cli_content_reports_partial_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run whose requests failed must not exit 0 with an empty findings list."""

    class _Broken:
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del url, addresses, timeout, max_bytes
            raise HttpClientError("connection reset by peer")

    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _Broken)
    scope = _write_scope(tmp_path / "scope.json")
    wl = _wordlist(tmp_path / "w.txt", ["admin", "login"])

    result = runner.invoke(
        app,
        [
            "artemis",
            "content",
            "--url",
            BASE,
            "--wordlist",
            str(wl),
            "--scope",
            str(scope),
            "--log",
            str(tmp_path / "b.log"),
            "--i-am-authorized",
        ],
    )

    assert result.exit_code == 6, result.output
    assert "status=failed" in result.output
    assert "transport_error=2" in result.output


def test_cli_content_finds_paths_with_exit_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(artemis_cli, "SocketResolver", _Resolver)
    monkeypatch.setattr(artemis_cli, "PinnedTransport", _Transport)
    scope = _write_scope(tmp_path / "scope.json")
    wl = _wordlist(tmp_path / "w.txt", ["admin", "login", ".env"])
    out = tmp_path / "findings.json"
    result = runner.invoke(
        app,
        [
            "artemis",
            "content",
            "--url",
            BASE,
            "--wordlist",
            str(wl),
            "--scope",
            str(scope),
            "--log",
            str(tmp_path / "b.log"),
            "--i-am-authorized",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 1, result.output
    assert "status=findings" in result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    titles = " ".join(f["title"] for f in findings)
    assert "/admin" in titles
    assert "/.env" in titles
