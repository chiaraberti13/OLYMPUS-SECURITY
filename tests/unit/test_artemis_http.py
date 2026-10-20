"""Offline tests for bounded and redirect-safe Artemis HTTP flows."""

from __future__ import annotations

import gzip
import json
import socket
import ssl
from pathlib import Path

import pytest
from typer.testing import CliRunner

from olympus.artemis import cli as artemis_cli
from olympus.artemis import http as artemis_http
from olympus.artemis.application import ScopedFetchRequest, ScopedFetchService
from olympus.artemis.http import (
    HttpClientError,
    HttpResponse,
    PinnedTransport,
    SocketResolver,
    fetch_scoped,
)
from olympus.artemis.scope import OutOfScopeError, ScopeError
from olympus.cli import app
from olympus.core.execution import (
    AuthorizationRequiredError,
    CancellationRequested,
    CancellationToken,
    ExecutionPolicy,
)

runner = CliRunner()


class FakeTransport:
    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        self.responses = responses
        self.requested: list[tuple[str, tuple[str, ...], float, int]] = []

    def get(
        self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
    ) -> HttpResponse:
        self.requested.append((url, addresses, timeout, max_bytes))
        return self.responses[url]


class FakeResolver:
    def __init__(self, addresses: list[str] | None = None) -> None:
        self.addresses = ["192.0.2.10"] if addresses is None else addresses
        self.requests: list[tuple[str, int]] = []

    def resolve(self, hostname: str, port: int) -> list[str]:
        self.requests.append((hostname, port))
        return self.addresses


def _scope(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "allowed_origins": ["https://portal.olympusdemocorp.example"],
                "allowed_path_prefixes": ["/app"],
                "allowed_ip_networks": ["192.0.2.0/24", "2001:db8::/32"],
            }
        )
    )
    return path


def _policy(timeout: float = 5.0) -> ExecutionPolicy:
    return ExecutionPolicy(authorized=True, timeout_seconds=timeout, deadline_seconds=60.0)


def test_fetch_follows_only_scope_checked_redirects(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    home = "https://portal.olympusdemocorp.example/app/home"
    transport = FakeTransport(
        {
            login: HttpResponse(login, 302, {"location": "/app/home"}, b""),
            home: HttpResponse(home, 200, {"content-type": "text/html"}, b"demo"),
        }
    )

    result = fetch_scoped(
        login,
        _scope(tmp_path / "scope.json"),
        tmp_path / "log",
        FakeResolver(),
        transport,
        policy=_policy(),
    )

    assert result.response.body == b"demo"
    assert result.redirects == [home]
    assert [request[0] for request in transport.requested] == [login, home]
    assert all(request[1] == ("192.0.2.10",) for request in transport.requested)


def test_fetch_blocks_redirect_before_second_request(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport(
        {login: HttpResponse(login, 302, {"location": "https://outside.example/steal"}, b"")}
    )

    with pytest.raises(OutOfScopeError):
        fetch_scoped(
            login,
            _scope(tmp_path / "scope.json"),
            tmp_path / "log",
            FakeResolver(),
            transport,
            policy=_policy(),
        )
    assert len(transport.requested) == 1


def test_fetch_requires_every_ipv4_ipv6_answer_in_scope(tmp_path: Path) -> None:
    target = "https://portal.olympusdemocorp.example/app"
    transport = FakeTransport({target: HttpResponse(target, 200, {}, b"")})
    scope = _scope(tmp_path / "scope.json")

    fetch_scoped(
        target,
        scope,
        tmp_path / "log",
        FakeResolver(["192.0.2.10", "2001:db8::10"]),
        transport,
        policy=_policy(),
    )
    assert transport.requested[0][1] == ("192.0.2.10", "2001:db8::10")

    with pytest.raises(OutOfScopeError):
        fetch_scoped(
            target,
            scope,
            tmp_path / "blocked.log",
            FakeResolver(["192.0.2.10", "127.0.0.1"]),
            transport,
            policy=_policy(),
        )
    assert "resolved_address_not_allowed" in (tmp_path / "blocked.log").read_text()
    with pytest.raises(ScopeError, match="no addresses"):
        fetch_scoped(target, scope, tmp_path / "log", FakeResolver([]), transport, policy=_policy())


def test_fetch_enforces_redirect_and_option_limits(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport({login: HttpResponse(login, 302, {"location": "/app/login"}, b"")})
    scope = _scope(tmp_path / "scope.json")

    with pytest.raises(HttpClientError, match="redirect limit"):
        fetch_scoped(
            login,
            scope,
            tmp_path / "log",
            FakeResolver(),
            transport,
            policy=_policy(),
            max_redirects=0,
        )
    with pytest.raises(ValueError, match="timeout"):
        fetch_scoped(
            login, scope, tmp_path / "log", FakeResolver(), transport, policy=_policy(0.05)
        )
    with pytest.raises(ValueError, match="max_bytes"):
        fetch_scoped(
            login,
            scope,
            tmp_path / "log",
            FakeResolver(),
            transport,
            policy=_policy(),
            max_bytes=0,
        )


def test_fetch_service_checks_policy_before_dns_or_transport(tmp_path: Path) -> None:
    target = "https://portal.olympusdemocorp.example/app"
    resolver = FakeResolver()
    transport = FakeTransport({target: HttpResponse(target, 200, {}, b"")})
    service = ScopedFetchService(resolver, transport)
    request = ScopedFetchRequest(
        url=target,
        scope_path=_scope(tmp_path / "scope.json"),
        audit_log_path=tmp_path / "blocked.log",
    )

    with pytest.raises(AuthorizationRequiredError):
        service.run(request)
    assert resolver.requests == []
    assert transport.requested == []

    with pytest.raises(OutOfScopeError):
        service.run(
            ScopedFetchRequest(
                url="https://outside.example/app",
                scope_path=request.scope_path,
                audit_log_path=request.audit_log_path,
                authorized=True,
            )
        )
    assert resolver.requests == []
    assert transport.requested == []


def test_fetch_service_observes_cancellation_before_dns(tmp_path: Path) -> None:
    target = "https://portal.olympusdemocorp.example/app"
    resolver = FakeResolver()
    transport = FakeTransport({target: HttpResponse(target, 200, {}, b"")})
    token = CancellationToken()
    token.cancel()

    with pytest.raises(CancellationRequested):
        ScopedFetchService(resolver, transport, token).run(
            ScopedFetchRequest(
                url=target,
                scope_path=_scope(tmp_path / "scope.json"),
                audit_log_path=tmp_path / "blocked.log",
                authorized=True,
            )
        )
    assert resolver.requests == []
    assert transport.requested == []


def test_fetch_retries_only_transport_failures(tmp_path: Path) -> None:
    target = "https://portal.olympusdemocorp.example/app"

    class FlakyTransport:
        def __init__(self) -> None:
            self.attempts = 0

        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del addresses, timeout, max_bytes
            self.attempts += 1
            if self.attempts == 1:
                raise HttpClientError("temporary transport failure")
            return HttpResponse(url, 200, {}, b"ok")

    transport = FlakyTransport()
    result = fetch_scoped(
        target,
        _scope(tmp_path / "scope.json"),
        tmp_path / "blocked.log",
        FakeResolver(),
        transport,
        policy=ExecutionPolicy(
            authorized=True,
            timeout_seconds=1.0,
            deadline_seconds=5.0,
            retries=1,
            backoff_seconds=0.0,
        ),
    )

    assert result.response.body == b"ok"
    assert transport.attempts == 2


def test_fetch_rejects_redirect_without_location(tmp_path: Path) -> None:
    login = "https://portal.olympusdemocorp.example/app/login"
    transport = FakeTransport({login: HttpResponse(login, 301, {}, b"")})
    with pytest.raises(HttpClientError, match="Location"):
        fetch_scoped(
            login,
            _scope(tmp_path / "scope.json"),
            tmp_path / "log",
            FakeResolver(),
            transport,
            policy=_policy(),
        )


class FakeRawResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.headers = {"Content-Type": "text/plain"}

    def read(self, size: int) -> bytes:
        return self.body[:size]

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self.headers.items())


class FakeConnection:
    response = FakeRawResponse(b"demo")

    def __init__(self, hostname: str, address: str, port: int, timeout: float) -> None:
        self.arguments = (hostname, address, port, timeout)

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:
        del method, path, headers

    def getresponse(self) -> FakeRawResponse:
        return self.response

    def close(self) -> None:
        return None


def test_pinned_transport_enforces_scheme_address_and_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(artemis_http, "_PinnedHTTPSConnection", FakeConnection)
    response = PinnedTransport().get(
        "https://portal.olympusdemocorp.example/app", ("192.0.2.10",), 1.0, 4
    )
    assert response.body == b"demo"
    assert response.headers == {"content-type": "text/plain"}
    monkeypatch.setattr(artemis_http, "_PinnedHTTPConnection", FakeConnection)
    assert (
        PinnedTransport()
        .get("http://portal.olympusdemocorp.example/app", ("192.0.2.10",), 1.0, 4)
        .status
        == 200
    )

    with pytest.raises(HttpClientError, match=r"HTTP\(S\)"):
        PinnedTransport().get("file:///etc/passwd", ("192.0.2.10",), 1.0, 4)
    with pytest.raises(HttpClientError, match="pinned address"):
        PinnedTransport().get("https://example.test/", (), 1.0, 4)
    FakeConnection.response = FakeRawResponse(b"oversized")
    with pytest.raises(HttpClientError, match="byte limit"):
        PinnedTransport().get("https://portal.olympusdemocorp.example/app", ("192.0.2.10",), 1.0, 4)


def test_pinned_transport_requests_and_bounds_content_codings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent_headers: dict[str, str] = {}

    class RecordingConnection(FakeConnection):
        def request(self, method: str, path: str, headers: dict[str, str]) -> None:
            sent_headers.update(headers)

    compressed = FakeRawResponse(gzip.compress(b"decoded"))
    compressed.headers = {"Content-Type": "text/plain", "Content-Encoding": "gzip"}
    RecordingConnection.response = compressed
    monkeypatch.setattr(artemis_http, "_PinnedHTTPSConnection", RecordingConnection)

    response = PinnedTransport().get(
        "https://portal.olympusdemocorp.example/app", ("192.0.2.10",), 1.0, 100_000
    )

    assert response.body == b"decoded"
    assert sent_headers["Accept-Encoding"] == artemis_http.ACCEPT_ENCODING

    bomb = FakeRawResponse(gzip.compress(b"\0" * 10_000_000))
    bomb.headers = {"Content-Encoding": "gzip"}
    RecordingConnection.response = bomb
    with pytest.raises(HttpClientError, match="could not be safely decoded"):
        PinnedTransport().get(
            "https://portal.olympusdemocorp.example/app", ("192.0.2.10",), 1.0, 100_000
        )


def test_socket_resolver_deduplicates_and_wraps_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    records = [
        (2, 1, 6, "", ("192.0.2.10", 443)),
        (2, 1, 6, "", ("192.0.2.10", 443)),
        (10, 1, 6, "", ("2001:db8::10", 443, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    assert SocketResolver().resolve("demo.example", 443) == ["192.0.2.10", "2001:db8::10"]

    def fail(*args: object, **kwargs: object) -> list[object]:
        raise OSError("synthetic DNS failure")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(HttpClientError, match="DNS resolution failed"):
        SocketResolver().resolve("demo.example", 443)


def test_pinned_connections_use_only_supplied_address(monkeypatch: pytest.MonkeyPatch) -> None:
    connected: list[tuple[str, int]] = []

    def connect(address: tuple[str, int], timeout: float) -> object:
        del timeout
        connected.append(address)
        return object()

    class FakeContext:
        # http.client reads these SSLContext attributes before wrapping the
        # socket (Python 3.11+); expose them so the stub matches a real context.
        verify_mode = ssl.CERT_NONE
        check_hostname = False

        def wrap_socket(self, raw_socket: object, server_hostname: str) -> object:
            del server_hostname
            return raw_socket

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl, "create_default_context", FakeContext)
    plain = artemis_http._PinnedHTTPConnection("demo.example", "192.0.2.10", 80, 1.0)
    secure = artemis_http._PinnedHTTPSConnection("demo.example", "2001:db8::10", 443, 1.0)
    plain.connect()
    secure.connect()

    assert connected == [("192.0.2.10", 80), ("2001:db8::10", 443)]


def test_fetch_cli_prints_metadata_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = "https://portal.olympusdemocorp.example/app"
    transport = FakeTransport({target: HttpResponse(target, 200, {}, b"BODY-CONTENT")})
    monkeypatch.setattr(artemis_cli, "PinnedTransport", lambda: transport)
    monkeypatch.setattr(artemis_cli, "SocketResolver", FakeResolver)

    result = runner.invoke(
        app,
        [
            "artemis",
            "fetch",
            "--url",
            target,
            "--scope",
            str(_scope(tmp_path / "scope.json")),
            "--log",
            str(tmp_path / "log"),
            "--i-am-authorized",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["body_bytes"] == 12
    assert "BODY-CONTENT" not in result.stdout


def test_fetch_cli_sanitizes_transport_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _HostileTransport:
        def get(
            self, url: str, addresses: tuple[str, ...], timeout: float, max_bytes: int
        ) -> HttpResponse:
            del url, addresses, timeout, max_bytes
            raise HttpClientError("reset\x1b[2J\nforged diagnostic")

    monkeypatch.setattr(artemis_cli, "PinnedTransport", _HostileTransport)
    monkeypatch.setattr(artemis_cli, "SocketResolver", FakeResolver)
    result = runner.invoke(
        app,
        [
            "artemis",
            "fetch",
            "--url",
            "https://portal.olympusdemocorp.example/app",
            "--scope",
            str(_scope(tmp_path / "scope.json")),
            "--log",
            str(tmp_path / "log"),
            "--i-am-authorized",
        ],
    )

    assert result.exit_code == 6, result.output
    assert "\x1b" not in result.output
    assert "\nforged diagnostic" not in result.output
    assert "fetch failed: reset[2J forged diagnostic" in result.output


def test_fetch_cli_requires_authorization_before_adapters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = "https://portal.olympusdemocorp.example/app"
    resolver = FakeResolver()
    transport = FakeTransport({target: HttpResponse(target, 200, {}, b"")})
    monkeypatch.setattr(artemis_cli, "PinnedTransport", lambda: transport)
    monkeypatch.setattr(artemis_cli, "SocketResolver", lambda: resolver)

    result = runner.invoke(
        app,
        [
            "artemis",
            "fetch",
            "--url",
            target,
            "--scope",
            str(_scope(tmp_path / "scope.json")),
        ],
    )

    assert result.exit_code == 4
    assert "AUTHORIZED USE ONLY" in result.output
    assert resolver.requests == []
    assert transport.requested == []
