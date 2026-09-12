"""Unit tests for the shared core HTTP client (network calls are stubbed)."""

from __future__ import annotations

import gzip
import io
import urllib.error
import urllib.request
from typing import Any

import pytest

from olympus.core.execution import CancellationToken, ExecutionPolicy, ExecutionPolicyError
from olympus.core.http import (
    DEFAULT_ACCEPT_ENCODING,
    DEFAULT_MAX_REDIRECTS,
    DEFAULT_MAX_RESPONSE_BYTES,
    USER_AGENT,
    HttpRequestError,
    HttpResponseHeadersTooLarge,
    HttpResponseTooLarge,
    HttpResponseUndecodable,
    UrllibHttpClient,
    _ValidatingRedirectHandler,
)


class _FakeHttpResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self._body = io.BytesIO(body)

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)

    def __enter__(self) -> _FakeHttpResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class _CancelAfterChecks:
    def __init__(self, allowed_checks: int) -> None:
        self._allowed_checks = allowed_checks
        self._checks = 0

    def is_cancelled(self) -> bool:
        self._checks += 1
        return self._checks > self._allowed_checks


def test_redirect_handler_validates_destination_before_following() -> None:
    checked: list[str] = []
    handler = _ValidatingRedirectHandler(checked.append)
    request = handler.redirect_request(
        urllib.request.Request("https://allowed.example/start"),
        None,
        302,
        "Found",
        {},
        "https://redirected.example/path",
    )

    assert checked == ["https://redirected.example/path"]
    assert request is not None


def test_redirect_handler_does_not_follow_rejected_destination() -> None:
    def reject(url: str) -> None:
        raise PermissionError(f"blocked: {url}")

    handler = _ValidatingRedirectHandler(reject)

    with pytest.raises(PermissionError, match="blocked"):
        handler.redirect_request(
            urllib.request.Request("https://allowed.example/start"),
            None,
            302,
            "Found",
            {},
            "http://127.0.0.1/admin",
        )


def test_redirect_handler_has_an_explicit_configurable_limit() -> None:
    handler = _ValidatingRedirectHandler(lambda _url: None, max_redirects=3)
    assert handler.max_redirections == 3
    assert UrllibHttpClient()._max_redirects == DEFAULT_MAX_REDIRECTS
    with pytest.raises(ValueError, match="max_redirects"):
        UrllibHttpClient(max_redirects=DEFAULT_MAX_REDIRECTS + 1)


def test_request_sends_honest_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def _capture(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        captured["headers"] = request.headers
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _capture)
    UrllibHttpClient().get("https://olympusdemocorp.example/")

    assert captured["headers"]["User-agent"] == USER_AGENT
    assert "Mozilla" not in USER_AGENT


def test_returns_normalized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeHttpResponse(200, {"Content-Type": "text/html"}, b"<html>hi</html>")
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=0.0: fake)

    response = UrllibHttpClient().get("https://olympusdemocorp.example/")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "text/html"
    assert response.body == "<html>hi</html>"


def test_http_error_status_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    def _raise(request: Any, timeout: float = 0.0) -> Any:
        raise urllib.error.HTTPError(
            "https://olympusdemocorp.example/missing",
            404,
            "Not Found",
            {"Content-Type": "text/plain"},  # type: ignore[arg-type]
            io.BytesIO(b"not found"),
        )

    monkeypatch.setattr("urllib.request.urlopen", _raise)
    response = UrllibHttpClient().get("https://olympusdemocorp.example/missing")
    assert response.status_code == 404
    assert response.body == "not found"


def test_rejects_response_body_over_configured_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeHttpResponse(200, {}, b"x" * 9)
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=0.0: fake)

    with pytest.raises(HttpResponseTooLarge, match="8 byte limit"):
        UrllibHttpClient(max_response_bytes=8).get("https://olympusdemocorp.example/")


def test_rejects_oversized_content_length_before_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _FakeHttpResponse(200, {"Content-Length": "99"}, b"small")
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=0.0: fake)

    with pytest.raises(HttpResponseTooLarge, match="declares 99 bytes"):
        UrllibHttpClient(max_response_bytes=8).get("https://olympusdemocorp.example/")


def test_response_size_violation_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}

    def _oversized(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        calls["n"] += 1
        return _FakeHttpResponse(200, {}, b"too large")

    monkeypatch.setattr("urllib.request.urlopen", _oversized)
    with pytest.raises(HttpResponseTooLarge):
        UrllibHttpClient(retries=3, max_response_bytes=4).get(
            "https://olympusdemocorp.example/"
        )
    assert calls["n"] == 1


def test_rejects_excessive_response_headers_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    def _many_headers(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        calls["n"] += 1
        return _FakeHttpResponse(200, {"A": "1", "B": "2"}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _many_headers)
    with pytest.raises(HttpResponseHeadersTooLarge, match="header limit"):
        UrllibHttpClient(retries=3, max_response_headers=1).get(
            "https://olympusdemocorp.example/"
        )
    assert calls["n"] == 1


def test_rejects_aggregate_response_header_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeHttpResponse(200, {"Long": "x" * 20}, b"ok")
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=0.0: fake)

    with pytest.raises(HttpResponseHeadersTooLarge, match="byte limit"):
        UrllibHttpClient(max_response_header_bytes=8).get(
            "https://olympusdemocorp.example/"
        )


def test_default_response_limit_is_bounded() -> None:
    client = UrllibHttpClient()
    assert client._max_response_bytes == DEFAULT_MAX_RESPONSE_BYTES
    with pytest.raises(ValueError, match="max_response_bytes"):
        UrllibHttpClient(max_response_bytes=0)


def test_response_body_is_read_in_bounded_chunks(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeHttpResponse(200, {}, b"abcdefghij")
    requested: list[int] = []
    original_read = fake.read

    def _recording_read(amount: int = -1) -> bytes:
        requested.append(amount)
        return original_read(min(amount, 3))

    fake.read = _recording_read  # type: ignore[method-assign]
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=0.0: fake)

    response = UrllibHttpClient(max_response_bytes=16).get(
        "https://olympusdemocorp.example/"
    )

    assert response.body == "abcdefghij"
    assert len(requested) > 1
    assert max(requested) <= 17


def test_cancellation_interrupts_streaming_read(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeHttpResponse(200, {}, b"x" * 32)
    original_read = fake.read

    def _small_read(amount: int = -1) -> bytes:
        return original_read(min(amount, 4))

    fake.read = _small_read  # type: ignore[method-assign]
    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout=0.0: fake)
    cancellation = _CancelAfterChecks(2)

    with pytest.raises(HttpRequestError, match="cancelled"):
        UrllibHttpClient(max_response_bytes=64, cancellation=cancellation).get(
            "https://olympusdemocorp.example/"
        )


def test_cancellation_interrupts_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    calls = {"requests": 0, "sleeps": 0}

    def _fail(request: Any, timeout: float = 0.0) -> Any:
        calls["requests"] += 1
        raise urllib.error.URLError("temporary")

    monkeypatch.setattr("urllib.request.urlopen", _fail)
    monkeypatch.setattr(
        "time.sleep", lambda seconds: calls.__setitem__("sleeps", calls["sleeps"] + 1)
    )

    with pytest.raises(HttpRequestError, match="cancelled"):
        UrllibHttpClient(
            retries=3,
            backoff=1.0,
            cancellation=_CancelAfterChecks(2),
        ).get("https://olympusdemocorp.example/")

    assert calls["requests"] == 1
    assert calls["sleeps"] <= 1


def test_network_error_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    def _raise(request: Any, timeout: float = 0.0) -> Any:
        raise urllib.error.URLError("boom")

    monkeypatch.setattr("urllib.request.urlopen", _raise)
    with pytest.raises(HttpRequestError, match="HTTP GET failed"):
        UrllibHttpClient().get("https://olympusdemocorp.example/")


def test_rejects_non_http_scheme() -> None:
    with pytest.raises(HttpRequestError, match="non-HTTP"):
        UrllibHttpClient().get("file:///etc/passwd")


def test_retries_on_network_error_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    calls = {"n": 0}
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    def _flaky(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("temporary")
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _flaky)
    response = UrllibHttpClient(retries=2).get("https://olympusdemocorp.example/")
    assert response.status_code == 200
    assert calls["n"] == 3  # two failures then success


def test_raises_after_exhausting_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    import urllib.error

    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    def _always_fail(request: Any, timeout: float = 0.0) -> Any:
        raise urllib.error.URLError("down")

    monkeypatch.setattr("urllib.request.urlopen", _always_fail)
    with pytest.raises(HttpRequestError, match="HTTP GET failed"):
        UrllibHttpClient(retries=1).get("https://olympusdemocorp.example/")


def test_backoff_is_capped_and_optionally_jittered(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retries must not stampede: the wait is capped and can be spread out."""
    import urllib.error

    slept: list[float] = []
    monkeypatch.setattr("time.sleep", lambda seconds: slept.append(seconds))

    def _fail(request: Any, timeout: float = 0.0) -> Any:
        del request, timeout
        raise urllib.error.URLError("temporary")

    monkeypatch.setattr("urllib.request.urlopen", _fail)

    with pytest.raises(HttpRequestError):
        UrllibHttpClient(timeout=1.0, retries=3, backoff=1.0).get(
            "https://olympusdemocorp.example/"
        )
    # Exponential and unjittered: the slices sum to 1, 2 and 4 seconds.
    assert sum(slept) == pytest.approx(7.0)

    slept.clear()
    with pytest.raises(HttpRequestError):
        UrllibHttpClient(timeout=1.0, retries=3, backoff=1.0, jitter=0.5).get(
            "https://olympusdemocorp.example/"
        )
    # Each of the three waits lands inside its own +/-50% band: [0.5,1.5],
    # [1,3] and [2,6], so the total stays strictly inside (3.5, 10.5).
    assert 3.5 <= sum(slept) <= 10.5


def test_jitter_outside_zero_to_one_is_refused() -> None:
    with pytest.raises(ExecutionPolicyError, match="jitter_ratio"):
        UrllibHttpClient(jitter=2.0)


def test_overall_deadline_caps_retries_backoff_and_request_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import urllib.error

    clock = [0.0]
    observed_timeouts: list[float] = []
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    monkeypatch.setattr("time.sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    def _fail(request: Any, timeout: float = 0.0) -> Any:
        observed_timeouts.append(timeout)
        raise urllib.error.URLError("temporary")

    monkeypatch.setattr("urllib.request.urlopen", _fail)
    with pytest.raises(HttpRequestError, match="deadline exceeded"):
        UrllibHttpClient(
            timeout=10.0,
            retries=5,
            backoff=0.2,
            deadline_seconds=0.25,
        ).get("https://olympusdemocorp.example/")

    assert len(observed_timeouts) == 2
    assert observed_timeouts[0] == pytest.approx(0.25)
    assert observed_timeouts[1] == pytest.approx(0.05)


def test_retries_on_retryable_status(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    def _rate_limited(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeHttpResponse(429, {}, b"slow down")
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _rate_limited)
    response = UrllibHttpClient(retries=2).get("https://olympusdemocorp.example/")
    assert response.status_code == 200
    assert calls["n"] == 2


def test_returns_last_response_when_retries_exhausted_on_5xx(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda request, timeout=0.0: _FakeHttpResponse(503, {}, b"busy")
    )
    response = UrllibHttpClient(retries=1).get("https://olympusdemocorp.example/")
    assert response.status_code == 503  # handed back, not raised


def test_rate_limit_sleeps_between_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", lambda seconds: slept.append(seconds))
    times = iter([0.0, 0.0, 0.0, 0.1])  # monotonic() readings
    monkeypatch.setattr("time.monotonic", lambda: next(times, 0.1))
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda request, timeout=0.0: _FakeHttpResponse(200, {}, b"ok")
    )
    client = UrllibHttpClient(min_interval=1.0)
    client.get("https://olympusdemocorp.example/a")
    client.get("https://olympusdemocorp.example/b")
    assert any(s > 0 for s in slept)  # throttled the second request


def test_http_client_builds_from_shared_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, float] = {}

    def _capture(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        observed["timeout"] = timeout
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr("urllib.request.urlopen", _capture)
    policy = ExecutionPolicy(
        authorized=True,
        timeout_seconds=3.0,
        deadline_seconds=10.0,
        retries=1,
    )

    UrllibHttpClient.from_policy(policy).get("https://olympusdemocorp.example/")

    assert observed["timeout"] == 3.0


def test_http_client_refuses_invalid_limits_and_observes_cancellation() -> None:
    with pytest.raises(ExecutionPolicyError):
        UrllibHttpClient(timeout=0)

    token = CancellationToken()
    token.cancel()
    with pytest.raises(HttpRequestError, match="cancelled"):
        UrllibHttpClient(cancellation=token).get("https://olympusdemocorp.example/")


def test_request_asks_servers_not_to_compress(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    def fake_urlopen(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        seen.update(request.headers)
        return _FakeHttpResponse(200, {}, b"ok")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    UrllibHttpClient().get("https://example.test/")

    assert seen["Accept-encoding"] == DEFAULT_ACCEPT_ENCODING


def test_gzip_response_is_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    body = gzip.compress(b"decoded payload")

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda request, timeout=0.0: _FakeHttpResponse(
            200, {"Content-Encoding": "gzip"}, body
        ),
    )

    assert UrllibHttpClient().get("https://example.test/").body == "decoded payload"


def test_decompression_bomb_is_refused_and_not_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bomb = gzip.compress(b"\0" * (64 * 1024 * 1024))
    attempts = 0

    def fake_urlopen(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        nonlocal attempts
        attempts += 1
        return _FakeHttpResponse(200, {"Content-Encoding": "gzip"}, bomb)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(HttpResponseUndecodable):
        UrllibHttpClient(retries=2).get("https://example.test/")
    assert attempts == 1


def test_unsupported_content_encoding_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda request, timeout=0.0: _FakeHttpResponse(
            200, {"Content-Encoding": "br"}, b"\x00opaque"
        ),
    )

    with pytest.raises(HttpResponseUndecodable, match="could not be safely decoded"):
        UrllibHttpClient().get("https://example.test/")


def test_error_response_bodies_are_decoded_under_the_same_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = urllib.error.HTTPError(
        "https://example.test/",
        404,
        "Not Found",
        {"Content-Encoding": "gzip"},  # type: ignore[arg-type]
        io.BytesIO(gzip.compress(b"missing")),
    )

    def fake_urlopen(request: Any, timeout: float = 0.0) -> _FakeHttpResponse:
        raise error

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    response = UrllibHttpClient().get("https://example.test/")

    assert (response.status_code, response.body) == (404, "missing")


def test_decompression_limits_are_validated() -> None:
    with pytest.raises(ValueError, match="max_decompressed_bytes"):
        UrllibHttpClient(max_decompressed_bytes=0)
    with pytest.raises(ValueError, match="max_expansion_ratio"):
        UrllibHttpClient(max_expansion_ratio=0.5)


def test_pinned_opener_never_uses_an_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pinned client must not proxy any scheme: a proxy re-resolves the host,

    which defeats pinning (regression for the plain-HTTP proxy gap — HTTPS CONNECT
    tunnels were already refused, but a default ProxyHandler would silently proxy
    a plain-HTTP pinned request).
    """
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    client = UrllibHttpClient(10.0, address_policy=lambda host: ("203.0.113.9",))
    assert client._opener is not None
    active_proxies = [
        handler
        for handler in client._opener.handlers
        if type(handler).__name__ == "ProxyHandler" and getattr(handler, "proxies", {})
    ]
    assert active_proxies == [], "pinned opener must carry no environment proxy"


def test_unpinned_opener_still_honours_environment_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only pinned openers disable proxying; a redirect-only client is unaffected."""
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    client = UrllibHttpClient(10.0, redirect_validator=lambda _url: None)
    assert client._opener is not None
    proxy_handlers = [
        handler
        for handler in client._opener.handlers
        if type(handler).__name__ == "ProxyHandler" and getattr(handler, "proxies", {})
    ]
    assert proxy_handlers, "a non-pinned opener should keep the environment proxy"
