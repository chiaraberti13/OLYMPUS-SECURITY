"""Unit tests for Argus phone enrichment adapters (network is faked)."""

from __future__ import annotations

import json

import pytest

from olympus.argus.enrichment import (
    EnrichmentError,
    HudsonRockBreachClient,
    NumverifyClient,
    RapidApiMessagingClient,
)
from olympus.core.http import HttpRequestError, HttpResponse


class _FakeClient:
    """Offline HttpClient double returning a preconfigured response or error."""

    def __init__(self, *, body: str = "", error: bool = False, status: int = 200) -> None:
        self._body = body
        self._error = error
        self._status = status
        self.calls: list[str] = []

    def get(self, url: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        self.calls.append(url)
        if self._error:
            raise HttpRequestError("boom")
        return HttpResponse(status_code=self._status, headers={}, body=self._body)


def test_numverify_dormant_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLYMPUS_NUMVERIFY_KEY", raising=False)
    assert NumverifyClient.from_env(_FakeClient()) is None


def test_numverify_active_with_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_NUMVERIFY_KEY", "secret")
    client = _FakeClient(body=json.dumps({"carrier": "Demo Mobile", "line_type": "mobile"}))
    adapter = NumverifyClient.from_env(client)
    assert adapter is not None
    result = adapter.enrich("+16505550123")
    assert result.carrier == "Demo Mobile"
    assert result.line_type == "mobile"
    assert client.calls[0].startswith("https://")
    assert "access_key=secret" in client.calls[0]


def test_numverify_key_resolved_via_injected_secret_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No environment variable set: the key comes from the injected provider,
    # proving the SecretProvider seam (ROADMAP SEC-D) is the single lookup point.
    monkeypatch.delenv("OLYMPUS_NUMVERIFY_KEY", raising=False)
    from olympus.core.secrets import EnvSecretProvider

    provider = EnvSecretProvider(environ={"OLYMPUS_NUMVERIFY_KEY": "from-provider"})
    client = _FakeClient(body=json.dumps({"carrier": "Demo", "line_type": "mobile"}))
    adapter = NumverifyClient.from_env(client, secrets=provider)
    assert adapter is not None
    adapter.enrich("+16505550123")
    assert "access_key=from-provider" in client.calls[0]


def test_numverify_network_error_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_NUMVERIFY_KEY", "secret")
    adapter = NumverifyClient.from_env(_FakeClient(error=True))
    assert adapter is not None
    with pytest.raises(EnrichmentError, match="numverify request failed") as error:
        adapter.enrich("+16505550123")
    assert "secret" not in str(error.value)


def test_numverify_non_success_status_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_NUMVERIFY_KEY", "secret")
    adapter = NumverifyClient.from_env(_FakeClient(body="{}", status=401))
    assert adapter is not None

    with pytest.raises(EnrichmentError, match="HTTP 401"):
        adapter.enrich("+16505550123")


def test_numverify_bad_json_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_NUMVERIFY_KEY", "secret")
    adapter = NumverifyClient.from_env(_FakeClient(body="<html>not json</html>"))
    assert adapter is not None
    with pytest.raises(EnrichmentError, match="non-JSON"):
        adapter.enrich("+16505550123")


def test_breach_client_counts_stealers() -> None:
    body = json.dumps({"stealers": [{"stealer_family": "Redline"}, {"stealer_family": "Raccoon"}]})
    result = HudsonRockBreachClient(_FakeClient(body=body)).enrich("+16505550123")
    assert result.breach_count == 2
    assert result.breach_sources == ("Redline", "Raccoon")


def test_breach_client_falls_back_to_total() -> None:
    result = HudsonRockBreachClient(_FakeClient(body=json.dumps({"total": 5}))).enrich("+1650")
    assert result.breach_count == 5
    assert result.breach_sources == ()


def test_breach_client_wraps_network_error() -> None:
    with pytest.raises(EnrichmentError, match="breach-intel request failed"):
        HudsonRockBreachClient(_FakeClient(error=True)).enrich("+16505550123")


def test_breach_client_endpoint_is_injectable() -> None:
    client = _FakeClient(body=json.dumps({"total": 0}))
    HudsonRockBreachClient(client, endpoint="https://example.test/breach").enrich("+1650")
    assert client.calls[0].startswith("https://example.test/breach?phone=")


def test_messaging_dormant_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OLYMPUS_RAPIDAPI_KEY", raising=False)
    assert RapidApiMessagingClient.from_env(_FakeClient()) is None


def test_messaging_reports_presence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_RAPIDAPI_KEY", "secret")
    body = json.dumps({"exists": True, "has_photo": True, "is_business": False})
    adapter = RapidApiMessagingClient.from_env(_FakeClient(body=body))
    assert adapter is not None
    presence = adapter.lookup("+16505550123")
    assert presence.registered is True
    assert presence.has_public_photo is True
    assert presence.platform == "whatsapp"


def test_messaging_bad_payload_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_RAPIDAPI_KEY", "secret")
    adapter = RapidApiMessagingClient.from_env(_FakeClient(body="[]"))
    assert adapter is not None
    with pytest.raises(EnrichmentError, match="unexpected payload"):
        adapter.lookup("+16505550123")
