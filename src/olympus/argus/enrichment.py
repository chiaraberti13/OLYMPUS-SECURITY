"""Optional, opt-in phone enrichment: real third-party lookups.

The offline core (:mod:`olympus.argus.phone`) never leaves the machine. This
module adds the *practical*, network-backed half an ethical-hacking workflow
needs — carrier validation, breach intelligence, messaging-platform presence
— behind clear protocols so tests inject offline doubles.

Safety model:
- Every real adapter talks to the injectable :class:`~olympus.core.http.HttpClient`.
- Key-gated adapters expose ``from_env(...)`` which returns ``None`` when the
  API key is absent, so the feature is *dormant by default* (no key in the
  repo, nothing fires unless an operator opts in with their own credentials).
- The CLI additionally requires an explicit authorization flag before any of
  these run against a real number.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote, urlencode

from olympus.core.http import HttpClient, HttpRequestError
from olympus.core.secrets import SecretProvider, resolve_secret


class EnrichmentError(RuntimeError):
    """Raised when a real enrichment lookup fails (network, auth, bad payload)."""


@dataclass(frozen=True)
class PhoneEnrichment:
    """Enrichment layered on top of the offline report."""

    carrier: str = ""
    line_type: str = ""
    breach_count: int = 0
    breach_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class MessagingPresence:
    """Presence and public metadata of a number on a messaging platform."""

    platform: str
    registered: bool
    has_public_photo: bool = False
    is_business: bool = False


class PhoneEnrichmentClient(Protocol):
    """Anything able to enrich an E.164 number with carrier/breach data."""

    def enrich(self, e164: str) -> PhoneEnrichment:
        """Return enrichment for ``e164`` (raises :class:`EnrichmentError` on failure)."""
        ...


class MessagingPresenceClient(Protocol):
    """Anything able to report a number's presence on a messaging platform."""

    def lookup(self, e164: str) -> MessagingPresence:
        """Return messaging presence for ``e164`` (raises :class:`EnrichmentError`)."""
        ...


class NumverifyClient:
    """Real, key-gated carrier/line-type validation via the Numverify API.

    Dormant unless ``OLYMPUS_NUMVERIFY_KEY`` is set: :meth:`from_env` returns
    ``None`` when the key is absent, so nothing ever calls out by default.
    """

    _ENDPOINT = "https://apilayer.net/api/validate"

    def __init__(self, api_key: str, client: HttpClient) -> None:
        self._api_key = api_key
        self._client = client

    @classmethod
    def from_env(
        cls, client: HttpClient, *, secrets: SecretProvider | None = None
    ) -> NumverifyClient | None:
        """Build from ``OLYMPUS_NUMVERIFY_KEY`` via ``secrets``, or ``None`` if unset.

        The key is resolved through a :class:`SecretProvider` (default: the
        environment fallback), so a deployment can source it from a keyring or
        external secret manager without changing this call site.
        """
        secret = resolve_secret("OLYMPUS_NUMVERIFY_KEY", provider=secrets)
        return cls(secret.get_secret_value(), client) if secret is not None else None

    def enrich(self, e164: str) -> PhoneEnrichment:
        """Validate ``e164`` and return carrier/line-type (no breach data)."""
        query = urlencode({"access_key": self._api_key, "number": e164})
        try:
            response = self._client.get(f"{self._ENDPOINT}?{query}")
        except HttpRequestError as exc:
            # The request URL contains the API key. Never reflect the transport
            # exception because it may embed that URL in logs or CLI output.
            raise EnrichmentError("numverify request failed") from exc
        if response.status_code != 200:
            raise EnrichmentError(f"numverify returned HTTP {response.status_code}")
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError as exc:
            raise EnrichmentError(f"numverify returned non-JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise EnrichmentError("numverify returned an unexpected payload")
        return PhoneEnrichment(
            carrier=str(data.get("carrier", "")),
            line_type=str(data.get("line_type", "")),
        )


class HudsonRockBreachClient:
    """Real, keyless breach-intelligence lookup (Hudson Rock Cavalier OSINT API).

    Works without an API key, so it is a genuinely usable tool out of the box;
    it is still gated behind scope + explicit authorization at the CLI layer.
    The endpoint is injectable to keep the adapter honest and testable.
    """

    _ENDPOINT = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-phone"

    def __init__(self, client: HttpClient, endpoint: str | None = None) -> None:
        self._client = client
        self._endpoint = endpoint or self._ENDPOINT

    def enrich(self, e164: str) -> PhoneEnrichment:
        """Return breach exposure counts for ``e164`` (best-effort parsing)."""
        try:
            response = self._client.get(f"{self._endpoint}?phone={quote(e164)}")
        except HttpRequestError as exc:
            raise EnrichmentError(f"breach-intel request failed: {exc}") from exc
        if response.status_code != 200:
            raise EnrichmentError(f"breach-intel returned HTTP {response.status_code}")
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError as exc:
            raise EnrichmentError(f"breach-intel returned non-JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise EnrichmentError("breach-intel returned an unexpected payload")

        stealers = data.get("stealers")
        count = len(stealers) if isinstance(stealers, list) else int(data.get("total", 0) or 0)
        sources: tuple[str, ...] = ()
        if isinstance(stealers, list):
            sources = tuple(
                str(item.get("stealer_family", "unknown"))
                for item in stealers
                if isinstance(item, dict)
            )
        return PhoneEnrichment(breach_count=count, breach_sources=sources)


class RapidApiMessagingClient:
    """Real, key-gated messaging-presence lookup (WhatsApp OSINT via RapidAPI).

    Dormant unless ``OLYMPUS_RAPIDAPI_KEY`` is set. Returns only presence and
    coarse public metadata — never message content — for authorized social
    -engineering risk assessment.
    """

    _HOST = "whatsapp-osint.p.rapidapi.com"
    _ENDPOINT = "https://whatsapp-osint.p.rapidapi.com/wa/check"

    def __init__(self, api_key: str, client: HttpClient) -> None:
        self._api_key = api_key
        self._client = client

    @classmethod
    def from_env(
        cls, client: HttpClient, *, secrets: SecretProvider | None = None
    ) -> RapidApiMessagingClient | None:
        """Build from ``OLYMPUS_RAPIDAPI_KEY`` via ``secrets``, or ``None`` if unset."""
        secret = resolve_secret("OLYMPUS_RAPIDAPI_KEY", provider=secrets)
        return cls(secret.get_secret_value(), client) if secret is not None else None

    def lookup(self, e164: str) -> MessagingPresence:
        """Return messaging presence for ``e164`` (best-effort parsing)."""
        headers = {"X-RapidAPI-Key": self._api_key, "X-RapidAPI-Host": self._HOST}
        try:
            response = self._client.get(f"{self._ENDPOINT}?phone={quote(e164)}", headers=headers)
        except HttpRequestError as exc:
            raise EnrichmentError(f"messaging request failed: {exc}") from exc
        if response.status_code != 200:
            raise EnrichmentError(f"messaging lookup returned HTTP {response.status_code}")
        try:
            data = json.loads(response.body)
        except json.JSONDecodeError as exc:
            raise EnrichmentError(f"messaging lookup returned non-JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise EnrichmentError("messaging lookup returned an unexpected payload")
        return MessagingPresence(
            platform="whatsapp",
            registered=bool(data.get("exists", data.get("registered", False))),
            has_public_photo=bool(data.get("has_photo", data.get("profile_pic", False))),
            is_business=bool(data.get("is_business", False)),
        )
