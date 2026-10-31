"""Tests for the pluggable ``SecretProvider`` (ROADMAP ``SEC-D``).

Pin the invariants: a resolved secret is a masked :class:`SecretStr`, the
environment is a live fallback (empty/whitespace is unset), an optional backend
that is not installed fails loudly rather than silently, and a chain returns the
first hit. No real keyring or network is touched.
"""

from __future__ import annotations

import sys
import types

import pytest
from pydantic import SecretStr

from olympus.core.secrets import (
    ChainSecretProvider,
    EnvSecretProvider,
    KeyringSecretProvider,
    SecretProviderUnavailable,
    default_secret_provider,
    resolve_secret,
)


def test_env_provider_reads_live_environment_and_masks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_TEST_SECRET", "s3cr3t")
    secret = EnvSecretProvider().get_secret("OLYMPUS_TEST_SECRET")
    assert isinstance(secret, SecretStr)
    assert secret.get_secret_value() == "s3cr3t"
    # The raw value never appears in the masked representation.
    assert "s3cr3t" not in repr(secret) and "s3cr3t" not in str(secret)


@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_env_provider_treats_empty_or_blank_as_unset(raw: str) -> None:
    provider = EnvSecretProvider(environ={"K": raw})
    assert provider.get_secret("K") is None


def test_env_provider_returns_none_for_missing_key() -> None:
    assert EnvSecretProvider(environ={}).get_secret("ABSENT") is None


def test_injected_environ_is_used_instead_of_process_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("K", "from-process")
    assert EnvSecretProvider(environ={"K": "injected"}).get_secret("K") == SecretStr("injected")


def test_resolve_secret_defaults_to_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_TEST_SECRET", "abc")
    assert resolve_secret("OLYMPUS_TEST_SECRET") == SecretStr("abc")
    monkeypatch.delenv("OLYMPUS_TEST_SECRET", raising=False)
    assert resolve_secret("OLYMPUS_TEST_SECRET") is None


def test_default_secret_provider_is_environment() -> None:
    assert isinstance(default_secret_provider(), EnvSecretProvider)


def test_chain_returns_first_hit_then_falls_through() -> None:
    empty = EnvSecretProvider(environ={})
    first = EnvSecretProvider(environ={"K": "one"})
    second = EnvSecretProvider(environ={"K": "two"})
    assert ChainSecretProvider((empty, first, second)).get_secret("K") == SecretStr("one")
    assert ChainSecretProvider((empty, empty)).get_secret("K") is None


def test_keyring_provider_unavailable_without_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force ``import keyring`` to fail even if it is installed in the environment.
    monkeypatch.setitem(sys.modules, "keyring", None)
    with pytest.raises(SecretProviderUnavailable, match="keyring"):
        KeyringSecretProvider()


def test_keyring_provider_reads_from_injected_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    def get_password(service: str, name: str) -> str | None:
        calls.append((service, name))
        return "from-keyring" if name == "TOKEN" else None

    fake = types.ModuleType("keyring")
    fake.get_password = get_password  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", fake)

    provider = KeyringSecretProvider(service="olympus")
    assert provider.get_secret("TOKEN") == SecretStr("from-keyring")
    assert provider.get_secret("ABSENT") is None
    assert calls == [("olympus", "TOKEN"), ("olympus", "ABSENT")]
