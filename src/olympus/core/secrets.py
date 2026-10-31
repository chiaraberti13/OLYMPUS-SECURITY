"""Pluggable secret resolution — the ``SecretProvider`` port (ROADMAP ``SEC-D``).

Runtime secrets (OSINT API keys, service tokens, ledger keys) are scattered
across the platform as direct ``os.environ`` reads. This module makes the lookup
a single, injectable seam so a deployment can keep using environment variables
as a **local fallback** or plug in a stronger backend (OS keyring, external
secret manager) without touching call sites.

Design rules that protect the secret:

* A resolved value is a :class:`pydantic.SecretStr`, so it is masked in ``repr``,
  logs and tracebacks and is only unwrapped (``.get_secret_value()``) at the exact
  point of use — keeping it a ``SecretStr`` *as long as possible*.
* Environment variables are a fallback, never an autoloaded ``.env``: this module
  reads the live process environment and nothing else.
* Optional backends are isolated imports: core never hard-depends on ``keyring``;
  constructing a backend that is not installed raises
  :class:`SecretProviderUnavailable` with an actionable message.

The provider is a :class:`typing.Protocol`, so a test wires an in-memory double
and production wires :class:`EnvSecretProvider` (or a :class:`ChainSecretProvider`
of several). Rotation, OIDC/mTLS and keyring packaging remain tracked in
[``ROADMAP.md``] under ``SEC-D``.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from pydantic import SecretStr


class SecretProviderError(RuntimeError):
    """Base error for secret resolution."""


class SecretProviderUnavailable(SecretProviderError):
    """Raised when an optional backend (e.g. ``keyring``) is not installed."""


class SecretProvider(Protocol):
    """A source of named runtime secrets."""

    def get_secret(self, name: str) -> SecretStr | None:
        """Return the secret named ``name``, or ``None`` when it is not set."""
        ...


@dataclass(frozen=True)
class EnvSecretProvider:
    """Resolve secrets from environment variables (the local fallback).

    Reads the live process environment by default; a fixed ``environ`` mapping can
    be injected for deterministic tests. A missing, empty or whitespace-only value
    is treated as unset, matching the existing ``os.environ.get(name, "").strip()``
    convention across the codebase. No ``.env`` file is ever loaded.
    """

    environ: Mapping[str, str] | None = None

    def get_secret(self, name: str) -> SecretStr | None:
        source = os.environ if self.environ is None else self.environ
        value = source.get(name, "").strip()
        return SecretStr(value) if value else None


@dataclass(frozen=True)
class KeyringSecretProvider:
    """Resolve secrets from the OS keyring (optional backend).

    The ``keyring`` import is isolated: constructing this provider without the
    package installed raises :class:`SecretProviderUnavailable`, so core keeps
    working with the environment fallback and nothing hard-depends on ``keyring``.
    """

    service: str = "olympus"

    def __post_init__(self) -> None:
        try:
            import keyring  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised via sys.modules double
            raise SecretProviderUnavailable(
                "keyring backend not installed; install it to use KeyringSecretProvider"
            ) from exc

    def get_secret(self, name: str) -> SecretStr | None:
        import keyring

        value = keyring.get_password(self.service, name)
        return SecretStr(value) if value else None


@dataclass(frozen=True)
class ChainSecretProvider:
    """Try each provider in order and return the first secret found."""

    providers: tuple[SecretProvider, ...]

    def get_secret(self, name: str) -> SecretStr | None:
        for provider in self.providers:
            secret = provider.get_secret(name)
            if secret is not None:
                return secret
        return None


def default_secret_provider() -> SecretProvider:
    """Return the default provider: environment variables only (local fallback)."""
    return EnvSecretProvider()


def resolve_secret(name: str, *, provider: SecretProvider | None = None) -> SecretStr | None:
    """Resolve one secret via ``provider`` (default: the environment fallback)."""
    return (provider or default_secret_provider()).get_secret(name)


__all__ = [
    "ChainSecretProvider",
    "EnvSecretProvider",
    "KeyringSecretProvider",
    "SecretProvider",
    "SecretProviderError",
    "SecretProviderUnavailable",
    "default_secret_provider",
    "resolve_secret",
]
