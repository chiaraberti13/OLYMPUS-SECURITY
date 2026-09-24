"""Editable execution bounds and lab scope, resolved from a single TOML file.

Until now the operational limits of every bounded operation were constants in
:mod:`olympus.core.execution` (``MAX_TIMEOUT_SECONDS`` and friends). Changing a
timeout for one engagement meant editing code. This module makes those numbers
**data**: an operator writes one ``olympus.policy.toml`` and re-runs.

What does *not* change is the safety story. The constants in
:mod:`olympus.core.execution` stop being the values and become the **ceilings**:
a policy file may lower a bound, never raise it above the compiled-in maximum.
A file that tries is rejected at load time, not silently clamped, so an operator
never believes a limit is in force when it is not.

Resolution order, highest priority first::

    1. an explicit caller/CLI override   (``resolve_execution_policy(timeout_seconds=...)``)
    2. ``OLYMPUS_POLICY_<KEY>`` environment variables
    3. the selected profile in the policy file  (``[bounds.<profile>]``)
    4. the ``[bounds.default]`` table in the policy file
    5. the built-in :class:`~olympus.core.execution.ExecutionPolicy` defaults

The file itself is selected from ``OLYMPUS_POLICY``, then ``./olympus.policy.toml``,
then ``~/.olympus/policy.toml``. With no file present every value falls back to
the built-in defaults, so an installation that never writes one behaves exactly
as before.

A named profile is an **overlay** on ``[bounds.default]``, not a replacement::

    [bounds.default]
    timeout_seconds = 10
    max_concurrency = 4

    [bounds.aggressive]      # inherits timeout_seconds = 10
    max_concurrency = 16

The ``[lab]`` table is the one place that *widens* what Olympus may reach: it
declares private ranges the operator owns, which the SSRF guard would otherwise
refuse. Enabling it therefore requires ``activated_by`` and ``activated_at`` —
who took the decision and when — and produces a signed activation record (see
:func:`lab_activation_record`).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import tomllib
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from olympus.core.execution import (
    MAX_BACKOFF_SECONDS,
    MAX_CONCURRENCY,
    MAX_DEADLINE_SECONDS,
    MAX_JITTER_RATIO,
    MAX_MIN_INTERVAL_SECONDS,
    MAX_RETRIES,
    MAX_TIMEOUT_SECONDS,
    ExecutionPolicy,
)

#: Contract version of the policy document. Bumped on any incompatible change.
POLICY_SCHEMA_VERSION = "1.0.0"
POLICY_SCHEMA_NAME = "olympus.policy"

#: Environment variable naming the policy file, and the discovery fallbacks.
POLICY_PATH_VARIABLE = "OLYMPUS_POLICY"
PROJECT_POLICY_FILE = "olympus.policy.toml"
USER_POLICY_FILE = Path(".olympus") / "policy.toml"

#: Prefix of the per-bound environment overrides, e.g. ``OLYMPUS_POLICY_TIMEOUT_SECONDS``.
ENVIRONMENT_PREFIX = "OLYMPUS_POLICY_"

#: Optional HMAC key used to sign the lab activation record.
LAB_SIGNING_KEY_VARIABLE = "OLYMPUS_POLICY_LAB_KEY"

DEFAULT_PROFILE = "default"

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: The only ranges a lab profile may declare. Checking ``is_global`` is not
#: enough: ``169.254.169.254/32`` — the cloud instance-metadata endpoint, the
#: single most valuable SSRF target there is — reports ``is_global = False`` and
#: would sail through such a check. Link-local and loopback are therefore
#: excluded on purpose: a lab lives on routed private space, and "reach the
#: metadata service" or "reach a service on this host" is not what an operator
#: means by "the range I own".
LAB_ELIGIBLE_RANGES: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),  # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),  # RFC 6598 carrier-grade NAT
    ipaddress.ip_network("198.18.0.0/15"),  # RFC 2544 benchmarking
    ipaddress.ip_network("192.0.2.0/24"),  # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # RFC 5737 TEST-NET-3
    ipaddress.ip_network("fc00::/7"),  # RFC 4193 unique local
    ipaddress.ip_network("2001:db8::/32"),  # RFC 3849 documentation
)

#: The compiled-in ceiling for every bound. A policy file may only go lower.
#: Integer bounds keep an integer ceiling so ``policy show`` does not print
#: ``max_concurrency: 64.0`` for a value that can only ever be a whole number.
BOUND_CEILINGS: dict[str, float] = {
    "timeout_seconds": MAX_TIMEOUT_SECONDS,
    "deadline_seconds": MAX_DEADLINE_SECONDS,
    "max_concurrency": MAX_CONCURRENCY,
    "retries": MAX_RETRIES,
    "backoff_seconds": MAX_BACKOFF_SECONDS,
    "min_interval_seconds": MAX_MIN_INTERVAL_SECONDS,
    "jitter_ratio": MAX_JITTER_RATIO,
}

#: The floor for every bound, mirroring ``ExecutionPolicy.__post_init__``.
BOUND_FLOORS: dict[str, float] = {
    "timeout_seconds": 0.05,
    "deadline_seconds": 0.05,
    "max_concurrency": 1,
    "retries": 0,
    "backoff_seconds": 0.0,
    "min_interval_seconds": 0.0,
    "jitter_ratio": 0.0,
}

#: The built-in default for every bound, taken from ``ExecutionPolicy`` itself so
#: the two cannot drift apart.
_BUILTIN_DEFAULTS: dict[str, float | int] = {
    "timeout_seconds": ExecutionPolicy().timeout_seconds,
    "deadline_seconds": ExecutionPolicy().deadline_seconds,
    "max_concurrency": ExecutionPolicy().max_concurrency,
    "retries": ExecutionPolicy().retries,
    "backoff_seconds": ExecutionPolicy().backoff_seconds,
    "min_interval_seconds": ExecutionPolicy().min_interval_seconds,
    "jitter_ratio": ExecutionPolicy().jitter_ratio,
}

_INTEGER_BOUNDS = frozenset({"max_concurrency", "retries"})


class PolicyError(RuntimeError):
    """Raised when a policy document is missing, unreadable, or unsafe."""


class BoundsProfile(BaseModel):
    """One overlay of execution bounds; every unset field inherits.

    All fields are optional on purpose. ``[bounds.default]`` overlays the
    built-in defaults, and a named profile overlays ``[bounds.default]``, so an
    operator writes only the numbers that differ.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    timeout_seconds: float | None = Field(
        default=None, ge=BOUND_FLOORS["timeout_seconds"], le=MAX_TIMEOUT_SECONDS
    )
    deadline_seconds: float | None = Field(
        default=None, ge=BOUND_FLOORS["deadline_seconds"], le=MAX_DEADLINE_SECONDS
    )
    max_concurrency: int | None = Field(default=None, ge=1, le=MAX_CONCURRENCY)
    retries: int | None = Field(default=None, ge=0, le=MAX_RETRIES)
    backoff_seconds: float | None = Field(default=None, ge=0.0, le=MAX_BACKOFF_SECONDS)
    min_interval_seconds: float | None = Field(default=None, ge=0.0, le=MAX_MIN_INTERVAL_SECONDS)
    jitter_ratio: float | None = Field(default=None, ge=0.0, le=MAX_JITTER_RATIO)

    def overlay(self, base: dict[str, Any]) -> dict[str, Any]:
        """Return ``base`` with this profile's explicitly set fields applied."""
        merged = dict(base)
        for key, value in self.model_dump(exclude_none=True).items():
            merged[key] = value
        return merged


class ScopeDomains(BaseModel):
    """Declared domain scope. Advisory here; each module owns its own gate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: tuple[str, ...] = ()
    excluded: tuple[str, ...] = ()

    @field_validator("allowed", "excluded", mode="after")
    @classmethod
    def _reject_blank(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for entry in value:
            if not entry.strip():
                raise ValueError("domain entries must not be blank")
        return tuple(entry.strip().lower() for entry in value)


class PolicyScope(BaseModel):
    """The ``[scope]`` table of the policy document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    domains: ScopeDomains = ScopeDomains()


class LabProfile(BaseModel):
    """Operator-declared private ranges the SSRF guard may reach.

    This is the only setting in the document that *widens* Olympus' reach, so it
    is deliberately noisy: enabling it without naming who enabled it, and when,
    is a validation error rather than a default.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = False
    allowed_networks: tuple[str, ...] = ()
    activated_by: str | None = None
    activated_at: datetime | None = None

    @field_validator("allowed_networks", mode="after")
    @classmethod
    def _parse_networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for entry in value:
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(f"{entry!r} is not a valid CIDR network") from exc
            # An allowlist that may name anything is not an allowlist. The lab
            # exists to reach routed private space the operator owns, so the
            # entry has to sit wholly inside one eligible range — a default
            # route, a public block, or the metadata endpoint never qualifies.
            if not any(
                network.version == eligible.version and network.subnet_of(eligible)  # type: ignore[arg-type]
                for eligible in LAB_ELIGIBLE_RANGES
            ):
                raise ValueError(
                    f"{entry!r} is not an eligible lab range; the lab allowlist accepts "
                    "only private/documentation space you declare you own "
                    f"({', '.join(str(net) for net in LAB_ELIGIBLE_RANGES)}), "
                    "never public, loopback or link-local addresses"
                )
            normalized.append(str(network))
        return tuple(normalized)

    def model_post_init(self, _context: object) -> None:
        if not self.enabled:
            return
        if not self.allowed_networks:
            raise ValueError("[lab].enabled requires at least one entry in allowed_networks")
        if not (self.activated_by or "").strip():
            raise ValueError("[lab].enabled requires activated_by (who authorized the lab)")
        if self.activated_at is None:
            raise ValueError("[lab].enabled requires activated_at (when the lab was authorized)")

    def networks(self) -> tuple[IPNetwork, ...]:
        """Return the parsed networks, or an empty tuple when the lab is off."""
        if not self.enabled:
            return ()
        return tuple(ipaddress.ip_network(entry, strict=False) for entry in self.allowed_networks)


class PolicyRuleset(BaseModel):
    """The whole, versioned policy document."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = POLICY_SCHEMA_VERSION
    engagement: str | None = None
    bounds: dict[str, BoundsProfile] = Field(default_factory=dict)
    scope: PolicyScope = PolicyScope()
    lab: LabProfile = LabProfile()

    @field_validator("schema_version", mode="after")
    @classmethod
    def _supported_version(cls, value: str) -> str:
        major = value.split(".", 1)[0]
        if major != POLICY_SCHEMA_VERSION.split(".", 1)[0]:
            raise ValueError(
                f"unsupported schema_version {value!r}; this build understands "
                f"{POLICY_SCHEMA_VERSION.split('.', 1)[0]}.x"
            )
        return value

    @field_validator("bounds", mode="after")
    @classmethod
    def _named_profiles(cls, value: dict[str, BoundsProfile]) -> dict[str, BoundsProfile]:
        for name in value:
            if not name.replace("-", "").replace("_", "").isalnum():
                raise ValueError(f"invalid profile name {name!r}")
        return value

    def profile_names(self) -> tuple[str, ...]:
        """Return every selectable profile name, ``default`` always included."""
        return tuple(sorted({DEFAULT_PROFILE, *self.bounds}))

    def bounds_for(self, profile: str = DEFAULT_PROFILE) -> dict[str, Any]:
        """Resolve built-in defaults, then ``[bounds.default]``, then ``profile``."""
        if profile not in self.profile_names():
            raise PolicyError(
                f"unknown policy profile {profile!r}; available: {', '.join(self.profile_names())}"
            )
        resolved = dict(_BUILTIN_DEFAULTS)
        base = self.bounds.get(DEFAULT_PROFILE)
        if base is not None:
            resolved = base.overlay(resolved)
        if profile != DEFAULT_PROFILE:
            resolved = self.bounds[profile].overlay(resolved)
        return resolved

    def lab_networks(self) -> tuple[IPNetwork, ...]:
        """Return the private networks the operator declared as authorized."""
        return self.lab.networks()

    def to_document(self) -> dict[str, Any]:
        """Return the JSON-ready form of the document as written."""
        document: dict[str, Any] = json.loads(self.model_dump_json(exclude_none=True))
        return document


def _candidate_paths() -> list[tuple[Path, bool]]:
    """Return candidate policy paths with whether each one is explicit."""
    candidates: list[tuple[Path, bool]] = []
    configured = os.environ.get(POLICY_PATH_VARIABLE, "").strip()
    if configured:
        candidates.append((Path(configured), True))
    candidates.append((Path(PROJECT_POLICY_FILE), False))
    candidates.append((Path.home() / USER_POLICY_FILE, False))
    return candidates


def parse_policy(raw: str, source: Path | None = None) -> PolicyRuleset:
    """Parse and validate one policy document from TOML text."""
    where = f" in {source}" if source is not None else ""
    try:
        parsed = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"invalid TOML policy{where}: {exc}") from exc
    try:
        return PolicyRuleset.model_validate(parsed)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        )
        raise PolicyError(f"invalid policy{where}: {details}") from exc


def load_policy_with_source(
    explicit_path: Path | None = None,
) -> tuple[PolicyRuleset, Path | None]:
    """Load the selected policy and return its source, never hiding a failure.

    A path the operator named — through ``explicit_path`` or ``OLYMPUS_POLICY`` —
    must exist. Only the implicit discovery fallbacks may be absent, in which
    case the built-in defaults apply.
    """
    candidates = [(explicit_path, True)] if explicit_path is not None else _candidate_paths()
    for path, is_explicit in candidates:
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            if is_explicit:
                raise PolicyError(f"policy file does not exist: {path}") from exc
            continue
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError(f"policy file {path} is not valid UTF-8") from exc
        return parse_policy(text, path), path.resolve()
    return PolicyRuleset(), None


def load_policy(explicit_path: Path | None = None) -> PolicyRuleset:
    """Load and validate the selected policy document."""
    ruleset, _source = load_policy_with_source(explicit_path)
    return ruleset


@lru_cache(maxsize=1)
def _cached_active_policy(fingerprint: tuple[Any, ...]) -> PolicyRuleset:
    del fingerprint  # only used to key the cache
    return load_policy()


def active_policy() -> PolicyRuleset:
    """Return the process-wide policy, re-reading it when its selection changes.

    The cache key is the selected path plus its modification time and size, so an
    edited file is picked up on the next call without a restart, while a hot loop
    does not re-parse TOML on every bounded operation.
    """
    configured = os.environ.get(POLICY_PATH_VARIABLE, "").strip()
    for path, _explicit in _candidate_paths():
        try:
            stat = path.stat()
        except OSError:
            continue
        return _cached_active_policy((str(path.resolve()), stat.st_mtime_ns, stat.st_size))
    return _cached_active_policy((configured, 0, 0))


def reset_active_policy_cache() -> None:
    """Drop the memoized policy. Tests and ``policy edit`` call this."""
    _cached_active_policy.cache_clear()


def environment_variable(key: str) -> str:
    """Return the deterministic environment override name for one bound."""
    return f"{ENVIRONMENT_PREFIX}{key.upper()}"


def _coerce_bound(key: str, raw: str, origin: str) -> float | int:
    try:
        value: float | int = int(raw.strip()) if key in _INTEGER_BOUNDS else float(raw.strip())
    except ValueError as exc:
        expected = "integer" if key in _INTEGER_BOUNDS else "number"
        raise PolicyError(f"invalid {origin}: expected {expected}, got {raw!r}") from exc
    return value


def _check_bound(key: str, value: float | int, origin: str) -> float | int:
    floor, ceiling = BOUND_FLOORS[key], BOUND_CEILINGS[key]
    if not floor <= float(value) <= ceiling:
        raise PolicyError(
            f"{origin} out of range: {key} must be between {floor:g} and {ceiling:g}, got {value:g}"
        )
    return value


def active_environment_overrides() -> list[str]:
    """List the active bound overrides by name, never by value."""
    return sorted(
        variable
        for key in _BUILTIN_DEFAULTS
        if (variable := environment_variable(key)) in os.environ
    )


def resolve_bounds(
    profile: str = DEFAULT_PROFILE,
    ruleset: PolicyRuleset | None = None,
    **overrides: float | int | None,
) -> dict[str, Any]:
    """Resolve one profile's bounds through the full precedence chain.

    ``overrides`` are the caller/CLI layer: a ``None`` entry means "not given"
    and defers to the layers below it, so a CLI can pass every flag through
    unconditionally.
    """
    unknown = set(overrides) - set(_BUILTIN_DEFAULTS)
    if unknown:
        raise PolicyError(f"unknown execution bound(s): {', '.join(sorted(unknown))}")

    document = active_policy() if ruleset is None else ruleset
    resolved = document.bounds_for(profile)
    for key, value in resolved.items():
        _check_bound(key, value, f"[bounds.{profile}].{key}")

    for key in _BUILTIN_DEFAULTS:
        variable = environment_variable(key)
        raw = os.environ.get(variable)
        if raw is None:
            continue
        resolved[key] = _check_bound(key, _coerce_bound(key, raw, variable), variable)

    for key, value in overrides.items():
        if value is None:
            continue
        resolved[key] = _check_bound(key, value, f"--{key.replace('_', '-')}")

    for key in _INTEGER_BOUNDS:
        resolved[key] = int(resolved[key])
    return resolved


def resolve_execution_policy(
    profile: str = DEFAULT_PROFILE,
    *,
    authorized: bool = False,
    approval_reference: str | None = None,
    ruleset: PolicyRuleset | None = None,
    **overrides: float | int | None,
) -> ExecutionPolicy:
    """Build the :class:`ExecutionPolicy` an operation should run under.

    Authorization is *not* something a file can grant: ``authorized`` stays a
    caller decision, exactly as before, so a policy file can never turn an
    unauthorized run into an authorized one.
    """
    bounds = resolve_bounds(profile, ruleset, **overrides)
    return ExecutionPolicy(
        authorized=authorized,
        approval_reference=approval_reference,
        **bounds,
    )


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def lab_activation_record(
    ruleset: PolicyRuleset | None = None,
    source: Path | None = None,
    signing_key: str | None = None,
) -> dict[str, Any]:
    """Return the attestation of who widened the SSRF guard, and when.

    The record is signed with HMAC-SHA256 when a key is configured through
    ``OLYMPUS_POLICY_LAB_KEY``. Without a key the record is still emitted and
    still carries the document digest, but ``signed`` is ``false`` — an
    unsigned record is never presented as a signed one.
    """
    document = active_policy() if ruleset is None else ruleset
    lab = document.lab
    payload: dict[str, Any] = {
        "schema_name": "olympus.policy-lab-activation",
        "schema_version": "1.0.0",
        "enabled": lab.enabled,
        "engagement": document.engagement,
        "source": str(source) if source is not None else None,
        "allowed_networks": list(lab.allowed_networks),
        "activated_by": lab.activated_by,
        "activated_at": lab.activated_at.astimezone(UTC).isoformat()
        if lab.activated_at is not None
        else None,
        "policy_digest": hashlib.sha256(_canonical(document.to_document())).hexdigest(),
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    key = signing_key if signing_key is not None else os.environ.get(LAB_SIGNING_KEY_VARIABLE, "")
    if key:
        signature = hmac.new(key.encode("utf-8"), _canonical(payload), hashlib.sha256).hexdigest()
        return {**payload, "signed": True, "algorithm": "HMAC-SHA256", "signature": signature}
    return {**payload, "signed": False, "algorithm": None, "signature": None}


def _describe_value(value: Any) -> Any:
    return value


def diff_bounds(
    profile: str = DEFAULT_PROFILE,
    ruleset: PolicyRuleset | None = None,
) -> list[dict[str, Any]]:
    """Return only the bounds a profile actually changes, and why.

    ``olympus policy diff`` exists so an operator can answer "what is this file
    doing to me?" without mentally replaying the precedence chain.
    """
    document = active_policy() if ruleset is None else ruleset
    effective = resolve_bounds(profile, document)
    changes: list[dict[str, Any]] = []
    for key, builtin in _BUILTIN_DEFAULTS.items():
        current = effective[key]
        if current == builtin:
            continue
        variable = environment_variable(key)
        if variable in os.environ:
            origin: str = f"environment:{variable}"
        elif profile != DEFAULT_PROFILE and key in document.bounds.get(
            profile, BoundsProfile()
        ).model_dump(exclude_none=True):
            origin = f"[bounds.{profile}]"
        else:
            origin = f"[bounds.{DEFAULT_PROFILE}]"
        changes.append(
            {
                "bound": key,
                "default": _describe_value(builtin),
                "effective": _describe_value(current),
                "ceiling": _describe_value(BOUND_CEILINGS[key]),
                "origin": origin,
            }
        )
    return changes


def effective_document(
    profile: str = DEFAULT_PROFILE,
    ruleset: PolicyRuleset | None = None,
    source: Path | None = None,
    status: Literal["valid"] = "valid",
) -> dict[str, Any]:
    """Return the machine-readable answer of ``olympus policy show``."""
    document = active_policy() if ruleset is None else ruleset
    return {
        "schema_name": POLICY_SCHEMA_NAME,
        "schema_version": POLICY_SCHEMA_VERSION,
        "status": status,
        "source": str(source) if source is not None else None,
        "engagement": document.engagement,
        "profile": profile,
        "profiles": list(document.profile_names()),
        "environment_overrides": active_environment_overrides(),
        "bounds": resolve_bounds(profile, document),
        "ceilings": {key: BOUND_CEILINGS[key] for key in sorted(BOUND_CEILINGS)},
        "scope": {
            "domains": {
                "allowed": list(document.scope.domains.allowed),
                "excluded": list(document.scope.domains.excluded),
            }
        },
        "lab": lab_activation_record(document, source),
    }


TEMPLATE = f'''# Olympus execution policy — see docs/policy.md
# Every bound below may only LOWER the compiled-in ceiling, never raise it.
schema_version = "{POLICY_SCHEMA_VERSION}"
engagement     = "example-engagement"

[bounds.default]
timeout_seconds  = {_BUILTIN_DEFAULTS["timeout_seconds"]:g}
deadline_seconds = {_BUILTIN_DEFAULTS["deadline_seconds"]:g}
max_concurrency  = {_BUILTIN_DEFAULTS["max_concurrency"]}
retries          = {_BUILTIN_DEFAULTS["retries"]}
backoff_seconds  = {_BUILTIN_DEFAULTS["backoff_seconds"]:g}
jitter_ratio     = 0.2

# Selected with --profile aggressive; inherits everything above.
[bounds.aggressive]
max_concurrency = 16
retries         = 3

[scope.domains]
allowed  = ["example.com"]
excluded = ["vpn.example.com"]

# Widens the SSRF guard to private ranges you declare you own.
# Enabling it requires naming who authorized it, and when.
# [lab]
# enabled          = true
# allowed_networks = ["10.10.0.0/16"]
# activated_by     = "operator@example.com"
# activated_at     = 2026-01-01T00:00:00Z
'''
