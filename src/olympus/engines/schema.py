"""Schema of ``olympus/engines/<name>/engine.toml`` — the per-engine source of truth.

A manifest is *data only*: it names the upstream project, how it is distributed,
the exact version/commit/digest Olympus is validated against, and whether the
engine must be present. It never contains a command line. Install commands shown
to operators are *derived* from the structured ``source`` table
(:meth:`EngineManifest.install_command`), so the text a person copies and the pin
the build verifies cannot drift apart.

Two independent rules decide when an absent engine aborts a run:

``mandatory``
    The engine belongs to the core path. Any engine-using command checks it,
    always.
``required_for_commands``
    The engine is needed only by the listed commands; the preflight checks it
    only when one of those commands runs.

An absent engine that is neither makes the run *partial* (exit 5), never clean.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Category = Literal["network", "web", "dns", "tls", "vuln"]
Distribution = Literal["apt", "pip", "gem", "go", "git", "binary", "docker", "npm", "api"]
UpdatePolicy = Literal["manual", "patch", "minor", "major"]
ResourceProfile = Literal["light", "network-heavy", "cpu-heavy"]
Runtime = Literal["python", "perl", "bash", "ruby"]
Build = Literal["autotools"]

#: Moving references that make a build non-reproducible. Rejected for every pin.
MOBILE_REFERENCES = frozenset(
    {"latest", "main", "master", "head", "stable", "edge", "nightly", "dev", "develop", "current"}
)

_NAME = r"^[a-z0-9][a-z0-9-]{0,63}$"  # same alphabet as ScanRequest.scanner
_DOTTED = r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$"
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,63}$")
_PROBE_TOKEN = re.compile(r"^[A-Za-z0-9._=:@%+,/-]{1,128}$")
_SHA1 = re.compile(r"^[a-f0-9]{40}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ENV_NAME = r"^[A-Z][A-Z0-9_]{2,63}$"
_BUILD_ARG = r"^--[a-z0-9][a-z0-9-]{0,40}(=[A-Za-z0-9/._-]{1,80})?$"
_RUNTIME_PACKAGE = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}==[0-9][A-Za-z0-9._+-]{0,40}$"
_ENTRYPOINT = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$")

DottedId = Annotated[str, StringConstraints(pattern=_DOTTED, max_length=64)]


#: PyPI names that look like an engine but are NOT the upstream project. A ``pip``
#: manifest naming one of these is rejected, so the mistake cannot come back.
NOT_UPSTREAM_ON_PYPI: dict[str, str] = {
    "commix": 'PyPI "commix" 0.1 is a third-party package (author "Bhai4You"), not '
    "commixproject/commix; install commix from git",
    "theharvester": 'PyPI "theHarvester" 0.0.1 is a stale release, not the 4.x tool; '
    "install theHarvester from git",
}


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Source(_Frozen):
    """Where the pinned artifact comes from. Which fields apply depends on ``distribution``."""

    package: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    module: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9./_-]{0,255}$")
    repo: str | None = Field(default=None, pattern=r"^https://[A-Za-z0-9./_-]{1,200}$")
    commit: str | None = None
    #: Absolute directory the git checkout lives in (also where ``git rev-parse`` runs).
    checkout_path: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9._/-]{1,200}$")
    #: Interpreted engines: script inside the checkout (relative) and its interpreter.
    entry: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-][A-Za-z0-9._/-]{0,120}$")
    runtime: Runtime | None = None
    #: Compiled engines: build system used on the checkout, and its configure flags.
    build: Build | None = None
    build_args: list[Annotated[str, StringConstraints(pattern=_BUILD_ARG)]] = Field(
        default_factory=list, max_length=16
    )
    #: Exact ``name==version`` packages the runtime needs (pip for python, gem for ruby).
    runtime_packages: list[Annotated[str, StringConstraints(pattern=_RUNTIME_PACKAGE)]] = Field(
        default_factory=list, max_length=16
    )
    url: str | None = Field(default=None, pattern=r"^https://[^\s'\"]{1,500}$")
    sha256: str | None = None
    image: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9./_-]{0,200}$")
    digest: str | None = None
    #: For ``api`` engines: the external product/service Olympus talks to, and the
    #: NAMES of the environment variables that configure it (never their values).
    requires_product: str | None = Field(default=None, max_length=200)
    env_vars: list[Annotated[str, StringConstraints(pattern=_ENV_NAME)]] = Field(
        default_factory=list, max_length=8
    )

    @model_validator(mode="after")
    def _shapes(self) -> Self:
        if self.commit is not None and _SHA1.fullmatch(self.commit) is None:
            raise ValueError("commit must be a full 40-hex lowercase SHA-1")
        if self.sha256 is not None and _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("sha256 must be 64 lowercase hex characters")
        if self.digest is not None and _DIGEST.fullmatch(self.digest) is None:
            raise ValueError("digest must be 'sha256:' followed by 64 lowercase hex characters")
        if self.entry is not None and (".." in self.entry.split("/") or self.entry.startswith("/")):
            raise ValueError("entry must be a relative path inside the checkout")
        return self


class Adapter(_Frozen):
    """Link to the existing :class:`~olympus.themis.base.ScannerAdapter` subclass."""

    entrypoint: str
    timeout_seconds: int = Field(ge=1, le=3600)
    resource_profile: ResourceProfile
    #: False while ``timeout_seconds``/``resource_profile`` are estimates rather than
    #: values derived from evidence. A pilot review flips it; nobody should have to
    #: guess later which numbers were ever measured.
    reviewed: bool = False

    @model_validator(mode="after")
    def _entrypoint(self) -> Self:
        if _ENTRYPOINT.fullmatch(self.entrypoint) is None:
            raise ValueError("entrypoint must look like 'package.module:ClassName'")
        return self


class Engine(_Frozen):
    name: str = Field(pattern=_NAME)
    category: Category
    upstream: str = Field(pattern=r"^https://[A-Za-z0-9.-]+(/[^\s]*)?$", max_length=300)
    #: True only once ``engines check-updates`` has resolved the URL and found
    #: tags compatible with the pin. A hand-written URL starts as False.
    upstream_verified: bool = False
    language: str = Field(min_length=1, max_length=40)
    license: str = Field(min_length=1, max_length=100)
    distribution: Distribution
    #: Exact version/tag the adapter is validated against. Absent only for ``api``
    #: engines, which are external products Olympus has never been run against.
    pinned_version: str | None = None
    #: Version the maturity evidence was actually captured against, as recorded in the
    #: evidence documents (free text, e.g. "7.94SVN" or "2.x"). Absent when none exists.
    evidence_version: str | None = Field(default=None, max_length=40)
    #: Version string the engine itself prints when it differs from ``pinned_version``
    #: (e.g. a tag whose code was never bumped). The pin is the tag/commit, never this.
    reported_version: str | None = Field(default=None, max_length=40)
    update_policy: UpdatePolicy
    mandatory: bool = False
    required_for_commands: list[DottedId] = Field(default_factory=list, max_length=16)
    #: Fixed argv that proves the executable is present. Empty only for ``api`` engines.
    presence_probe: list[str] = Field(default_factory=list, max_length=8)
    #: Names of ``_data/<name>.toml`` dependencies this engine cannot work without.
    requires_data: list[Annotated[str, StringConstraints(pattern=_NAME)]] = Field(
        default_factory=list, max_length=8
    )
    capability: DottedId
    source: Source

    @model_validator(mode="after")
    def _pin_and_probe(self) -> Self:
        version = self.pinned_version
        if version is not None and (
            version.lower() in MOBILE_REFERENCES or _VERSION.fullmatch(version) is None
        ):
            raise ValueError(
                f"pinned_version {version!r} is not an exact version, tag, commit or digest "
                f"(moving references such as {sorted(MOBILE_REFERENCES)} are forbidden)"
            )
        if any(_PROBE_TOKEN.fullmatch(token) is None for token in self.presence_probe):
            raise ValueError("presence_probe tokens may only use [A-Za-z0-9._=:@%+,/-]")
        if self.presence_probe and "/" in self.presence_probe[0]:
            raise ValueError("presence_probe[0] must be a bare executable name, not a path")
        if len(set(self.required_for_commands)) != len(self.required_for_commands):
            raise ValueError("required_for_commands must not repeat a command")
        if self.mandatory and self.required_for_commands:
            raise ValueError(
                "an engine is either mandatory (always checked) or required_for_commands "
                "(checked only for those commands), not both"
            )
        return self


class DataDependency(_Frozen):
    """Data an engine needs that is not code (e.g. nuclei's template repository).

    Pinned and verified exactly like an engine, because it decides what the engine
    does: a floating template set changes findings without any change to Olympus.
    """

    name: str = Field(pattern=_NAME)
    upstream: str = Field(pattern=r"^https://[A-Za-z0-9.-]+(/[^\s]*)?$", max_length=300)
    upstream_verified: bool = False
    license: str = Field(min_length=1, max_length=100)
    pinned_version: str
    update_policy: UpdatePolicy
    used_by: list[Annotated[str, StringConstraints(pattern=_NAME)]] = Field(
        min_length=1, max_length=16
    )
    source: Source

    @model_validator(mode="after")
    def _pinned_git_checkout(self) -> Self:
        version = self.pinned_version
        if version.lower() in MOBILE_REFERENCES or _VERSION.fullmatch(version) is None:
            raise ValueError(f"pinned_version {version!r} is not an exact version or tag")
        missing = [
            field
            for field in ("repo", "commit", "checkout_path")
            if getattr(self.source, field) is None
        ]
        if missing:
            raise ValueError(f"a data dependency requires source.{', source.'.join(missing)}")
        return self


class DataManifest(_Frozen):
    """One validated ``_data/<name>.toml``."""

    data: DataDependency

    def install_command(self) -> str:
        source = self.data.source
        return (
            f"git init {source.checkout_path} && "
            f"git -C {source.checkout_path} fetch --depth 1 {source.repo} {source.commit} && "
            f"git -C {source.checkout_path} checkout --detach FETCH_HEAD"
        )


class EngineManifest(_Frozen):
    """One validated ``engine.toml``."""

    engine: Engine
    adapter: Adapter | None = None

    @model_validator(mode="after")
    def _distribution_rules(self) -> Self:
        engine, source = self.engine, self.engine.source
        required: dict[str, tuple[str, ...]] = {
            "apt": ("package",),
            "pip": ("package",),
            "gem": ("package",),
            "npm": ("package",),
            "go": ("module",),
            "git": ("repo", "commit", "checkout_path"),
            "binary": ("url", "sha256"),
            "docker": ("image", "digest"),
            "api": ("requires_product",),
        }
        missing = [
            field for field in required[engine.distribution] if getattr(source, field) is None
        ]
        if missing:
            raise ValueError(
                f"distribution {engine.distribution!r} requires source.{', source.'.join(missing)}"
            )
        if engine.distribution == "pip" and source.package is not None:
            reason = NOT_UPSTREAM_ON_PYPI.get(source.package.lower())
            if reason is not None:
                raise ValueError(reason)
        if engine.distribution == "git":
            interpreted = source.entry is not None and source.runtime is not None
            half = (source.entry is None) != (source.runtime is None)
            if half or interpreted == (source.build is not None):
                raise ValueError(
                    "a git engine is either interpreted (source.entry + source.runtime) "
                    "or compiled (source.build), never both and never neither"
                )
        if engine.distribution != "api":
            if engine.pinned_version is None:
                raise ValueError(f"distribution {engine.distribution!r} requires pinned_version")
            if not engine.presence_probe:
                raise ValueError(f"distribution {engine.distribution!r} requires presence_probe")
        if (
            engine.distribution == "go"
            and engine.pinned_version is not None
            and not engine.pinned_version.startswith("v")
        ):
            raise ValueError("a go pin must be a module version tag such as 'v3.11.1'")
        if engine.distribution == "api":
            if engine.mandatory or engine.required_for_commands:
                raise ValueError(
                    "an api engine needs an external product and can never be required"
                )
            if self.adapter is not None:
                raise ValueError("an api engine has no adapter yet and must stay catalog-only")
            if engine.presence_probe:
                raise ValueError(
                    "an api engine has no executable: use source.env_vars, not a probe"
                )
            if not source.env_vars:
                raise ValueError("an api engine must list the env var NAMES that configure it")
        if engine.mandatory and self.adapter is None:
            raise ValueError("a mandatory engine must declare an [adapter]")
        if engine.required_for_commands and self.adapter is None:
            raise ValueError("an engine required by commands must declare an [adapter]")
        return self

    # ------------------------------------------------------------------ derived
    def install_command(self) -> str | None:
        """Return the exact, copy-pasteable command that installs the pinned engine.

        Derived from the structured pin, never stored, so the message an operator
        sees always matches what the build verifies. ``None`` for ``api`` engines,
        which are products rather than installable artifacts.
        """
        engine, source = self.engine, self.engine.source
        version = engine.pinned_version
        match engine.distribution:
            case "apt":
                return f"apt-get install -y --no-install-recommends {source.package}={version}"
            case "pip":
                return f"pip install '{source.package}=={version}'"
            case "gem":
                return f"gem install {source.package} -v {version}"
            case "npm":
                return f"npm install --save-exact {source.package}@{version}"
            case "go":
                return f"go install {source.module}@{version}"
            case "git":
                steps = [
                    f"git init {source.checkout_path}",
                    f"git -C {source.checkout_path} fetch --depth 1 {source.repo} {source.commit}",
                    f"git -C {source.checkout_path} checkout --detach FETCH_HEAD",
                ]
                if source.build == "autotools":
                    flags = " ".join(source.build_args)
                    steps.append(
                        f"cd {source.checkout_path} && ./configure {flags} && make && make install"
                    )
                else:
                    if source.runtime == "python" and source.runtime_packages:
                        quoted = " ".join(f"'{item}'" for item in source.runtime_packages)
                        steps.append(f"pip install {quoted}")
                    if source.runtime == "ruby" and source.runtime_packages:
                        for item in source.runtime_packages:
                            package, _, gem_version = item.partition("==")
                            steps.append(f"gem install --no-document {package} -v {gem_version}")
                    steps.append(
                        f"printf '#!/bin/sh\\nexec {source.runtime} "
                        f'{source.checkout_path}/{source.entry} "$@"\\n\' '
                        f"> /usr/local/bin/{engine.presence_probe[0]} "
                        f"&& chmod 0755 /usr/local/bin/{engine.presence_probe[0]}"
                    )
                return " && ".join(steps)
            case "binary":
                return (
                    f"curl -fsSLo {engine.name} {source.url} && "
                    f"echo '{source.sha256}  {engine.name}' | sha256sum -c -"
                )
            case "docker":
                return f"docker pull {source.image}@{source.digest}"
            case _:
                return None
