"""Optional TOML configuration so operators stop repeating the same flags.

Olympus resolves values, in order of precedence:

1. an explicit caller/CLI override;
2. ``OLYMPUS_<SECTION>_<KEY>`` environment variables;
3. the selected TOML file;
4. built-in defaults.

The TOML file itself is selected from ``OLYMPUS_CONFIG``, then
``./olympus.toml``, then ``~/.olympus.toml``.

The file is entirely optional — with no file present every helper falls back
to the built-in defaults, so nothing changes. Example::

    [http]
    timeout = 15.0
    retries = 3
    rate = 0.25
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path
from typing import Any


class ConfigError(RuntimeError):
    """Raised when an explicitly selected or discovered config is invalid."""


HTTP_DEFAULTS: dict[str, int | float] = {
    "timeout": 10.0,
    "retries": 2,
    "backoff": 0.5,
    "jitter": 0.0,
    "rate": 0.0,
    "max_response_bytes": 2 * 1024 * 1024,
    "max_response_headers": 100,
    "max_response_header_bytes": 64 * 1024,
    "max_redirects": 10,
    "max_decompressed_bytes": 8 * 1024 * 1024,
    "max_expansion_ratio": 100.0,
    "deadline": 600.0,
}

OBSERVABILITY_DEFAULTS: dict[str, str | int] = {
    "backend": "none",
    "cardinality_limit": 64,
    "otlp_endpoint": "http://127.0.0.1:4318",
    "prometheus_textfile": "",
    "service_name": "olympus-security",
}

_OBSERVABILITY_BACKENDS = frozenset({"none", "prometheus", "otlp"})
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_HTTP_NUMERIC_RULES: dict[str, tuple[type, float, float]] = {
    "timeout": (float, 0.001, 3600.0),
    "retries": (int, 0, 10),
    "backoff": (float, 0.0, 300.0),
    "jitter": (float, 0.0, 1.0),
    "rate": (float, 0.0, 3600.0),
    "max_response_bytes": (int, 1, 100 * 1024 * 1024),
    "max_response_headers": (int, 1, 1_000),
    "max_response_header_bytes": (int, 1, 1024 * 1024),
    "max_redirects": (int, 0, 10),
    "max_decompressed_bytes": (int, 1, 100 * 1024 * 1024),
    "max_expansion_ratio": (float, 1.0, 10_000.0),
    "deadline": (float, 0.05, 86_400.0),
}


def _candidate_paths() -> list[Path]:
    paths: list[Path] = []
    env_path = os.environ.get("OLYMPUS_CONFIG", "").strip()
    if env_path:
        paths.append(Path(env_path))
    paths.append(Path("olympus.toml"))
    paths.append(Path.home() / ".olympus.toml")
    return paths


def _validate_http_config(data: dict[str, Any], path: Path) -> None:
    table = data.get("http")
    if table is None:
        return
    if not isinstance(table, dict):
        raise ConfigError(f"[http] must be a TOML table in {path}")

    for key, value in table.items():
        if key not in _HTTP_NUMERIC_RULES:
            raise ConfigError(f"unknown [http] option {key!r} in {path}")
        expected, minimum, maximum = _HTTP_NUMERIC_RULES[key]
        valid_type = isinstance(value, expected) and not isinstance(value, bool)
        if expected is float:
            valid_type = isinstance(value, int | float) and not isinstance(value, bool)
        if not valid_type or not minimum <= value <= maximum:
            raise ConfigError(
                f"invalid [http].{key} in {path}: expected {expected.__name__} "
                f"between {minimum:g} and {maximum:g}"
            )


def _validate_observability_config(data: dict[str, Any], path: Path) -> None:
    table = data.get("observability")
    if table is None:
        return
    if not isinstance(table, dict):
        raise ConfigError(f"[observability] must be a TOML table in {path}")
    unknown = set(table) - set(OBSERVABILITY_DEFAULTS)
    if unknown:
        raise ConfigError(f"unknown [observability] option {sorted(unknown)[0]!r} in {path}")
    backend = table.get("backend", "none")
    if not isinstance(backend, str) or backend.casefold() not in _OBSERVABILITY_BACKENDS:
        raise ConfigError(f"invalid [observability].backend in {path}")
    limit = table.get("cardinality_limit", 64)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 8 <= limit <= 256:
        raise ConfigError(f"invalid [observability].cardinality_limit in {path}: expected 8..256")
    endpoint = table.get("otlp_endpoint", "http://127.0.0.1:4318")
    if not isinstance(endpoint, str) or not endpoint.startswith(("http://", "https://")):
        raise ConfigError(f"invalid [observability].otlp_endpoint in {path}")
    textfile = table.get("prometheus_textfile", "")
    if not isinstance(textfile, str):
        raise ConfigError(f"invalid [observability].prometheus_textfile in {path}")
    service_name = table.get("service_name", "olympus-security")
    if not isinstance(service_name, str) or not _SERVICE_NAME.fullmatch(service_name):
        raise ConfigError(f"invalid [observability].service_name in {path}")


def _validate_config(data: dict[str, Any], path: Path) -> dict[str, Any]:
    _validate_http_config(data, path)
    _validate_observability_config(data, path)
    return data


def load_config_with_source(
    explicit_path: Path | None = None,
) -> tuple[dict[str, Any], Path | None]:
    """Load the selected document and return its source without hiding failures."""
    configured_path = os.environ.get("OLYMPUS_CONFIG", "").strip()
    candidates = [explicit_path] if explicit_path is not None else _candidate_paths()
    for index, path in enumerate(candidates):
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            if explicit_path is not None or (configured_path and index == 0):
                raise ConfigError(f"explicit config file does not exist: {path}") from exc
            continue
        except OSError as exc:
            raise ConfigError(f"cannot read config file {path}: {exc}") from exc
        try:
            parsed = tomllib.loads(raw.decode("utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"invalid TOML config {path}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ConfigError(f"config root must be a TOML table: {path}")
        return _validate_config(parsed, path), path.resolve()
    return {}, None


def load_config() -> dict[str, Any]:
    """Load and validate the selected configuration document."""
    data, _source = load_config_with_source()
    return data


def environment_variable(section: str, key: str) -> str:
    """Return the deterministic environment override name for one value."""
    normalized = f"{section}_{key}".upper().replace("-", "_")
    return f"OLYMPUS_{normalized}"


def _environment_value(variable: str, raw: str, default: Any) -> Any:
    """Parse one environment value using the declared default's exact type."""
    try:
        if isinstance(default, bool):
            normalized = raw.strip().casefold()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
            raise ValueError
        if isinstance(default, int):
            return int(raw.strip())
        if isinstance(default, float):
            return float(raw.strip())
        if isinstance(default, str):
            return raw
    except ValueError as exc:
        raise ConfigError(
            f"invalid environment override {variable}: expected {type(default).__name__}"
        ) from exc
    raise ConfigError(f"unsupported configuration type for {variable}")


def get(section: str, key: str, default: Any, config: dict[str, Any] | None = None) -> Any:
    """Resolve environment, validated file value, then built-in default."""
    data = load_config() if config is None else config
    variable = environment_variable(section, key)
    raw_environment = os.environ.get(variable)
    if raw_environment is not None:
        value = _environment_value(variable, raw_environment, default)
        if section == "http":
            _validate_http_config({"http": {key: value}}, Path(f"environment:{variable}"))
        if section == "observability":
            _validate_observability_config(
                {"observability": {key: value}}, Path(f"environment:{variable}")
            )
        return value
    table = data.get(section)
    if not isinstance(table, dict) or key not in table:
        return default
    value = table[key]
    # Only honor a config value that matches the default's type (bool is not int here).
    if type(value) is type(default) or (
        isinstance(default, float) and isinstance(value, int) and not isinstance(value, bool)
    ):
        return value
    raise ConfigError(
        f"invalid type for [{section}].{key}: expected {type(default).__name__}, "
        f"got {type(value).__name__}"
    )


def effective_config(data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the redaction-ready effective document for known settings."""
    loaded = load_config() if data is None else data
    effective = {key: value for key, value in loaded.items() if key != "http"}
    http = {
        key: get("http", key, default, loaded)
        for key, default in HTTP_DEFAULTS.items()
        if key != "deadline"
    }
    http["deadline"] = get("http", "deadline", max(float(http["timeout"]), 600.0), loaded)
    effective["http"] = http
    effective["observability"] = {
        key: get("observability", key, default, loaded)
        for key, default in OBSERVABILITY_DEFAULTS.items()
    }
    return effective


def active_environment_overrides() -> list[str]:
    """List active known override names without exposing their values."""
    variables = [
        variable
        for key in HTTP_DEFAULTS
        if (variable := environment_variable("http", key)) in os.environ
    ]
    variables.extend(
        variable
        for key in OBSERVABILITY_DEFAULTS
        if (variable := environment_variable("observability", key)) in os.environ
    )
    return sorted(variables)
