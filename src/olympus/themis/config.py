"""Themis configuration with legacy ``VAP_*`` compatibility.

The subsystem was renamed AEGIS -> Themis (ROADMAP ``DEV-I``). The configuration
environment variables are a **deployment contract**, so they keep the
``AEGIS_*`` names for now; each falls back to the corresponding legacy ``VAP_*``
variable when unset. Renaming the variables to ``THEMIS_*`` (reading
``THEMIS_*`` first, then ``AEGIS_*``, then ``VAP_*``) is staged with the
schema-name migration as a ``DEV-I`` follow-up, so existing deployments keep
working. This mapping is documented in ``docs/themis-config.md``.
"""

from __future__ import annotations

import os


class ThemisConfigError(ValueError):
    """Raised when native and legacy configuration is invalid or ambiguous."""


#: AEGIS_* → legacy VAP_* compatibility mapping.
COMPAT: dict[str, str] = {
    "AEGIS_ENABLE_LIVE_SCANS": "VAP_ENABLE_LIVE_SCANS",
    "AEGIS_SIMULATION_MODE": "VAP_SIMULATION_MODE",
    "AEGIS_HOST": "VAP_HOST",
    "AEGIS_PORT": "VAP_PORT",
    "AEGIS_DATABASE_URL": "VAP_DATABASE_URL",
    "AEGIS_REPORTS_DIR": "VAP_REPORTS_DIR",
    "AEGIS_CELERY_BROKER_URL": "VAP_CELERY_BROKER_URL",
}


def get(name: str, default: str = "") -> str:
    """Return ``AEGIS_<name>`` (or its legacy ``VAP_*`` fallback), else ``default``."""
    value = os.environ.get(name)
    legacy = COMPAT.get(name)
    legacy_value = os.environ.get(legacy) if legacy is not None else None
    if value is not None and legacy_value is not None and value.strip() != legacy_value.strip():
        raise ThemisConfigError(
            f"ambiguous configuration: {name} and {legacy} are both set differently"
        )
    if value is not None:
        return value
    if legacy_value is not None:
        return legacy_value
    return default


def _flag(name: str) -> bool:
    value = get(name, "false").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ThemisConfigError(
        f"{name} must be one of true/false, 1/0, yes/no, or on/off; got {value!r}"
    )


def live_enabled() -> bool:
    """True when live scanning is explicitly enabled (AEGIS or legacy VAP)."""
    return _flag("AEGIS_ENABLE_LIVE_SCANS")


def simulation_mode() -> bool:
    """True when global simulation mode is explicitly requested."""
    return _flag("AEGIS_SIMULATION_MODE")
