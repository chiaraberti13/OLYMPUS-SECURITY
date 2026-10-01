"""Themis configuration with ``AEGIS_*`` and legacy ``VAP_*`` compatibility.

The subsystem was renamed AEGIS -> Themis (ROADMAP ``DEV-I``). Configuration
environment variables are now canonically ``THEMIS_*``. Because the variable
names are a **deployment contract**, each canonical ``THEMIS_*`` value falls
back — in order — to the corresponding ``AEGIS_*`` variable (the previous name)
and then to the legacy ``VAP_*`` variable (the vendored upstream name), so
existing deployments keep working without any change. Setting two of them to
*different* values is rejected as ambiguous. This mapping is documented in
``docs/themis-config.md``.
"""

from __future__ import annotations

import os

_THEMIS_PREFIX = "THEMIS_"
_AEGIS_PREFIX = "AEGIS_"


class ThemisConfigError(ValueError):
    """Raised when canonical and legacy configuration is invalid or ambiguous."""


#: Canonical ``THEMIS_*`` → legacy ``VAP_*`` compatibility mapping (deepest
#: fallback, from the vendored upstream platform).
COMPAT: dict[str, str] = {
    "THEMIS_ENABLE_LIVE_SCANS": "VAP_ENABLE_LIVE_SCANS",
    "THEMIS_SIMULATION_MODE": "VAP_SIMULATION_MODE",
    "THEMIS_HOST": "VAP_HOST",
    "THEMIS_PORT": "VAP_PORT",
    "THEMIS_DATABASE_URL": "VAP_DATABASE_URL",
    "THEMIS_REPORTS_DIR": "VAP_REPORTS_DIR",
    "THEMIS_CELERY_BROKER_URL": "VAP_CELERY_BROKER_URL",
}


def _fallback_names(name: str) -> list[str]:
    """Return the resolution order for ``name``: THEMIS, then AEGIS, then VAP.

    The resolver is bidirectional: whether a caller passes the canonical
    ``THEMIS_*`` name or the previous ``AEGIS_*`` name, both are tried (canonical
    first), followed by any mapped legacy ``VAP_*`` name. This keeps every read
    working during the rename regardless of which name a call site uses.
    """
    if name.startswith(_THEMIS_PREFIX):
        canonical = name
        aegis = _AEGIS_PREFIX + name[len(_THEMIS_PREFIX) :]
    elif name.startswith(_AEGIS_PREFIX):
        canonical = _THEMIS_PREFIX + name[len(_AEGIS_PREFIX) :]
        aegis = name
    else:
        return [name]
    order = [canonical, aegis]
    legacy = COMPAT.get(canonical)
    if legacy is not None:
        order.append(legacy)
    return order


def get(name: str, default: str = "") -> str:
    """Return the value of ``name`` (canonical ``THEMIS_*``) or a fallback.

    Resolution order is ``THEMIS_*`` → ``AEGIS_*`` → ``VAP_*``. If more than one
    is set to a *different* value, the configuration is ambiguous and rejected.
    """
    candidates = _fallback_names(name)
    present = [(key, os.environ[key]) for key in candidates if key in os.environ]
    distinct = {value.strip() for _, value in present}
    if len(distinct) > 1:
        names = ", ".join(key for key, _ in present)
        raise ThemisConfigError(f"ambiguous configuration: {names} are set to different values")
    if present:
        return present[0][1]
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
    """True when live scanning is explicitly enabled (THEMIS, AEGIS or VAP)."""
    return _flag("THEMIS_ENABLE_LIVE_SCANS")


def simulation_mode() -> bool:
    """True when global simulation mode is explicitly requested."""
    return _flag("THEMIS_SIMULATION_MODE")
