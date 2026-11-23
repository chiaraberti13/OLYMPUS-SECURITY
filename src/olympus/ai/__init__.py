"""Optional AI layer (ADR-011 / ADR-012).

Everything here is **off by default**: with the AI feature flag unset Olympus
behaves exactly as without this package (ADR-011's first invariant). The flag is
read from the environment so no code path turns the layer on implicitly.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

#: Environment variable that enables the optional AI layer. Anything other than a
#: truthy value leaves the whole layer inert.
AI_ENABLED_ENV = "OLYMPUS_AI_ENABLED"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def ai_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Return whether the optional AI layer is enabled (default: False)."""
    source = env if env is not None else os.environ
    return source.get(AI_ENABLED_ENV, "").strip().lower() in _TRUTHY
