"""Build an engine's command line from its manifest allow-list - never by concatenation.

The flags an adapter may pass live in ``engine.toml`` (``static_flags``, ``value_flags``,
``optional_flags``). A caller supplies only *values*, keyed by an allowed value flag;
every value becomes exactly one ``argv`` element, so there is no string to split, no shell,
and no way for a value to introduce a flag of its own. A value that merely *looks* like a
flag (leading ``-``) is refused as argument injection, and so is anything the manifest does
not list.
"""

from __future__ import annotations

from collections.abc import Mapping

from olympus.engines.schema import EngineManifest

MAX_VALUE_LENGTH = 4_096


class ArgvError(ValueError):
    """A value or flag is not allowed by the engine manifest."""


def _checked(flag: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ArgvError(f"{flag}: value must be a non-empty string")
    if len(value) > MAX_VALUE_LENGTH:
        raise ArgvError(f"{flag}: value exceeds {MAX_VALUE_LENGTH} characters")
    if any(character in value for character in ("\x00", "\r", "\n")):
        raise ArgvError(f"{flag}: value must not contain NUL, CR or LF")
    if value.startswith("-"):
        raise ArgvError(f"{flag}: a value may not start with '-' (argument injection)")
    return value


def build_argv(manifest: EngineManifest, values: Mapping[str, str]) -> list[str]:
    """Return ``[binary, <value flags>, <static flags>]`` for ``manifest``.

    ``values`` maps each allowed value flag to its runtime value. Unknown flags, missing
    required flags and unsafe values raise :class:`ArgvError` before anything runs.
    """
    adapter = manifest.adapter
    if adapter is None or not manifest.engine.presence_probe:
        raise ArgvError(f"{manifest.engine.name}: no adapter allow-list to build a command from")
    if not adapter.value_flags and not adapter.static_flags:
        raise ArgvError(f"{manifest.engine.name}: the manifest declares no allowed flags")
    unknown = sorted(set(values) - set(adapter.value_flags))
    if unknown:
        raise ArgvError(f"{manifest.engine.name}: flags not allowed by the manifest: {unknown}")
    argv = [manifest.engine.presence_probe[0]]
    for flag in adapter.value_flags:
        if flag in values:
            argv += [flag, _checked(flag, values[flag])]
        elif flag not in adapter.optional_flags:
            raise ArgvError(f"{manifest.engine.name}: required flag {flag} has no value")
    argv += adapter.static_flags
    return argv
