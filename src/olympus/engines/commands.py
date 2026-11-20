"""Canonical identifiers of the Olympus commands that may *require* an engine.

An ``engine.toml`` manifest can declare ``required_for_commands``: the engine is
not core (``mandatory``) but a specific command cannot run correctly without it,
so the preflight must demand it *for that command only*. That is worth nothing
unless two things hold, and this module is the single source of truth for both:

* **The identifier is real.** A free-form string would let a typo
  (``themis.rnu``) name a command that does not exist, so the engine is required
  for nothing and silently goes unchecked on the path that actually needs it —
  fail-*open* on a governance path. Every ``required_for_commands`` entry must be
  a member of :data:`COMMAND_IDS`, enforced at manifest load
  (:mod:`olympus.engines.schema`); :func:`require_known` raises otherwise.
* **The vocabulary matches the product.** :data:`COMMAND_IDS` holds the dotted
  form (``<group>.<command>``) of the real Olympus CLI commands that launch an
  external engine, and ``tests/unit/test_engine_commands.py`` fails if any id
  here is not a registered command — so the map cannot drift from the CLI.

Kept deliberately small: only a command that actually starts an engine belongs
here. Today a Themis scan is the one such command (direct ``themis run`` and the
queued jobs the worker executes are the same operation); the set grows only when
a new command genuinely launches an engine.
"""

from __future__ import annotations

from typing import Final

#: The dotted id of a Themis scan — the one command that launches an engine today.
#: Direct ``themis run`` and the persisted jobs the worker executes are the same
#: operation, so they share this id and the same ``required_for_commands`` map.
THEMIS_RUN: Final = "themis.run"

#: Closed vocabulary of command ids a manifest's ``required_for_commands`` may name.
COMMAND_IDS: Final[frozenset[str]] = frozenset({THEMIS_RUN})


class UnknownCommandError(ValueError):
    """A command id that is not in :data:`COMMAND_IDS` (a typo or an unknown command)."""


def is_known_command(command_id: str) -> bool:
    """Return whether ``command_id`` is a governed, engine-launching command."""
    return command_id in COMMAND_IDS


def require_known(command_id: str) -> str:
    """Return ``command_id`` if governed, else raise :class:`UnknownCommandError`.

    Fail-closed: a caller that gates on a command Olympus does not know must stop,
    never silently check nothing.
    """
    if command_id not in COMMAND_IDS:
        known = ", ".join(sorted(COMMAND_IDS))
        raise UnknownCommandError(f"unknown command {command_id!r}; known commands: {known}")
    return command_id
