# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cross-cutting closed vocabularies, one definition each.

This module imports nothing from the package (standard-library ``enum`` only),
so every layer (core, config, base, cli, utils, plugin modules) can import it
without a cycle. A vocabulary used inside one module or one small cluster stays
in the owning module; a vocabulary spelled in several layers lives here.

Base rules (the project floor is Python 3.10, so ``StrEnum`` is not available):

* ``(str, Enum)`` for anything that serializes (config keys, JSON, CLI flags).
  A member compares equal to its wire string, so a caller that still passes the
  bare string keeps working.
* ``.value`` at every textual boundary (f-strings, log lines, argv). Members of
  a vocabulary here also render as their value under ``str()`` and ``format()``
  so an interpolated member cannot print the qualified ``Class.MEMBER`` form on
  one interpreter and the value on another.
* One ingest helper per vocabulary turns outside text into a member; past it the
  code carries members.
"""

from enum import Enum
from typing import Any, Optional, Tuple


class PluginKind(str, Enum):
    """The three plugin kinds ASH loads: converter, scanner and reporter.

    The value is the singular spelling (``ash_plugin_type``, ``--plugin-type``,
    ``get_plugin_config(plugin_type=...)``). The plural config section that holds
    the kind's plugins (``converters``, ``scanners``, ``reporters``) is derived
    by :attr:`section`, so the singular and plural spellings are one definition.
    Member order is the order the three sections are walked in.

    The kinds are a closed set ASH ships; the NAMES of the plugins of a kind
    (scanner names, reporter names, converter names) are an open set that plugins
    extend and are never enumerated here.
    """

    CONVERTER = "converter"
    SCANNER = "scanner"
    REPORTER = "reporter"

    def __str__(self) -> str:
        return self.value

    def __format__(self, format_spec: str) -> str:
        return format(self.value, format_spec)

    @property
    def section(self) -> str:
        """The plural config section key of this kind (``"scanners"`` for SCANNER)."""
        return f"{self.value}s"

    @classmethod
    def coerce(cls, value: Any) -> Optional["PluginKind"]:
        """The member a kind spelling names, or ``None`` for anything else.

        The ingest helper for the singular spelling: a member passes through, a
        string is looked up by value. An unknown kind is ``None``, which is how
        the lookups that have always answered "no such kind" with an empty result
        still do.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value)
            except ValueError:
                return None
        return None

    @classmethod
    def from_section(cls, section: Any) -> Optional["PluginKind"]:
        """The member whose plural section key is ``section``, or ``None``.

        The ingest helper for the plural spelling (``"scanners"`` gives SCANNER).
        """
        if isinstance(section, str):
            for kind in cls:
                if kind.section == section:
                    return kind
        return None

    @classmethod
    def sections(cls) -> Tuple[str, ...]:
        """The plural section keys of every kind, in member order."""
        return tuple(kind.section for kind in cls)

    @classmethod
    def values(cls) -> Tuple[str, ...]:
        """The singular spellings of every kind, in member order."""
        return tuple(kind.value for kind in cls)
