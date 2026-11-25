# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cross-cutting string vocabularies, as stdlib enums.

This module imports nothing from the package (stdlib ``enum`` only), so every
layer -- core, config, base, cli, utils, the plugin modules -- can import it
without a cycle. A vocabulary used inside one module, or one small cluster of
files, stays in its owning module; enums that already exist elsewhere
(``core/enums.py``, ``models/workspace.py``) stay where they are.

Every member's value is the exact wire spelling, and every enum mixes in ``str``
so a member serializes, compares and hashes as its value. Compare members by
identity (``x is Severity.HIGH``) and take ``.value`` at every textual boundary:
``str(member)`` and f-string interpolation render the qualified member name on
some supported interpreters, so ``f"{member}"`` is never a spelling of the value.

Severity stays an OPEN vocabulary for now: a scanner may emit a word that is not
on the ladder, and the ingest helpers here return ``None`` for it instead of
raising. Closing it (a ``Severity``-typed finding field, a polars ``Enum``
column) is a separate, deliberate change.
"""

from enum import Enum
from typing import Literal, Optional, Tuple


class Severity(str, Enum):
    """ASH's finding-severity ladder, most severe first.

    Member order is the ladder order: ``SEVERITY_RANK`` and every rank table
    derive from it, so nothing else needs to spell the ladder.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_text(cls, text: object) -> Optional["Severity"]:
        """The member *text* names in any case, or ``None`` when it names none.

        The one ingest helper for severity words: it case-folds and strips, and
        an off-ladder word (npm's ``moderate``, a blank, a non-string) is not an
        error here -- severity is an open vocabulary until it is deliberately
        closed.
        """
        if isinstance(text, Severity):
            return text
        if not isinstance(text, str):
            return None
        try:
            return cls(text.strip().upper())
        except ValueError:
            return None

    @property
    def bucket(self) -> str:
        """The lowercase spelling used for count-bucket and field names."""
        return self.value.lower()


class SeverityThreshold(str, Enum):
    """The gate vocabulary: the least severe finding that still fails a scan.

    Not merged with ``Severity`` (it has ``ALL`` and no ``INFO``) and not with
    ``core.enums.MinSeverity`` (a different casing family with ``none``).
    Member order is loosest first.
    """

    ALL = "ALL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_text(cls, text: object) -> Optional["SeverityThreshold"]:
        """The member *text* names in any case, or ``None`` when it names none."""
        if isinstance(text, SeverityThreshold):
            return text
        if not isinstance(text, str):
            return None
        try:
            return cls(text.strip().upper())
        except ValueError:
            return None


#: The gate vocabulary as a static type, for the fields that must stay text.
#:
#: A pydantic field typed ``SeverityThreshold`` validates differently from this
#: Literal in the two ways the config seam depends on: under ``strict=True`` (how
#: config files are loaded) an enum field refuses the plain string a file holds
#: ("Input should be an instance of SeverityThreshold"), and the JSON schema grows
#: a ``$ref`` where the committed schemas carry the inline ``enum``. So the config
#: fields, the scanner option and the report container keep this Literal -- the
#: one place outside the enum that spells the five words -- and
#: ``tests/unit/vocab`` pins ``get_args(SeverityThresholdText)`` to the members, so
#: it cannot drift from the enum it mirrors. Type checkers cannot read a Literal
#: built from a variable, which is why this is written out and pinned, not derived.
SeverityThresholdText = Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

#: The ladder as wire strings, most severe first -- ``tuple(Severity)`` as text.
SEVERITY_VALUES: Tuple[str, ...] = tuple(m.value for m in Severity)

#: The gate vocabulary as wire strings, loosest first.
SEVERITY_THRESHOLD_VALUES: Tuple[str, ...] = tuple(m.value for m in SeverityThreshold)

#: The lowercase count-bucket names of a severity tally, most severe first. These
#: are pydantic field names and dict keys, so they cannot be members; they are
#: derived from the enum so the ladder is spelled once.
SEVERITY_BUCKETS: Tuple[str, ...] = tuple(m.bucket for m in Severity)

#: ``SEVERITY_BUCKETS`` with the ``suppressed`` tally in front, the field order
#: of ``ScannerSeverityCount``.
SEVERITY_COUNT_FIELDS: Tuple[str, ...] = ("suppressed",) + SEVERITY_BUCKETS
