# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cross-cutting string vocabularies, as stdlib enums.

This module imports nothing from the package (stdlib ``enum`` only), so every
layer -- core, config, base, cli, utils, the plugin modules -- can import it
without a cycle. A vocabulary used inside one module, or one small cluster of
files, stays in its owning module; enums that already exist elsewhere
(``core/enums.py``, ``models/workspace.py``) stay where they are.

Every member's value is the exact wire spelling, and every enum mixes in ``str``
so a member serializes, compares and hashes as its value. Compare with ``==``
(members equal their values, so the same test reads a member and plain text);
use ``is`` only on a value already converted to a member, because a field that
holds text (the config, scanner and container fields do) never ``is`` a member.
Take ``.value`` at every textual boundary:
``str(member)`` and f-string interpolation render the qualified member name on
some supported interpreters, so ``f"{member}"`` is never a spelling of the value
unless the class itself pins the rendering (``PluginKind`` overrides ``__str__``
and ``__format__`` to the value, as does ``Severity``; ``TargetType`` overrides ``__str__``; the
others do not).

Severity is OPEN at the scanner boundary and CLOSED from the finding on: a
scanner may emit a word that is not on the ladder, and the ingest helpers here
return ``None`` for it instead of raising, but the grading functions in
``utils.severity_ladder`` always land on a ladder word, and
``FlatVulnerability.severity`` (a ``Severity``-typed field) and the flat frame's
``severity`` column (a polars ``Enum``) refuse any other value.
"""

from enum import Enum
from typing import Any, Literal, Optional, Tuple


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

    # A finding holds a member (``FlatVulnerability.severity`` is typed as this
    # enum), and the reporters and exports interpolate it, so the rendering is
    # pinned to the value on every supported interpreter.
    def __str__(self) -> str:
        return self.value

    def __format__(self, format_spec: str) -> str:
        return format(self.value, format_spec)

    @classmethod
    def from_text(cls, text: object) -> Optional["Severity"]:
        """The member *text* names in any case, or ``None`` when it names none.

        The one ingest helper for severity words: it case-folds and strips, and
        an off-ladder word (npm's ``moderate``, a blank, a non-string) is not an
        error here: this is the scanner-boundary helper, and the caller decides
        what an unknown word grades as.
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


class TargetType(str, Enum):
    """Which tree a scanner is asked to scan: the source tree or the converted one.

    ``SOURCE`` is the directory the user pointed ASH at. ``CONVERTED`` is the work
    directory holding what converters produced from archives and notebooks.
    ``IMAGE`` labels the results of a scan whose subject is a container image, not
    a tree. The wire spellings (``"source"`` / ``"converted"`` / ``"image"``) are in
    result files, identity
    keys and log lines and never change.

    ``__str__`` returns the value so ``f"{target_type}"`` and ``str(target_type)``
    render ``source`` on every supported interpreter. Without it the rendering of a
    mixed-in ``str`` enum differs across 3.10, 3.11 and 3.12 (``TargetType.SOURCE``
    on some), and scanner modules that interpolate the label into messages and
    paths would change with the interpreter.
    """

    SOURCE = "source"
    CONVERTED = "converted"
    IMAGE = "image"

    def __str__(self) -> str:
        return self.value


class FailureKind(str, Enum):
    """What failed when a converter could not convert an input.

    ``INPUT`` is the file not being one the converter could hand to its tool;
    ``TOOL`` is the tool, or the run, failing. The kind decides who may waive
    the completeness gate: only an ``INPUT`` failure can be accepted by an
    ``ash-unconverted-input`` suppression. Any value this version does not know
    reads as ``TOOL``, the side that is never accepted.
    """

    INPUT = "input"
    TOOL = "tool"


class Disposition(str, Enum):
    """What a report does with one finding.

    The value is the spelling the HTML report and its script compare
    (``data-status``, the finding-scope menu, ``ash-report.js``). The summary's
    JSON keys spell the same words with underscores, so that spelling is derived:
    :attr:`summary_key`. One definition, two named egress spellings; neither wire
    changed when the enum was introduced.

    The menu's ``active`` and ``all`` choices are view scopes over these, not
    dispositions, and stay in the report template.

    ``INFORMATION`` is a result that states no finding: its SARIF kind is
    ``pass``, ``notApplicable`` or ``informational``, its level is ``none`` or not
    stated, and no ``issue_severity`` it declares is above INFO. The reports list
    it under Information, never as a card, so the scope menu has no entry for it.
    The summary writes no key for it: no total counts such a result.
    """

    ACTIONABLE = "actionable"
    SUPPRESSED = "suppressed"
    BELOW_THRESHOLD = "below-threshold"
    POLICY_NOT_GATING = "policy-not-gating"
    INFORMATION = "information"

    @property
    def summary_key(self) -> str:
        """The member's spelling as a key of the report summary."""
        return self.value.replace("-", "_")


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

#: The count field of findings a suppression hides. It is a count bucket beside
#: the five severities, not a sixth severity: it never takes part in the gate.
SUPPRESSED_COUNT_KEY = "suppressed"

#: ``SEVERITY_BUCKETS`` with the ``suppressed`` tally in front, the field order
#: of ``ScannerSeverityCount``.
SEVERITY_COUNT_FIELDS: Tuple[str, ...] = (SUPPRESSED_COUNT_KEY,) + SEVERITY_BUCKETS
