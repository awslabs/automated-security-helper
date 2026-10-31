# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Utility functions for matching findings against suppression rules."""

import bisect
import codecs
import fnmatch
import re
import weakref
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, TypeVar

from automated_security_helper.models.core import (
    PACKAGE_SUPPRESSION_FIELDS,
    AshSuppression,
    IgnorePathWithReason,
    current_date,
    expiration_has_passed,
)
from automated_security_helper.utils.path_matching import (
    _match_form,
    _path_pattern_matches,
    _pattern_components,
    directory_spelling,
    ignore_path_pattern,
)
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanned_tree import (
    TreeInputRefused,
    open_in_scanned_tree,
)
from automated_security_helper.utils.symbol_spans import SymbolResolver

# Regex patterns for inline suppression comments.
# Supported formats (hash-style for Python/Ruby/YAML/Shell):
#   # ash-ignore: RULE-ID [reason]
#   # ash-ignore-next-line: RULE-ID [reason]
# Supported formats (slash-style for JS/TS/Java/C#/Go):
#   // ash-ignore: RULE-ID [reason]
#   // ash-ignore-next-line: RULE-ID [reason]
# The blanks after the marker and after the rule id are spaces and tabs only,
# not ``\s``: ``\s`` matches a carriage return, and under the line-feed-only
# count a lone CR is inside the line, so ``# ash-ignore: R1\r...`` had its
# reason start after the CR (the text of the next CR-line, which ``_reason``
# then could not cut) and ``# ash-ignore:\rR1`` took ``R1`` from the next
# CR-line as its rule id. A directive ends at the CR either way, and the blank
# between the comment marker and the word is the same class: ``#\rash-ignore:``
# is a bare ``#`` on one CR-line and a directive-shaped text on the next, not a
# comment that holds a directive.
_HASH_INLINE_PATTERN = re.compile(
    r"#[ \t]*ash-ignore:[ \t]*(\S+)[ \t]*(.*)?$", re.IGNORECASE
)
_HASH_NEXT_LINE_PATTERN = re.compile(
    r"#[ \t]*ash-ignore-next-line:[ \t]*(\S+)[ \t]*(.*)?$", re.IGNORECASE
)
_SLASH_INLINE_PATTERN = re.compile(
    r"//[ \t]*ash-ignore:[ \t]*(\S+)[ \t]*(.*)?$", re.IGNORECASE
)
_SLASH_NEXT_LINE_PATTERN = re.compile(
    r"//[ \t]*ash-ignore-next-line:[ \t]*(\S+)[ \t]*(.*)?$", re.IGNORECASE
)

_INLINE_PATTERNS = [_HASH_INLINE_PATTERN, _SLASH_INLINE_PATTERN]
_NEXT_LINE_PATTERNS = [_HASH_NEXT_LINE_PATTERN, _SLASH_NEXT_LINE_PATTERN]

# The part of each pattern up to the rule id: where a directive can begin. The
# patterns end in ``(.*)?$``, so one match attempt reads to the end of the line,
# and an attempt per marker inside a string cost the line's length each. A
# marker is found with these, and the full pattern is tried only at a marker
# that lies outside every string (``_search_comment``).
_MARKER_OF = {
    _HASH_INLINE_PATTERN: re.compile(r"#[ \t]*ash-ignore:", re.IGNORECASE),
    _HASH_NEXT_LINE_PATTERN: re.compile(r"#[ \t]*ash-ignore-next-line:", re.IGNORECASE),
    _SLASH_INLINE_PATTERN: re.compile(r"//[ \t]*ash-ignore:", re.IGNORECASE),
    _SLASH_NEXT_LINE_PATTERN: re.compile(
        r"//[ \t]*ash-ignore-next-line:", re.IGNORECASE
    ),
}

# The characters that open and close a quoted string on one line: double, single
# or backtick quotes, a backslash escaping the next character. A quote that never
# closes on its line (an apostrophe in prose, say) is no string, so it hides
# nothing; nor does a quote glued to the word before it (``Bob's``, ``isn't``),
# unless that word is a string prefix (``f"..."``, ``rb'...'``).
_QUOTE_CHARACTERS = ('"', "'", "`")
_STRING_PREFIX_LETTERS = frozenset("rRbBfFuU")


def _is_word_character(character: str) -> bool:
    """What ``\\w`` matches in a ``str`` pattern: a letter, a digit or ``_``."""
    return character.isalnum() or character == "_"


def _opens_a_string(line: str, index: int) -> bool:
    """Whether the quote at ``index`` can open a string.

    A quote glued to the end of a word is an apostrophe, not a delimiter: in
    ``Description: Bob's bucket  # ash-ignore: X logging isn't needed`` (a YAML
    plain scalar with a comment) the two apostrophes once opened and closed a
    "string" that held the marker, and the directive, which the plain search
    found, went unseen with no warning: an existing suppression stopped working.
    So a quote preceded by a word character opens nothing, with one exception:
    the word is a string prefix of one or two letters from ``rRbBfFuU`` (Python's
    ``f"..."``, ``b'...'``, ``rb"..."`` and their spellings), itself at a word
    start, so ``f"# ash-ignore: X"`` is still a string and hides its marker.
    Three or more word characters before the quote, or a letter outside the set,
    is a word (``Bob``, ``isn``, ``it``), never a prefix. The walk back is at most
    three characters, so the check is constant per quote.
    """
    start = index
    while start > 0 and index - start < 3 and _is_word_character(line[start - 1]):
        start -= 1
    prefix = line[start:index]
    if not prefix:
        return True
    return len(prefix) <= 2 and all(c in _STRING_PREFIX_LETTERS for c in prefix)


def _quoted_spans(line: str) -> List[Tuple[int, int]]:
    """The ``[start, end)`` spans of the quoted strings in ``line``, left to right.

    A string opens at a quote character that ``_opens_a_string`` admits and
    closes at the next quote character of the same kind that no odd run of
    backslashes precedes; a quote with no such closer on the line opens nothing,
    and the scan goes on from the next character. That is what the regular
    expression this replaced found (the word-character rule added), but the
    expression was tried afresh at every quote in the line, and each attempt
    from a quote that never closes ran to the end of the line: a line of many
    escaped quotes (a scanned tree holds whatever its author wrote, and under
    the line-feed count a CR-only or minified file is one line) took time
    quadratic in its length. Here the closers of each kind are listed in one
    pass and the opener's scan consumes each one at most once, so the work is
    linear in the line.
    """
    # The positions at which a string of each kind can close: a quote that an
    # even run of backslashes precedes (within the string, a backslash escapes
    # the character after it, and the run cannot reach back past the opener,
    # which is a quote and not a backslash).
    closers: Dict[str, List[int]] = {quote: [] for quote in _QUOTE_CHARACTERS}
    backslashes = 0
    for index, character in enumerate(line):
        if character == "\\":
            backslashes += 1
            continue
        if character in closers and backslashes % 2 == 0:
            closers[character].append(index)
        backslashes = 0
    spans: List[Tuple[int, int]] = []
    next_closer = dict.fromkeys(_QUOTE_CHARACTERS, 0)
    index = 0
    while index < len(line):
        character = line[index]
        if character not in closers or not _opens_a_string(line, index):
            index += 1
            continue
        candidates = closers[character]
        pointer = next_closer[character]
        while pointer < len(candidates) and candidates[pointer] <= index:
            pointer += 1
        next_closer[character] = pointer
        if pointer == len(candidates):
            # No closer of this kind follows: the quote opens nothing.
            index += 1
            continue
        end = candidates[pointer] + 1
        spans.append((index, end))
        index = end
    return spans


def _search_comment(pattern: "re.Pattern[str]", line: str) -> Optional["re.Match[str]"]:
    """The first match of ``pattern`` in ``line`` that begins outside a quoted string.

    Every pattern starts with the comment marker (``#`` or ``//``), so a match
    inside a string literal is text that looks like a directive, not a comment:
    ``x = "# ash-ignore: B101"`` suppresses nothing. A marker inside a string
    never ends the search: the next one, if there is one, is looked at in turn.
    The spans are found once per line (``_quoted_spans``) and each marker is
    placed among them by bisection. Markers are found with the pattern's marker
    alone (``_MARKER_OF``), which stops where the marker does, and the full
    pattern, which reads to the end of the line, is tried only at a marker
    outside every string: a line of many markers inside many strings costs the
    line's length once, not once per marker.
    """
    marker = _MARKER_OF.get(pattern, pattern)
    starts: Optional[List[int]] = None
    ends: List[int] = []
    position = 0
    while True:
        candidate = marker.search(line, position)
        if candidate is None:
            return None
        if starts is None:
            spans = _quoted_spans(line)
            starts = [begin for begin, _ in spans]
            ends = [end for _, end in spans]
        start = candidate.start()
        # The spans are in order and do not overlap, so the only span that can
        # hold ``start`` is the last one that begins at or before it.
        within = bisect.bisect_right(starts, start) - 1
        if within < 0 or start >= ends[within]:
            match = pattern.match(line, start)
            if match is not None:
                return match
        position = start + 1


def _reason(match: "re.Match[str]") -> str:
    """The directive's reason: the text after its rule id, up to the line's end
    or the first carriage return, whichever comes first.

    Lines are split at line feeds alone (``find_inline_suppressions``), so a
    lone CR is inside a line, and the reason group (``(.*)?$``) ran past it: on
    a CR-only file the reason was the rest of the file, and the reason is copied
    into the SARIF justification of every finding the directive suppresses, so
    source text (a secret among it, say) landed in the results. The reason is
    cut at the first CR whatever the line numbering decides about it. The
    patterns' blanks after the rule id are spaces and tabs only, so a CR right
    after the rule id is the first character of the reason group and the cut
    leaves the default reason; with ``\s*`` there the CR was consumed before
    the group began and the next CR-line's text was the reason.
    """
    return (match.group(2) or "").split("\r", 1)[0].strip()


def _decode_source(data: bytes) -> str:
    """``data`` as text: UTF-32 or UTF-16 when it starts with that encoding's byte
    order mark, else UTF-8, with anything undecodable replaced.

    A source file saved as UTF-16 (a Windows editor's "Unicode") read as UTF-8
    is a NUL between every two characters, so no directive in it was ever found.
    A file with no byte order mark is read as UTF-8, as before: its encoding
    cannot be told from its bytes.
    """
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return data.decode("utf-32", errors="replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class InlineSuppression:
    """A suppression directive parsed from an inline source comment."""

    line_number: int
    """The source line that the suppression applies to."""
    rule_id: str
    reason: str


def matches_suppression(
    finding: FlatVulnerability,
    suppression: AshSuppression,
    symbol_resolver: Optional[SymbolResolver] = None,
) -> bool:
    """Thin wrapper around ``AshSuppression.matches`` kept for backward compatibility.

    Prefer ``suppression.matches(finding)`` in new code.
    """
    return suppression.matches(finding, symbol_resolver)


def _rule_id_matches(finding_rule_id: Optional[str], suppression_rule_id: str) -> bool:
    """Check if the finding's rule ID matches the suppression rule ID."""
    if finding_rule_id is None:
        return False

    # Normalize to lowercase for OS-independent case-insensitive matching.
    # fnmatch.fnmatch is case-insensitive on macOS/Windows but case-sensitive
    # on Linux, so we force lowercase on both sides for consistent behavior.
    return fnmatch.fnmatch(finding_rule_id.lower(), suppression_rule_id.lower())


def file_path_matches(
    finding_file_path: Optional[str], suppression_file_path: str
) -> bool:
    """Check if the finding's file path matches the suppression file path pattern.

    Supports ``**`` as a recursive glob that matches zero or more directories,
    e.g. ``tests/**/*.py`` matches both ``tests/test_foo.py`` and
    ``tests/sub/test_bar.py``.

    The matcher ``AshSuppression.matches`` and ``IgnorePathWithReason`` use
    (``path_matching._path_pattern_matches``), so every reader of a pattern gives
    the same answer: case-sensitive, a backslash in the pattern a separator and
    one in the path part of a name, and ``""``, ``.``, ``./`` and ``.\\`` matching
    nothing.

    A pattern containing ``**`` goes to ``_recursive_glob_match``, which matches
    whole path components. Any other goes to ``fnmatchcase``, whose ``*`` is not
    stopped by a separator: ``fnmatch.translate("*")`` is ``(?s:.*)``, so
    ``src/*.py`` also matches ``src/sub/deep/a.py`` and a suppression written that
    way covers subdirectories too.
    """
    return _path_pattern_matches(finding_file_path, suppression_file_path)


def ignore_path_matches(file_path: Optional[str], ignore_path: str) -> bool:
    """Whether ``file_path`` is under the global ignore path ``ignore_path``.

    ``file_path_matches``, with the pattern read as ``path_matching.
    ignore_path_pattern`` reads it: one ending in ``/`` names the directory and
    matches every path below it. Every place ASH matches an ignore path calls this,
    so they agree: dropping findings, the converters, detect-secrets, the
    exclusions the tree-walking scanners are given, and snyk-code's refusal.
    """
    return file_path_matches(file_path, ignore_path_pattern(ignore_path))


def warn_unmatched_directory_suppressions(
    suppressions: Iterable[AshSuppression],
    used_ids: Iterable[str],
    recorded: Optional[Dict[int, Dict[str, Any]]] = None,
    config: Any = None,
) -> None:
    """Warn once for each suppression whose path ends in ``/`` and matched nothing.

    An ignore path ending in ``/`` names a directory; a suppression's path does
    not, and matches only that literal path, which no file has. A suppression
    written ``build/`` therefore suppresses nothing, and the findings it was
    written for are reported. The warning names the glob that suppresses the
    directory's findings, ``build/**/*``: as a suppression path that covers every
    file below the directory and not a file named ``build``, which ``build/**``
    would also cover. Called after the scan's last suppression pass, with the ids
    of the suppressions that pass used.

    A path whose last component is ``**`` (``build/**/``) is not literal: the
    matcher reads the trailing slash after ``**`` as part of it
    (``path_matching._pattern_components``), so it is ``build/**``, which matches
    files, and the warning does not apply to it.

    ``recorded`` is ``recorded_suppressions(config)``. The warning then quotes a
    path the config file read from the environment by its reference, as every
    other message about a suppression does, and never by its value. A caller
    that holds the config passes it as ``config`` instead and the record is
    built here, from the same list it is keyed by: the scan's caller passed
    neither, so a path read from the environment was printed by its value in
    this one warning. The record is keyed by ``id()``, so ``suppressions`` are
    the config's own instances (``config.global_settings.suppressions``), not
    copies; with ``config`` given that is what the record is built from.
    """
    if recorded is None and config is not None:
        recorded = recorded_suppressions(config)
    used = set(used_ids)
    for suppression in suppressions:
        path = getattr(suppression, "path", None) or ""
        if not path.endswith(("/", "\\")) or suppression.id in used:
            continue
        directory = path.rstrip("/\\")
        if not directory:
            continue
        # As the matcher reads it: one slash after a trailing ``**`` is part of
        # it (``build/**/`` is ``build/**``), a second is a component of its own
        # that no path has (``build/**//`` matches nothing and is warned about).
        if _pattern_components(_match_form(path))[-1] == "**":
            continue
        written = (recorded or {}).get(id(suppression), {}).get("path")
        if isinstance(written, str) and written.rstrip("/\\"):
            path = written
            directory = written.rstrip("/\\")
        # A plain message: the log sinks show it, values included, once. Escaping
        # the values for Rich here showed them a second time.
        ASH_LOGGER.warning(
            f"The suppression with path '{path}' matched no finding: "
            "a suppression path ending in '/' matches only that literal path, not "
            "the files in the directory, as an ignore path's does. To suppress the "
            "findings below it, write "
            f"'{directory_spelling(directory, ignore_path=False)}'."
        )


def _line_range_matches(
    finding: FlatVulnerability, suppression: AshSuppression
) -> bool:
    """Check if the finding's line range overlaps with the suppression line range."""
    # If suppression doesn't specify line range, it matches any line
    if suppression.line_start is None and suppression.line_end is None:
        return True

    # If finding doesn't have line information but suppression requires it, no match
    if finding.line_start is None:
        return False

    # If only start line is specified in suppression
    if suppression.line_start is not None and suppression.line_end is None:
        # Open-ended on purpose: a suppression with line_start and no line_end
        # matches every finding from that line to the end of the file, including
        # findings that do not exist yet. It does not mean "just this line".
        #
        # This is the documented contract, not an oversight. The linter used to
        # describe it as defaulting to a single line, which was the reverse of
        # what happens here; the message was corrected rather than this
        # comparison, because narrowing it would stop existing single-line
        # suppressions from covering the range they cover today. Tests in
        # tests/unit/config/test_open_ended_suppression_range.py pin it.
        #
        # Match if finding overlaps with the suppression start line:
        # either the finding starts at/after suppression start, or the
        # finding spans across the suppression start (multi-line finding).
        finding_end = (
            finding.line_end if finding.line_end is not None else finding.line_start
        )
        return finding_end >= suppression.line_start

    # If only end line is specified in suppression
    if suppression.line_start is None and suppression.line_end is not None:
        # Match if finding ends at or before the suppression end line
        finding_end = (
            finding.line_end if finding.line_end is not None else finding.line_start
        )
        return finding_end <= suppression.line_end

    # Both start and end lines are specified in suppression
    finding_start = finding.line_start
    finding_end = (
        finding.line_end if finding.line_end is not None else finding.line_start
    )

    # Check if the finding's line range overlaps with the suppression's line range
    return (finding_start <= (suppression.line_end or 0)) and (
        finding_end >= (suppression.line_start or 0)
    )


def should_suppress_finding(
    finding: FlatVulnerability,
    suppressions: List[AshSuppression],
    symbol_resolver: Optional[SymbolResolver] = None,
    where: str = "global_settings.suppressions",
) -> Tuple[bool, Optional[AshSuppression]]:
    """
    Determine if a finding should be suppressed based on the suppression rules.

    Args:
        finding: The finding to check
        suppressions: List of suppression rules to check against
        symbol_resolver: Resolves ``symbol`` on a suppression to source spans.
            Without it, a suppression that sets ``symbol`` matches nothing.
        where: The list's location, which names an entry in a message
            (_has_expired).

    Returns:
        A tuple of (should_suppress, matching_suppression)
    """
    for index, suppression in enumerate(suppressions):
        location = f"{where}[{index}]"
        if _has_expired(suppression, location) or _has_unknown_keys(
            suppression, location
        ):
            continue

        if matches_suppression(finding, suppression, symbol_resolver):
            return True, suppression

    return False, None


#: The entries _has_expired has warned about, by ``id()``. Weak, so the id a
#: collected entry leaves behind is never read as a later entry's.
_WARNED_UNREADABLE_EXPIRATION: "weakref.WeakValueDictionary[int, Any]" = (
    weakref.WeakValueDictionary()
)


def _has_expired(entry: IgnorePathWithReason, where: str) -> bool:
    """Whether ``entry`` no longer applies because its ``expiration`` has passed.

    The one rule for suppressions and ignore paths alike. ``expiration`` is a
    YYYY-MM-DD date compared with ``current_date()``, the host's local date, and
    the entry stops applying at the start of that day: on the expiration date
    itself it is already expired.

    A date that does not parse counts as expired, with a warning. A config file
    with one is refused when it loads, but a configuration kept from a results
    file keeps the date as written (utils/unknown_keys.py), and ``ash merge``
    applies that configuration to the shards' findings. For such an entry the
    safe reading is that it does not apply: an unapplied ignore path means more
    is scanned, not less.

    The messages name the entry by ``where``, its location, and not by its
    values: the date and the path are the file's data, and either can be a
    value read from the environment where the scan ran.

    Args:
        entry: The suppression or ignore path.
        where: Its location, such as ``global_settings.ignore_paths[0]``.
    """
    if not entry.expiration:
        return False
    try:
        expired = expiration_has_passed(entry.expiration)
    except ValueError:
        # Once for an entry: should_suppress_finding asks about every entry for
        # every finding, so a warning per call wrote one line per finding for one
        # bad date. An entry of a configuration loaded again is a new object and
        # is warned about again.
        if _WARNED_UNREADABLE_EXPIRATION.get(id(entry)) is not entry:
            try:
                _WARNED_UNREADABLE_EXPIRATION[id(entry)] = entry
            except TypeError:
                pass  # not weak-referenceable: warned about on every call
            ASH_LOGGER.warning(
                f"Invalid expiration date format for {where}. Use YYYY-MM-DD; "
                "the entry is not applied."
            )
        return True
    if expired:
        ASH_LOGGER.debug(f"{where} has expired")
    return expired


def _has_unknown_keys(entry: IgnorePathWithReason, where: str) -> bool:
    """Whether ``entry`` came from a results file with a key it does not declare.

    A config file with such a key is refused when it loads, so only an entry
    kept from a stored config (utils/unknown_keys.py) gets here. It is never
    applied; the warning was logged when the results were loaded. Named by
    ``where``, its location, as in _has_expired.
    """
    if entry.has_unknown_keys:
        ASH_LOGGER.debug(
            f"Not applying {where}: it has keys this version of ASH does not know"
        )
        return True
    return False


#: The rule_id of a suppression that accepts an input a converter could not
#: convert (a FailedInputInfo whose kind is "input").
UNCONVERTED_INPUT_RULE = "ash-unconverted-input"


def accepting_unconverted_input(
    path: str,
    suppressions: Optional[Sequence[AshSuppression]],
    where: str = "global_settings.suppressions",
) -> Optional[AshSuppression]:
    """The suppression that accepts ``path`` as an unconverted input, or None.

    An entry accepts when its ``rule_id`` is :data:`UNCONVERTED_INPUT_RULE`
    exactly (case-insensitive; a glob written for finding suppressions grants
    nothing here, because this acceptance waives scan coverage rather than one
    finding) and its ``path`` pattern matches, read as
    ``AshSuppression.matches_path`` reads it. Only ``path``, ``reason`` and
    ``expiration`` take part: an expired entry, or one kept from a results file
    with unknown keys, accepts nothing (_has_expired, _has_unknown_keys).

    Only the operator's entries accept. An entry a delivered tree's own config
    or a workspace policy file supplied (``client_supplied``) is left to the
    finding step, where it marks results suppressed and the results show what
    the client's config hid; it never waives scan coverage, as a client-supplied
    ignore path never skips scanning (``ignore_paths_that_skip_scanning``).
    Without this a tree could carry a suppression that waives the completeness
    gate for an archive or notebook the tree itself made unreadable.

    Consulted only for an input error, the record of a file that is not one the
    converter could hand to its tool. A tool failure never reaches this, so a
    broken tool cannot be suppressed into a complete scan.
    """
    for index, suppression in enumerate(suppressions or []):
        rule_id = suppression.rule_id
        if rule_id is None or rule_id.lower() != UNCONVERTED_INPUT_RULE:
            continue
        # Read with getattr: a record built outside this model carries no flag.
        if getattr(suppression, "client_supplied", False) is True:
            continue
        location = f"{where}[{index}]"
        if _has_expired(suppression, location) or _has_unknown_keys(
            suppression, location
        ):
            continue
        if suppression.matches_path(path):
            return suppression
    return None


def active_ignore_paths(
    ignore_paths: Optional[Sequence[IgnorePathWithReason]],
    where: str = "global_settings.ignore_paths",
) -> List[IgnorePathWithReason]:
    """The entries of ``ignore_paths`` that still apply today.

    Every place that applies a list of ignore-path entries filters it through
    this first: for ``global_settings.ignore_paths``, the list the orchestrator
    hands the scanners, the archive and Jupyter converters, and the SARIF step
    that drops findings after the scan; and the scanner options of the same type
    (bandit ``excluded_paths``, checkov ``skip_path``, syft ``exclude``) where
    they become tool arguments. The config itself keeps every entry, so the
    aggregated results still report an expired one; only its effect stops.

    ``where`` is the list's location, which names an entry in a message
    (_has_expired): pass it for a list other than ``global_settings.ignore_paths``.
    """
    return [
        entry
        for index, entry in enumerate(ignore_paths or [])
        if not _has_expired(entry, f"{where}[{index}]")
        and not _has_unknown_keys(entry, f"{where}[{index}]")
    ]


_Entry = TypeVar("_Entry", bound=IgnorePathWithReason)


def _expiring_within(
    entries: Sequence[_Entry], days_threshold: int, where: str
) -> List[_Entry]:
    """Entries whose expiration is today or within ``days_threshold`` days.

    One whose date does not parse is named by its location in ``where``, the
    list's location, as in _has_expired. One kept from a results file with a key
    it does not declare is left out: it is never applied (_has_unknown_keys), so
    it does not expire.
    """
    expiring = []
    today = current_date()

    for index, entry in enumerate(entries):
        # ``is True``: a record built outside the model carries no such flag.
        if getattr(entry, "has_unknown_keys", False) is True:
            continue
        if entry.expiration:
            try:
                expiration_date = datetime.strptime(entry.expiration, "%Y-%m-%d").date()
                days_until_expiration = (expiration_date - today).days

                if 0 <= days_until_expiration <= days_threshold:
                    expiring.append(entry)
            except ValueError:
                ASH_LOGGER.warning(
                    f"Invalid expiration date format for {where}[{index}]. "
                    "Use YYYY-MM-DD."
                )

    return expiring


#: The fields of a suppression that the reports and warnings quoting it show.
SHOWN_SUPPRESSION_FIELDS = (
    "path",
    "rule_id",
    "line_start",
    "line_end",
    "reason",
    "expiration",
    *PACKAGE_SUPPRESSION_FIELDS,
    "symbol",
)


def recorded_suppressions(config: Any) -> Dict[int, Dict[str, Any]]:
    """Each of ``config``'s suppressions, keyed by its ``id()``, as a dict of its
    shown fields (``SHOWN_SUPPRESSION_FIELDS``) in which each field the config
    file read from the environment is the reference as the file wrote it
    (``${VAR}``, ``!ENV`` and any text after the reference included). The
    rewrite is value-based: a literal field whose text happens to equal an
    environment-read value is recorded as the reference too, not as the
    literal the file wrote at that spot.

    What quotes a suppression's fields (its SARIF justification, which the results
    file and every report carry, the unused-suppressions report, the expiry
    warning) quotes one read from the environment by its reference, as the results
    file's ``ash_config`` records it, and never the value. The suppressions are the
    config's ``global_settings.suppressions``, where its record places the
    references.
    """
    settings = getattr(config, "global_settings", None)
    suppressions = list(getattr(settings, "suppressions", None) or [])
    if not suppressions:
        return {}
    shown: List[Dict[str, Any]] = [
        {name: getattr(s, name, None) for name in SHOWN_SUPPRESSION_FIELDS}
        for s in suppressions
    ]
    references = getattr(config, "_environment_references", ()) or ()
    if references:
        from automated_security_helper.config.environment_record import (
            record_environment_references,
        )

        shown = record_environment_references(
            shown, references, at=("global_settings", "suppressions")
        )
    return {id(s): entry for s, entry in zip(suppressions, shown)}


def written_suppression_reasons(
    config: Any, recorded: Optional[Dict[int, Dict[str, Any]]] = None
) -> Dict[int, str]:
    """The reason of each of ``config``'s suppressions that its config file read
    from the environment, as the file wrote it, keyed by the suppression's
    ``id()`` (``recorded_suppressions``). A caller that already holds
    ``recorded_suppressions(config)`` passes it as ``recorded``, so the
    environment record is not built a second time."""
    settings = getattr(config, "global_settings", None)
    suppressions = list(getattr(settings, "suppressions", None) or [])
    if recorded is None:
        recorded = recorded_suppressions(config)
    return {
        id(s): recorded[id(s)]["reason"]
        for s in suppressions
        if isinstance(recorded[id(s)].get("reason"), str)
        and recorded[id(s)]["reason"] != getattr(s, "reason", None)
    }


def written_suppression_id(
    suppression: AshSuppression, recorded: Dict[int, Dict[str, Any]]
) -> str:
    """``suppression``'s id over its written form: each field the config file
    read from the environment is the reference as the file wrote it
    (``recorded_suppressions``). ``used_suppressions`` records this id, so the
    results file names a used entry the way its own config record does and
    never by a resolved value. The written form's id is one of the ids the
    unused-suppressions check matches a report entry by
    (``ConfigLinter._suppression_ids``).

    The two forms share one text namespace, so this reduces collisions rather
    than ruling them out: an entry the file writes as quoted text that only
    looks like a reference (``path: '${VAR}'``) has that text as its id, the
    same id an env-read ``path: ${VAR}`` entry is recorded by, and a use of
    either reads as a use of both."""
    written = (recorded or {}).get(id(suppression))
    if not written:
        return suppression.id
    changed = {
        name: value
        for name, value in written.items()
        if value != getattr(suppression, name, None)
    }
    if not changed:
        return suppression.id
    return suppression.model_copy(update=changed).id


#: The fields of an ignore path that the warnings naming it show.
SHOWN_IGNORE_PATH_FIELDS = ("path", "reason", "expiration")


def recorded_ignore_paths(
    config: Any, entries: Sequence[Any], at: Sequence[str]
) -> Dict[int, Dict[str, Any]]:
    """Each of ``entries``, the ignore paths at ``at`` in ``config`` (its global
    ``ignore_paths``, or a scanner option that takes the same entries), keyed by
    its ``id()``, as a dict of its shown fields (``SHOWN_IGNORE_PATH_FIELDS``) in
    which each field the config file read from the environment is the reference
    as the file wrote it, as ``recorded_suppressions`` gives a suppression's."""
    entries = list(entries or [])
    if not entries:
        return {}
    shown: List[Dict[str, Any]] = [
        {name: getattr(entry, name, None) for name in SHOWN_IGNORE_PATH_FIELDS}
        for entry in entries
    ]
    references = getattr(config, "_environment_references", ()) or ()
    if references:
        from automated_security_helper.config.environment_record import (
            record_environment_references,
        )

        shown = record_environment_references(shown, references, at=tuple(at))
    return {id(entry): fields for entry, fields in zip(entries, shown)}


def check_for_expiring_suppressions(
    suppressions: List[AshSuppression],
    days_threshold: int = 30,
    where: str = "global_settings.suppressions",
) -> List[AshSuppression]:
    """
    Check for suppressions that will expire within the specified number of days.

    Args:
        suppressions: List of suppression rules to check
        days_threshold: Number of days threshold for warning
        where: The list's location, which names an entry in a message.

    Returns:
        List of suppressions that will expire within the threshold
    """
    return _expiring_within(suppressions, days_threshold, where)


def check_for_expiring_ignore_paths(
    ignore_paths: List[IgnorePathWithReason],
    days_threshold: int = 30,
    where: str = "global_settings.ignore_paths",
) -> List[IgnorePathWithReason]:
    """The ignore paths that will expire within ``days_threshold`` days.

    The same window ``check_for_expiring_suppressions`` uses, so the scan-start
    warning gives an ignore path the same notice a suppression gets. ``where``
    is the list's location, which names an entry in a message.
    """
    return _expiring_within(ignore_paths, days_threshold, where)


def find_inline_suppressions(
    file_path: Path, scan_root: Optional[Path] = None
) -> List[InlineSuppression]:
    """Scan a source file for inline suppression comments.

    Recognised directives (both ``#`` and ``//`` comment styles):

    * ``# ash-ignore: <rule-id> [reason]``  --  suppresses same line.
    * ``# ash-ignore-next-line: <rule-id> [reason]``  --  suppresses next line.
    * ``// ash-ignore: <rule-id> [reason]``  --  same (JS/TS/Java/C#/Go).
    * ``// ash-ignore-next-line: <rule-id> [reason]``  --  same.

    A directive is a comment: the marker must begin outside a quoted string on
    its line, so ``x = "# ash-ignore: B101"`` suppresses nothing. A file that
    starts with a UTF-16 or UTF-32 byte order mark is read in that encoding, any
    other as UTF-8.

    Lines are counted by line feed, as a scanner's SARIF ``startLine`` counts
    them (a CRLF file's carriage return belongs to the line before it; a lone
    CR is not a line break). That is the contract for a file with no line feed
    at all (classic Mac CR-only line endings): it is one line here, so at most
    one directive is found, the first on the line, it names line 1 (line 2 for
    ``ash-ignore-next-line``), and its reason runs to the end of the file, the
    rest of that one line; a scanner that numbers such a file by CR reports
    lines these directives never match.

    Args:
        file_path: Path to the source file to scan.
        scan_root: The scanned tree. When given, the file is read under the
            scanned-tree rule (``utils/scanned_tree.py``): a reason found here is
            copied into the SARIF justification, so a link must not make it read a
            file outside the tree. A link whose target is inside the tree is
            followed, because the finding was reported under the link's path and
            the file behind it is tree content. A refused file has no inline
            suppressions.

    Returns:
        List of ``InlineSuppression`` instances, one per directive found.
    """
    suppressions: List[InlineSuppression] = []
    try:
        # Both paths read the bytes as they are, so the two number lines the
        # same way (read_text's universal newlines would have folded CR and
        # CRLF on one path only).
        if scan_root is None:
            data = file_path.read_bytes()
        else:
            with open_in_scanned_tree(
                file_path, scan_root, follow_links_inside=True
            ) as handle:
                data = handle.read()
        text = _decode_source(data)
    except TreeInputRefused as refused:
        ASH_LOGGER.warning(
            f"Inline suppressions in '{refused.path}' were not read: {refused.reason}"
        )
        return suppressions
    except (OSError, ValueError) as exc:
        # ValueError covers UnicodeDecodeError, and the two refusals the OS
        # layer gives a path before opening it: an embedded NUL, and a lone
        # surrogate the file-system encoding cannot encode (UnicodeEncodeError).
        # Either is one unreadable file, not a reason to drop every other
        # file's suppressions with it.
        ASH_LOGGER.debug(f"Could not read {file_path} for inline suppressions: {exc}")
        return suppressions

    # Lines are counted as a scanner's SARIF startLine counts them: by line
    # feed, with a CRLF file's carriage return belonging to the line before
    # it. A lone CR is not a line break here (the scanners whose results these
    # suppressions match are not all Python, and they count LF), and neither
    # is anything str.splitlines would also break at (a form feed, a vertical
    # tab, NEL, LINE SEPARATOR, PARAGRAPH SEPARATOR, the \x1c-\x1e
    # separators), which once attached every later directive to a line number
    # the SARIF results never carry.
    text = text.replace("\r\n", "\n")
    for line_num_0, line in enumerate(text.split("\n")):
        line_num = line_num_0 + 1  # 1-based

        matched = False
        for pattern in _INLINE_PATTERNS:
            match = _search_comment(pattern, line)
            if match:
                rule_id = match.group(1)
                reason = _reason(match)
                suppressions.append(
                    InlineSuppression(
                        line_number=line_num,
                        rule_id=rule_id,
                        reason=reason or "Inline suppression",
                    )
                )
                matched = True
                break
        if matched:
            continue

        for pattern in _NEXT_LINE_PATTERNS:
            match = _search_comment(pattern, line)
            if match:
                rule_id = match.group(1)
                reason = _reason(match)
                suppressions.append(
                    InlineSuppression(
                        line_number=line_num + 1,
                        rule_id=rule_id,
                        reason=reason or "Inline suppression (next-line)",
                    )
                )
                break

    return suppressions
