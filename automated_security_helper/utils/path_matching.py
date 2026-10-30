# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Glob-based path matching utilities supporting ``**`` recursive patterns."""

import fnmatch
import re
from functools import lru_cache
from typing import List, Optional

from automated_security_helper.utils.undecodable_text import (
    _RECORDED_ESCAPE,
    text_of_undecodable,
    undecodable_of_text,
)

_DOUBLE_STAR = "**"


def _pattern_components(pattern: str) -> List[str]:
    """Split *pattern* into path components, normalizing the ``**`` forms.

    * ``**`` alone in a component means zero or more whole path components.
    * ``**`` inside a longer component (``foo**``, ``**.py``) is an ordinary
      ``*``, the rule gitignore uses. The matcher this replaced split the
      pattern on every ``**``, so ``src/**.py`` matched only a file literally
      named ``.py``.
    * Repeated ``**`` components collapse to one: ``a/**/**/b`` is ``a/**/b``.
    * A slash next to a leading or trailing ``**`` is absorbed, so ``/**/x``
      is ``**/x`` and ``tests/**/`` is ``tests/**``. That is what the previous
      splitter did with its ``/?\\*\\*/?`` separator, kept so that no existing
      ignore path or suppression changes meaning.
    """
    components: List[str] = []
    for component in pattern.split("/"):
        if _DOUBLE_STAR in component and component != _DOUBLE_STAR:
            component = re.sub(r"\*{2,}", "*", component)
        if component == _DOUBLE_STAR and components and components[-1] == _DOUBLE_STAR:
            continue
        components.append(component)
    if len(components) >= 2 and components[0] == "" and components[1] == _DOUBLE_STAR:
        components.pop(0)
    while (
        len(components) >= 2 and components[-1] == "" and components[-2] == _DOUBLE_STAR
    ):
        components.pop()
    return components


def _recursive_glob_match(path: str, pattern: str, *, record_form: bool = True) -> bool:
    """Match *path* against *pattern* treating ``**`` as zero-or-more directories.

    Both sides are split into ``/``-separated components. A ``**`` component
    matches any run of path components, including none; every other pattern
    component must match exactly one path component, with ``fnmatch`` deciding
    the match. So the whole path is consumed, anchored at both ends, and a
    ``**`` can sit anywhere: first, last, or between other components, any
    number of times.

    Why a component matcher rather than the segment splitter it replaced
    --------------------------------------------------------------------
    The old algorithm split the pattern on ``**`` and then special-cased the
    single-segment shapes. With two or more segments it ignored a ``**`` at
    either end: the last segment was always anchored to the end of the path and
    the first to the start. So ``a/**/b/**`` did not match ``a/x/b/c``,
    ``tests/**/__snapshots__/**`` matched nothing under a snapshot directory,
    and ``**/x/**/y`` did not match ``p/x/q/y``. Ignore paths and suppressions
    written that way were silently inert, which for a suppression means the
    findings it was written for stay reported, and for an ignore path means
    the directory stays scanned.

    Matching a whole pattern component against a whole path component gives
    the same answer the old code gave for every shape it handled correctly:
    it compared a pattern segment of N components against N path components
    joined with ``/``, and with the slash counts equal a ``*`` in the segment
    could not span a slash and still leave enough literal slashes to match.

    Components are compared with ``fnmatchcase``, case-sensitively and without
    ``fnmatch.fnmatch``'s platform case folding, so the answer is the same on
    every platform. A backslash in the pattern is a separator; one in the path is
    part of a name,
    as it is on POSIX, so the path is split on ``/`` alone (see ``_match_form``).

    Each component is compared in the record form (see ``_path_pattern_matches``),
    the pattern's after its separators are read, so the escape's backslash stays part
    of the name. With ``record_form=False`` each is compared as the name itself
    instead (the raw side of ``_path_pattern_matches``): *path* and *pattern* then
    hold each lone surrogate as its one character, so a glob character stands for
    the byte, not for a character of its six-character spelling.
    """
    form = text_of_undecodable if record_form else str
    path_parts = tuple(form(part) for part in path.split("/"))
    pattern_parts = tuple(
        form(part) for part in _pattern_components(pattern.replace("\\", "/"))
    )

    @lru_cache(maxsize=None)
    def match(pattern_index: int, path_index: int) -> bool:
        if pattern_index == len(pattern_parts):
            return path_index == len(path_parts)
        component = pattern_parts[pattern_index]
        if component == _DOUBLE_STAR:
            return any(
                match(pattern_index + 1, next_path_index)
                for next_path_index in range(path_index, len(path_parts) + 1)
            )
        if path_index == len(path_parts):
            return False
        return fnmatch.fnmatchcase(path_parts[path_index], component) and match(
            pattern_index + 1, path_index + 1
        )

    return match(0, 0)


def _match_form(pattern: str) -> str:
    """One spelling of an ignore path or suppression pattern on every platform.

    With backslashes as forward slashes. The same config is read on Windows and
    POSIX, and a config author may write either separator, so a backslash in a
    pattern is a separator everywhere. Python's ``fnmatch`` has no escape
    character, so no backslash in a pattern was an escape to begin with. Case is
    kept: on a case-sensitive filesystem ``TESTS/`` and ``tests/`` are two
    directories, and the repository's author names them.

    For the pattern only. The path is compared as given: on POSIX a backslash is
    an ordinary filename character, so a file named ``tests\\other.py`` is at the
    top of the tree, and reading its backslash as a separator put it under a
    ``tests/**`` ignore path. ASH hands these matchers ``/``-joined paths on
    every platform.

    A surrogate's escape, ``\\udcNN`` for a file name byte that is not UTF-8 or
    another ``\\uXXXX`` from ``\\ud800`` to ``\\udfff``, is the record form a report
    shows such a name in (utils/undecodable_text.py), so it is read as that
    character before the separators are, and its backslash is not one. The cost: a
    separator directly before a component spelled ``ud800`` to ``udfff`` and more
    is read as such an escape, so that component is written after a ``/``.
    """
    return undecodable_of_text(pattern).replace("\\", "/")


#: Patterns, in their :func:`_match_form`, that name no path: ``""``, ``"."``,
#: ``"./"`` and ``".\\"``. As an ignore path ``./`` read as the directory ``.``
#: matched every ``./``-prefixed path, so the whole tree, and ``.`` and ``""``
#: matched only a path spelled the same, which names no file.
_PATTERNS_NAMING_NO_PATH = frozenset({"", ".", "./"})


def names_no_path(pattern: str) -> bool:
    """Whether *pattern* is ``""``, ``"."``, ``"./"`` or ``".\\"``, which match no path.

    Every reader of an ignore path or a suppression pattern treats these the same
    way: :func:`_path_pattern_matches` matches nothing with them, and
    :func:`ignore_path_pattern` leaves them as they are.
    """
    return _match_form(pattern) in _PATTERNS_NAMING_NO_PATH


def _class_holds_surrogate(pattern: str) -> bool:
    """Whether a bracket expression in *pattern* holds a lone surrogate.

    The brackets are found as ``fnmatch`` finds them: ``[``, an optional ``!``, an
    optional first ``]`` that is a member, then everything up to the next ``]``; a
    ``[`` with no such end is an ordinary character. A surrogate there stands for one
    file name byte that is not UTF-8. Compared in the record form, the class holds
    the six characters of the byte's escape instead, so it also names ``\\``, ``u``,
    ``d``, ``c``, ``e`` and the digits (see :func:`_path_pattern_matches`).
    """
    length = len(pattern)
    index = 0
    while index < length:
        if pattern[index] != "[":
            index += 1
            continue
        end = index + 1
        if end < length and pattern[end] == "!":
            end += 1
        if end < length and pattern[end] == "]":
            end += 1
        while end < length and pattern[end] != "]":
            end += 1
        if end >= length:
            index += 1
            continue
        if any("\ud800" <= char <= "\udfff" for char in pattern[index:end]):
            return True
        index = end + 1
    return False


def _path_pattern_matches(file_path: Optional[str], pattern: str) -> bool:
    """Case-sensitive path match supporting ``**`` recursive globs.

    Gives the same answer on every platform. ``fnmatch.fnmatch`` does not: it
    runs both sides through ``os.path.normcase``, which on Windows lowercases them
    and turns ``/`` into ``\\``, and on POSIX does nothing. So the pattern is put
    in :func:`_match_form`, the path is taken as given, and the two are compared
    with ``fnmatchcase``, which skips normcase. ``TESTS/x.py`` is not below
    ``tests/``. A pattern :func:`names_no_path` matches nothing.
    """
    if file_path is None or names_no_path(pattern):
        return False

    # A result holds a file name that is not UTF-8 in its record form (each lone
    # surrogate as \udcNN, utils/undecodable_text.py), while the scan set and a
    # pattern given as text may hold the surrogate itself. The pattern is matched
    # against the name as the report shows it and as the name itself: both sides in
    # the record form, and both sides with each escape read back as its surrogate.
    # So a pattern gives one answer for the file a scanner is handed and for the
    # finding it reports, and it can spell the name as the report shows it
    # (secr\udce9t.py), with the byte itself, with ? for the one byte (secr?t.py),
    # with ? for the escape's backslash (secr?udce9t.py) or as a glob. The raw side
    # is tried only when the name holds a surrogate or its escape; for any other
    # name the two forms are the same text, so nothing changes for it.
    #
    # A bracket expression holding a surrogate is matched against the name itself
    # only. In the record form it holds the surrogate's six characters, so
    # ``secr[<surrogate>]t.py`` read there also names ``secrdt.py`` and ``secrut.py``.
    finding_raw = undecodable_of_text(file_path)
    finding_norm = text_of_undecodable(finding_raw)
    pattern_form = _match_form(pattern)
    pattern_norm = text_of_undecodable(pattern_form)
    record_form_reads_it_wider = _class_holds_surrogate(pattern_form)

    # The exact text matches whatever it holds. A pattern with glob characters in it
    # also matches the file named exactly like it, on purpose: a suppression written
    # with the file's own name keeps matching it when that name holds ``[``, ``]``,
    # ``*`` or ``?`` (a framework's ``app/[id]/page.tsx``). The same pattern is still
    # a glob, so it names the files its classes name as well; ``literal_path_pattern``
    # is how a pattern is made to name one file only.
    if finding_norm == pattern_norm:
        return True

    if "**" in pattern_norm:
        if not record_form_reads_it_wider and _recursive_glob_match(
            finding_norm, pattern_form
        ):
            return True
        return (
            record_form_reads_it_wider or finding_raw != finding_norm
        ) and _recursive_glob_match(finding_raw, pattern_form, record_form=False)

    if not record_form_reads_it_wider and fnmatch.fnmatchcase(
        finding_norm, pattern_norm
    ):
        return True
    # The name itself is tried when it holds a surrogate or its escape, and always
    # for a pattern whose class holds a surrogate: that pattern was not tried in the
    # record form above, so for an ordinary name this is its only match.
    return (
        record_form_reads_it_wider or finding_raw != finding_norm
    ) and fnmatch.fnmatchcase(finding_raw, pattern_form)


def ignore_path_pattern(pattern: str) -> str:
    """The pattern a global ignore path's ``path`` is matched as.

    One ending in ``/`` (or ``\\``) names a directory and ignores what is inside
    it, so ``vendor/`` is matched as ``vendor/*/**``. A file's path never ends in a
    slash, so before this ``vendor/`` matched nothing, though it is how a
    ``.gitignore`` names a directory. Anchored like every ignore path: ``vendor/``
    is the top-level directory, and ``**/vendor/`` one at any depth. A pattern that
    is only slashes is left alone, so ``/`` keeps matching nothing instead of
    becoming ``**``; any other pattern is returned as it is.

    Not ``vendor/**``: a trailing ``**`` also matches no component at all, so
    that form covers a FILE named ``vendor`` as well, and ``**/.*/`` covered
    every dotfile (``.env``, ``app/config/.npmrc``), which the detect-secrets
    pre-filter then stopped scanning. The ``*`` requires one component below
    the directory.

    For ignore paths only. A suppression's path ending in ``/`` keeps its literal
    meaning, which matches no file (see
    ``suppression_matcher.warn_unmatched_directory_suppressions``).

    ``./`` and ``.\\`` are not read as the directory ``.``, which would be every
    ``./``-prefixed path: like ``.`` and ``""`` they name no path
    (:func:`names_no_path`) and are returned as they are. So is a spelling with
    more trailing separators, ``.//`` or ``.\\\\``: the directory is what is
    left once they come off, and ``.`` names no path either. Checked after the
    strip, because checked before it ``.//`` was not one of the spellings
    :func:`names_no_path` knows and became ``./*/**``, every path.
    """
    if pattern.endswith(("/", "\\")):
        directory = pattern.rstrip("/\\")
        if directory and not names_no_path(directory):
            return f"{directory}/*/{_DOUBLE_STAR}"
    return pattern


#: A character of a path that is glob syntax in a pattern, as a class matching it.
_LITERAL_CLASSES = {"[": "[[]", "*": "[*]", "?": "[?]"}


class PathNotExpressible(ValueError):
    """A path no pattern names on its own: one holding a backslash."""


def literal_path_pattern(path: str) -> str:
    """A pattern that matches ``path`` itself and no other path, for a suppression
    naming one file.

    ``[``, ``*`` and ``?`` in the path are glob syntax in a pattern, so each is
    written as a class holding only itself: ``x[1].py`` as a pattern matched
    ``x1.py`` as well as ``x[1].py`` (the exact text always matches,
    :func:`_path_pattern_matches`), so a suppression for the one hid the findings
    of the other. A path with none of these comes back as it is.

    A backslash is part of a name in a path and a separator in a pattern, a
    class's included (:func:`_match_form`), so no pattern spells it. A class
    that admits it, ``[!/]``, admits every other character but ``/`` there too,
    and a suppression written with one hides the findings of other files. A path
    holding one raises :class:`PathNotExpressible`.

    One backslash a pattern does spell: the one starting a surrogate's record
    form, ``\\udcNN`` for a file name byte that is not UTF-8
    (utils/undecodable_text.py), which :func:`_match_form` reads as the escape,
    not as a separator. A path holding the surrogate itself, or its record form,
    gives a pattern spelling the record form, which is how a report shows the
    name, and that pattern matches the file.
    """
    recorded = text_of_undecodable(undecodable_of_text(path))
    if "\\" in _RECORDED_ESCAPE.sub("", recorded):
        raise PathNotExpressible(
            f'"{path}" holds a backslash, which a suppression\'s path reads as a '
            "separator, so no suppression path names this file alone"
        )
    pattern: List[str] = []
    index = 0
    for match in _RECORDED_ESCAPE.finditer(recorded):
        pattern.extend(
            _LITERAL_CLASSES.get(char, char) for char in recorded[index : match.start()]
        )
        pattern.append(match.group(0))
        index = match.end()
    pattern.extend(_LITERAL_CLASSES.get(char, char) for char in recorded[index:])
    return "".join(pattern)


def directory_spelling(directory: str, *, ignore_path: bool) -> str:
    """How to write "every file inside ``directory``", for advice ASH prints.

    One spelling for one meaning, so the config lint, ``ash config validate`` and
    the warning after the scan agree. For an ignore path, ``<dir>/``, which
    ``ignore_path_pattern`` reads as what is inside the directory. For a
    suppression path, whose trailing slash is literal, ``<dir>/**/*``: every file
    below the directory and not a path named exactly ``<dir>``, which ``<dir>/**``
    would also match.

    A directory that is only separators (``/``, ``\\``) has no spelling here: ``""``
    is returned, which a caller reads as "no advice to give". It was ``/`` for an
    ignore path, which matches nothing, and ``/**/*`` for a suppression path, which
    matches every file, so the two meanings of one input disagreed.
    """
    directory = directory.rstrip("/\\")
    if not directory:
        return ""
    return f"{directory}/" if ignore_path else f"{directory}/**/*"


def match_glob(path: str, pattern: str) -> bool:
    """Public entry point: case-sensitive glob match with ``**`` support."""
    return _path_pattern_matches(path, pattern)
