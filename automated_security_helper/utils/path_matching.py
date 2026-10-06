# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Glob-based path matching utilities supporting ``**`` recursive patterns."""

import fnmatch
import re
from functools import lru_cache
from typing import List, Optional

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


def _recursive_glob_match(path: str, pattern: str) -> bool:
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

    Callers lower-case both sides first (see ``_match_form`` and
    ``suppression_matcher.file_path_matches``), so ``fnmatch.fnmatch``'s
    platform case folding has nothing left to change. Backslashes are treated
    as separators on both sides.
    """
    path_parts = tuple(path.replace("\\", "/").split("/"))
    pattern_parts = tuple(_pattern_components(pattern.replace("\\", "/")))

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
        return fnmatch.fnmatch(path_parts[path_index], component) and match(
            pattern_index + 1, path_index + 1
        )

    return match(0, 0)


def _match_form(value: str) -> str:
    """One spelling of a path or pattern for comparison on every platform.

    Lowercased, and with backslashes as forward slashes. The same suppression
    file is read on Windows and POSIX, and a config author may write either
    separator, so a backslash in a suppression path or pattern is treated as a
    separator everywhere. Applied to both sides, so it can never make a path
    and a pattern that were equal compare unequal.
    """
    return value.lower().replace("\\", "/")


def _path_pattern_matches(file_path: Optional[str], pattern: str) -> bool:
    """Case-insensitive path match supporting ``**`` recursive globs.

    Gives the same answer on every platform. ``fnmatch.fnmatch`` does not: it
    runs both sides through ``os.path.normcase``, which on Windows turns ``/``
    into ``\\`` and on POSIX does nothing, so ``deploy\\cdk\\x`` matched
    ``deploy/cdk/x`` on Windows and not on Linux. Both sides are put in
    :func:`_match_form` and compared with ``fnmatchcase``, which skips normcase.
    """
    if file_path is None:
        return False

    finding_norm = _match_form(file_path)
    pattern_norm = _match_form(pattern)

    if finding_norm == pattern_norm:
        return True

    if "**" in pattern_norm:
        return _recursive_glob_match(finding_norm, pattern_norm)

    return fnmatch.fnmatchcase(finding_norm, pattern_norm)


def match_glob(path: str, pattern: str) -> bool:
    """Public entry point: case-insensitive glob match with ``**`` support."""
    return _path_pattern_matches(path, pattern)
