# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Glob-based path matching utilities supporting ``**`` recursive patterns."""

import fnmatch
import re
from typing import Optional


def _recursive_glob_match(path: str, pattern: str) -> bool:
    """Match *path* against *pattern* treating ``**`` as zero-or-more directories.

    The algorithm splits the pattern on ``**`` separators, then verifies that
    each resulting segment appears in the correct order inside *path* using
    ``fnmatch`` for each segment.
    """
    path = path.replace("\\", "/")
    pattern = pattern.replace("\\", "/")

    segments = re.split(r"/?\*\*/?", pattern)
    has_trailing_star = pattern.rstrip("/").endswith("**")
    has_leading_star = pattern.lstrip("/").startswith("**")
    segments = [s for s in segments if s]

    if not segments:
        return True

    if len(segments) == 1 and has_leading_star and has_trailing_star:
        middle = segments[0]
        parts = path.split("/")
        seg_parts = middle.split("/")
        seg_len = len(seg_parts)
        for j in range(len(parts) - seg_len + 1):
            candidate = "/".join(parts[j : j + seg_len])
            if fnmatch.fnmatch(candidate, middle):
                return True
        return False

    if len(segments) == 1 and has_trailing_star and not has_leading_star:
        prefix = segments[0]
        parts = path.split("/")
        seg_parts = prefix.split("/")
        seg_len = len(seg_parts)
        if len(parts) < seg_len:
            return False
        candidate = "/".join(parts[:seg_len])
        return fnmatch.fnmatch(candidate, prefix)

    if len(segments) == 1 and has_leading_star and not has_trailing_star:
        suffix = segments[0]
        parts = path.split("/")
        seg_parts = suffix.split("/")
        seg_len = len(seg_parts)
        if len(parts) < seg_len:
            return fnmatch.fnmatch(path, suffix)
        candidate = "/".join(parts[-seg_len:])
        return fnmatch.fnmatch(candidate, suffix)

    remaining = path
    for i, segment in enumerate(segments):
        if not segment:
            continue

        is_first = i == 0
        is_last = i == len(segments) - 1

        if is_first and is_last:
            return fnmatch.fnmatch(remaining, segment)

        if is_first:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            prefix = "/".join(parts[:seg_len])
            if not fnmatch.fnmatch(prefix, segment):
                return False
            remaining = "/".join(parts[seg_len:])
        elif is_last:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            suffix = "/".join(parts[-seg_len:]) if seg_len <= len(parts) else remaining
            return fnmatch.fnmatch(suffix, segment)
        else:
            parts = remaining.split("/")
            seg_parts = segment.split("/")
            seg_len = len(seg_parts)
            found = False
            for j in range(len(parts) - seg_len + 1):
                candidate = "/".join(parts[j : j + seg_len])
                if fnmatch.fnmatch(candidate, segment):
                    remaining = "/".join(parts[j + seg_len :])
                    found = True
                    break
            if not found:
                return False

    return True


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
