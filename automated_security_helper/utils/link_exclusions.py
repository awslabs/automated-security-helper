# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Exclusion values that keep a tree-walking scanner off links leaving its target.

ASH's scan set leaves out every link to a file whose target, with every link
resolved, leaves the scanned tree. Scanners that walk the directory they are given
do not read the scan set, so each is also given, in its own exclusion option, every
such link under its target (``get_scan_set.file_links_leaving_tree``). bandit,
checkov and ferret-scan read such a link, so their scanners build their values
themselves and refuse a target whose link cannot be written. The scanners here do
not read one (measured, see each function), so the values are a second guard: a
link that cannot be written exactly is left out of the option rather than the
target refused, because a pattern that also matched other paths would hide files
the scan should read.

semgrep and opengrep get no such value: they follow no link either, and their
``--exclude`` cannot name one path (see ``_grep_scanner_base._execute_scan``).

The same goes for the operator's ``global_settings.ignore_paths``
(``ignored_entries``): ASH drops the findings in those paths after the scan, but a
scanner that walks the tree still reads the files unless its own option leaves
them out.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Iterable, List, Sequence

from automated_security_helper.utils.get_scan_set import file_links_leaving_tree
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.suppression_matcher import file_path_matches

#: The characters doublestar (the glob library syft, grype and trivy match with)
#: reads as pattern syntax, each escaped with a backslash to stand for itself.
_DOUBLESTAR_SPECIAL = frozenset("\\*?[]{}")

#: The characters trivy's ``--skip-files`` cannot carry: its value is read as one
#: line of CSV, so a comma splits it and a quote or a line break changes it.
_TRIVY_UNSAFE = frozenset(',"\r\n')


def doublestar_literal(text: str) -> str:
    """``text`` as a doublestar pattern that matches ``text`` and nothing else."""
    return "".join(
        f"\\{character}" if character in _DOUBLESTAR_SPECIAL else character
        for character in text
    )


def syft_excludes(target: str | Path) -> List[str]:
    """``--exclude`` values for syft and grype, one per link leaving ``target``.

    syft 1.54.1 and grype 0.120.1 list no file behind a link to a file or a
    directory whose target leaves the directory they scan (measured). Each value is
    ``./`` and the link's path below ``target``, glob characters escaped: syft
    anchors a ``./`` pattern at the scanned directory, whatever ``--base-path``
    says, and matches the whole path, so ``./x/requirements.txt`` left out that file
    and not ``sub/x/requirements.txt`` (measured, with brackets, braces, ``*``,
    ``?``, a backslash, a space and a comma in the path). None on Windows, where
    the paths it matches are not ``/``-joined.
    """
    if os.sep != "/":
        return []
    return [
        f"./{doublestar_literal(relative)}"
        for relative in file_links_leaving_tree(target)
    ]


def trivy_skip_files(target: str | Path) -> List[str]:
    """``--skip-files`` values for trivy, one per link leaving ``target``.

    trivy 0.75.0 skips every link, inside the tree or not (measured). A value is the
    link's path below ``target`` with glob characters escaped, which trivy matches
    against the whole path: ``x.txt`` left out ``x.txt`` and not ``sub/x.txt``
    (measured). A path with a comma, a double quote or a line break is left out of
    the option, since trivy reads the value as CSV, and named in one debug record.
    None on Windows.
    """
    if os.sep != "/":
        return []
    values: List[str] = []
    left_out: List[str] = []
    for relative in file_links_leaving_tree(target):
        if any(character in _TRIVY_UNSAFE for character in relative):
            left_out.append(relative)
        else:
            values.append(doublestar_literal(relative))
    if left_out:
        ASH_LOGGER.debug(
            "trivy: %d link(s) leaving %s not given in --skip-files, since a comma, "
            "a double quote or a line break would change the value (trivy skips "
            "every link itself): %s",
            len(left_out),
            target,
            ", ".join(repr(relative) for relative in left_out),
        )
    return values


def walked_files(target: str | Path) -> tuple[List[str], List[str]]:
    """Every file below ``target`` as the tree-walking tools list it, and the links
    among them whose target leaves it, both relative to ``target`` and sorted.

    One walk (``file_links_leaving_tree``): links to directories are not entered,
    and ignore files are not read, as the tools do not read them.
    """
    files: List[str] = []
    links = file_links_leaving_tree(target, all_files=files)
    return sorted(files), links


def ignored_entries(
    target: str | Path,
    source_dir: str | Path,
    ignore_paths: Iterable[object],
    files: Sequence[str],
    matches: Callable[[str, str], bool] = file_path_matches,
) -> List[str]:
    """The paths below ``target`` that ``ignore_paths`` ignore, as few as possible.

    Each ignore path's pattern is matched as ASH matches it when it drops findings
    (``matches``, by default ``file_path_matches``), against each file's path below
    ``source_dir``. A directory whose every walked file is ignored is returned once,
    with a trailing ``/``, and the files below it are not; any other ignored file is
    returned itself. Paths are relative to ``target`` and ``/``-joined.

    Empty when ``target`` is not ``source_dir`` or a directory below it (ASH's work
    directory for converted files): the patterns name paths below the source
    directory, and a converted file's path there is not its path in the work
    directory. ASH still drops such a file's findings after the scan.

    Args:
        target: The directory the tool is given.
        source_dir: The scan's source directory.
        ignore_paths: The scan's ``global_settings.ignore_paths`` entries (each with
            a ``path``).
        files: ``target``'s walked files, from ``walked_files``.
        matches: ``(path, pattern) -> bool``.
    """
    patterns = [
        str(getattr(entry, "path", "") or "")
        for entry in ignore_paths or []
        if getattr(entry, "path", None)
    ]
    if not patterns or not files:
        return []
    try:
        below = Path(os.path.realpath(target)).relative_to(
            Path(os.path.realpath(source_dir))
        )
    except ValueError:
        return []
    prefix = "" if below.as_posix() in ("", ".") else f"{below.as_posix()}/"

    ignored = {
        relative
        for relative in files
        if any(matches(f"{prefix}{relative}", pattern) for pattern in patterns)
    }
    if not ignored:
        return []
    total: dict[str, int] = {}
    hit: dict[str, int] = {}
    for relative in files:
        parts = relative.split("/")
        for depth in range(1, len(parts)):
            directory = "/".join(parts[:depth])
            total[directory] = total.get(directory, 0) + 1
            if relative in ignored:
                hit[directory] = hit.get(directory, 0) + 1
    whole = {
        directory for directory, count in total.items() if hit.get(directory) == count
    }

    def _under_whole(relative: str) -> bool:
        parts = relative.split("/")
        return any("/".join(parts[:depth]) in whole for depth in range(1, len(parts)))

    entries = [f"{directory}/" for directory in whole if not _under_whole(directory)]
    entries += [relative for relative in ignored if not _under_whole(relative)]
    return sorted(entries)
