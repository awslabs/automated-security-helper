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
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from automated_security_helper.utils.get_scan_set import file_links_leaving_tree

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
    the option, since trivy reads the value as CSV. None on Windows.
    """
    if os.sep != "/":
        return []
    return [
        doublestar_literal(relative)
        for relative in file_links_leaving_tree(target)
        if not any(character in _TRIVY_UNSAFE for character in relative)
    ]
