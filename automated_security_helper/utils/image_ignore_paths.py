# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ignore_paths`` as the exclude globs an image tool reads.

An ignore path filters an image scan's REPORT (the suppression step drops any
finding whose every location is under one), and always did. The three tools
that read images can also be told to leave paths unread: trivy's
``--skip-files`` and syft's and grype's ``--exclude``. Measured on trivy
0.76.2, syft 1.57.2 and grype 0.122.1 over a saved image holding the same
files under three directories:

- an absolute in-image glob (``/opt/skipme/**``, ``/srv/*/creds.txt``) leaves
  those files out of the scan, in all three; ``**/`` forms work too;
- the spelling must be the in-image path: syft's ``./opt/...`` form matched
  nothing on an image;
- trivy's ``--skip-dirs`` removed nothing from an image scan in any spelling
  tried (``/dir``, ``dir``, ``/dir/**``, ``**/dir``), so a directory is
  excluded through ``--skip-files`` with a ``/**`` tail.

So an ignore path becomes one or two globs, by the matcher's own reading of it
(``utils/path_matching._path_pattern_matches``):

- a glob-free path names that exact path AND the directory of that name, whose
  whole subtree it covers (the bare-directory rule): ``P`` and ``P/**``;
- a glob-free path ending in ``/`` names the directory only: ``P/**``;
- a pattern with glob characters is passed as written.

Only patterns that start with ``/`` or ``**`` are translated: they name an
in-image path from its root, which is what the tools' globs are matched
against. A relative pattern (``vendor/``, ``node_modules/**``) anchors at the
start of a path the tool reports, so no tool glob says the same thing; a
pattern ending in ``/`` that holds glob characters means "a file below one of
these directories", which the tools cannot say either. Those, and any entry the
tools' argument syntax cannot carry, are returned as ``left_to_the_filter`` and
are applied to the report only, exactly as before. The report filter always
runs, so a translation can only save the tool work, never change an answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List

from automated_security_helper.utils.path_matching import (
    has_glob_syntax,
    names_no_path,
)

#: The most globs one scan hands its tools. Each is a command-line argument, and
#: an operator's list can be long; the rest are applied to the report only.
MAX_EXCLUDE_GLOBS = 200

#: Characters no tool argument carries safely (a line break splits trivy's CSV
#: list and a NUL ends the argument).
_UNCARRIABLE = ("\n", "\r", "\x00")


@dataclass
class ImageExcludes:
    """The globs to hand the tools, and the entries only the report filter applies."""

    globs: List[str] = field(default_factory=list)
    left_to_the_filter: List[str] = field(default_factory=list)


def _globs_for(pattern: str) -> List[str]:
    """The tool globs for one ignore path pattern, or [] when it has none."""
    text = pattern.replace("\\", "/")
    if names_no_path(text) or any(ch in text for ch in _UNCARRIABLE):
        return []
    if not text.startswith(("/", "**")):
        return []
    if has_glob_syntax(text):
        # "dir/*/" and the like name a file below a directory; no tool glob does.
        return [] if text.endswith("/") else [text]
    directory = text.rstrip("/")
    if not directory:
        return []
    if text.endswith("/"):
        return [f"{directory}/**"]
    return [directory, f"{directory}/**"]


def image_exclude_globs(entries: Iterable[object] | None) -> ImageExcludes:
    """Translate the ignore-path *entries* (objects with a ``path``) into globs."""
    result = ImageExcludes()
    seen = set()
    for entry in entries or []:
        path = getattr(entry, "path", None)
        if not isinstance(path, str):
            continue
        globs = _globs_for(path)
        if not globs or len(result.globs) + len(globs) > MAX_EXCLUDE_GLOBS:
            result.left_to_the_filter.append(path)
            continue
        for glob in globs:
            if glob not in seen:
                seen.add(glob)
                result.globs.append(glob)
    return result
