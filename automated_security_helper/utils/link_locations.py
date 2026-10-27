# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Where the symlinks sit that a path passes through.

A config file's location says who wrote it: a file under the MCP workspace root
came from a client, and one inside the scanned tree from the repository. A
symlink's location says the same about the file it reaches, because whoever
wrote the link chose that file. ``Path.resolve`` returns only the last
location, so a check of who chose a file judges each link on the way as well
(``cli/mcp/sandbox.config_is_client_supplied``,
``config/sandbox_grants.files_inside``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

#: The most symlinks ``link_locations`` follows for one path, as Linux's own
#: lookup does.
MAX_LINKS_FOLLOWED = 40

_EXTENDED_PREFIX = "\\\\?\\"
_EXTENDED_UNC_PREFIX = "\\\\?\\UNC\\"


def without_extended_prefix(target: str) -> str:
    """``target`` without the Win32 extended-length prefix ``os.readlink`` can give it.

    A link made with an absolute target reads back on Windows as ``\\\\?\\C:\\dir``.
    The same place is ``C:\\dir`` everywhere else the walk and its callers name
    it, and the two spellings do not compare equal, so a location kept in the
    prefixed form would be taken for one outside the directory it sits in.
    ``\\\\?\\UNC\\host\\share`` becomes ``\\\\host\\share``.
    """
    if target.startswith(_EXTENDED_UNC_PREFIX):
        return "\\\\" + target[len(_EXTENDED_UNC_PREFIX) :]
    if target.startswith(_EXTENDED_PREFIX):
        return target[len(_EXTENDED_PREFIX) :]
    return target


def link_locations(path: str | Path) -> List[Path]:
    """Where each symlink sits that looking ``path`` up follows, in the order followed.

    Each entry is the link itself, under its parent directory with that
    directory's own links resolved: the place the link was written. The path is
    walked one component at a time as the kernel walks it, so a link in a
    directory reached through another link is found as well, and a ``..`` after
    a link applies to the link's target. A component that cannot be read ends
    the walk, and so does a loop once ``MAX_LINKS_FOLLOWED`` links have been
    followed. A relative ``path`` is taken from the working directory.
    """
    absolute = Path(os.path.join(os.getcwd(), os.fspath(path)))
    current = Path(absolute.anchor)
    pending = list(absolute.parts[1:])
    found: List[Path] = []
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            current = current.parent
            continue
        step = current / part
        try:
            if not step.is_symlink():
                current = step
                continue
            text = os.readlink(step)
        except OSError:
            break
        if len(found) >= MAX_LINKS_FOLLOWED:
            break
        found.append(step)
        target = Path(without_extended_prefix(text) if os.name == "nt" else text)
        if target.is_absolute():
            current = Path(target.anchor)
            pending = list(target.parts[1:]) + pending
        else:
            pending = list(target.parts) + pending
    return found
