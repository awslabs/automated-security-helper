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


def link_locations(path: str | Path) -> List[Path]:
    """Where each symlink sits that looking ``path`` up follows, in the order followed.

    Each entry is the link itself, under its parent directory with that
    directory's own links resolved: the place the link was written. The path is
    walked one component at a time as the kernel walks it, so a link in a
    directory reached through another link is found as well, and a ``..`` after
    a link applies to the link's target. A component that cannot be read ends
    the walk, and so does a loop once ``MAX_LINKS_FOLLOWED`` links have been
    followed. A relative ``path`` is taken from the working directory, which is
    read for that and nothing else: an absolute ``path`` is walked with the
    working directory deleted. A relative ``path`` with the directory gone has
    no place to start from, so it raises ``FileNotFoundError``, as
    ``os.path.abspath`` does for it, and never answers an empty list, which a
    caller would read as "no links".
    """
    if Path(path).is_absolute():
        absolute = Path(path)
    else:
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
            target = Path(os.readlink(step))
        except OSError:
            break
        if len(found) >= MAX_LINKS_FOLLOWED:
            break
        found.append(step)
        if target.is_absolute():
            current = Path(target.anchor)
            pending = list(target.parts[1:]) + pending
        else:
            pending = list(target.parts) + pending
    return found
