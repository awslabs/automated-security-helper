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

import errno
import os
from pathlib import Path
from typing import List

from automated_security_helper.utils.scanned_tree import _is_link_stat

#: The most symlinks ``link_locations`` follows for one path, as the platform's
#: own lookup does: Linux follows 40, and Windows resolves up to 63 reparse points
#: on one path. At Linux's cap on Windows the walk stopped reporting links on a
#: path the OS still opened.
MAX_LINKS_FOLLOWED = 63 if os.name == "nt" else 40

#: The errors ``Path.is_symlink`` reads as "not a link": a component that is not
#: there, or is below a file, or is a loop, and on Windows a device that is not
#: ready, an invalid name, or a name that cannot be resolved (the Win32 errors
#: pathlib ignores, which come with ``EINVAL`` as the errno). The walk steps
#: through such a component as before; any other error ends it. A ``ValueError``
#: (a NUL in a component) is "not a link" too, as it is for ``is_symlink``.
_NOT_A_LINK_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})
_NOT_A_LINK_WINERRORS = frozenset({21, 123, 1921})


def _lookup_says_not_a_link(error: Exception) -> bool:
    """Whether *error*, raised looking a component up, means "not a link" rather
    than "the walk cannot continue": the reading :meth:`pathlib.Path.is_symlink`
    makes of the same errors."""
    if isinstance(error, ValueError):
        return True
    return (
        getattr(error, "errno", None) in _NOT_A_LINK_ERRNOS
        or getattr(error, "winerror", None) in _NOT_A_LINK_WINERRORS
    )


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
    directory's own links resolved: the place the link was written. A Windows
    directory junction is a link here as everywhere else in this family
    (``scanned_tree._is_link_stat``): ``Path.is_symlink`` says it is none, and
    stepping through it as a plain directory would examine the later components
    under the junction's name, not where it leads. The path is
    walked one component at a time as the kernel walks it, so a link in a
    directory reached through another link is found as well, and a ``..`` after
    a link applies to the link's target. A component that cannot be read ends
    the walk, and so does a loop once ``MAX_LINKS_FOLLOWED`` links have been
    followed; a component that is not there, holds a NUL, or fails the lookup
    in a way ``Path.is_symlink`` reads as "not a link" (:data:`_NOT_A_LINK_ERRNOS`,
    :data:`_NOT_A_LINK_WINERRORS`) is stepped through as a plain name, so a ``..``
    after it still applies. A relative ``path`` is taken from the working directory, which is
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
            try:
                is_link = _is_link_stat(os.lstat(step))
            except (OSError, ValueError) as error:
                if not _lookup_says_not_a_link(error):
                    raise
                is_link = False
            if not is_link:
                current = step
                continue
            text = os.readlink(step)
        except (OSError, ValueError):
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
