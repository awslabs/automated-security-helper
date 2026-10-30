# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""One stat of a path a caller named, and what its failure means.

A config path the operator named is "not found" only when the stat says so:
ENOENT, ENOTDIR for a path through a non-directory, or a path the OS cannot
take at all (an embedded NUL, which Python refuses before the stat; a name the
OS refuses with EINVAL, as Windows does for one holding ``<`` or ``?``; a path
longer than the OS allows, ENAMETOOLONG). A symbolic link loop or a denied stat is not a
missing file, and falling back to the default configuration for one would run a
scan with settings the operator did not choose. Windows reports a link it cannot
resolve as EINVAL, the same errno as an invalid name, so an EINVAL whose path is
itself a symbolic link (``os.lstat``, which does not follow it) is the loop, not
a missing path. Windows gives EINVAL to every error it has no errno for (a share's
logon failure, a network name deleted), so on Windows only ERROR_INVALID_NAME
(``winerror`` 123) is an invalid name; any other EINVAL is unreadable.
``Path.exists()`` and
``Path.is_file()`` cannot tell these apart, and before Python 3.14 they raise
the stat's PermissionError for a path under an unsearchable directory instead
of answering, so the same path got a different answer on each interpreter.

Every site that classifies a named path reads the one stat this module makes
and formats its own refusal from the result: the scan's ``--config`` pre-check,
``resolve_config``, the ASH_CONFIG lookup (``default_config._ash_config_file``)
and the ASH_CONFIG chain helpers.
"""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from typing import Optional, Union

#: ENOENT, ENOTDIR, or a path the OS cannot take: the documented "not found".
MISSING = "missing"
#: The errnos of a path the OS cannot take: an invalid name (EINVAL, Windows's
#: answer for a reserved character) and a name longer than it allows. Neither
#: can be a file that is there, so both are MISSING with ENOENT and ENOTDIR.
_CANNOT_TAKE = frozenset(
    code
    for code in (getattr(errno, "EINVAL", None), getattr(errno, "ENAMETOOLONG", None))
    if code is not None
)
#: Windows's ERROR_INVALID_NAME: the one Windows error behind an EINVAL that means
#: the path is a name the OS cannot take (one holding ``<`` or ``?``).
_ERROR_INVALID_NAME = 123
#: ELOOP, or Windows's EINVAL on a path that is itself a symbolic link: a
#: symbolic link loop.
LOOP = "loop"
#: Any other errno (EACCES among them): the path may be there, and cannot be read.
UNREADABLE = "unreadable"

#: The code of an error that carried no errno (a filesystem or wrapper raising
#: OSError with a text alone).
NO_ERROR_CODE = "no error code"


@dataclass(frozen=True)
class StatProblem:
    """Why the stat of a named path failed.

    ``kind`` is MISSING, LOOP or UNREADABLE. ``code`` is the errno's name
    (``"EACCES"``; ``"EINVAL"`` for a LOOP Windows reported that way), the
    errno as text when it has no name, NO_ERROR_CODE when the error carried
    none, and empty for a path the OS cannot take.
    ``strerror`` is the error's own strerror, kept for an error with no errno,
    whose message cannot come from ``os.strerror``.
    """

    kind: str
    code: str
    number: Optional[int]
    strerror: str = ""

    def cause(self) -> OSError:
        """A fresh OSError for a refusal's ``from``: this errno and its
        message, and no filename. The stat's own error names the path, which
        can be one the configuration read from the environment; and
        ``os.strerror`` takes only an int, so an error that carried no errno
        is described by its own strerror, or by its code when it has none,
        instead of raising a TypeError in its place.
        """
        if isinstance(self.number, int):
            return OSError(self.number, os.strerror(self.number))
        return OSError(None, self.strerror or self.code)


def stat_named_path(
    path: Union[str, "os.PathLike[str]"],
) -> Union[os.stat_result, StatProblem]:
    """``os.stat(path)``, or why it failed, read from that one stat's own error.

    One stat: a second could answer differently (a permission or mount change
    in between) and send a path whose first stat was denied to the "not found"
    fallback, which is the outcome the classification exists to rule out. The
    one exception reads the other way: an EINVAL is followed by an ``os.lstat``
    of the path itself, which can only move the answer from MISSING to LOOP (a
    refusal), never toward the fallback.
    """
    try:
        return os.stat(path)
    except OSError as error:
        number = error.errno
        strerror = error.strerror if isinstance(error.strerror, str) else ""
        # Set on Windows only: the Windows error the errno was made from.
        winerror = getattr(error, "winerror", None)
    except ValueError:
        return StatProblem(MISSING, "", None)
    if number == errno.EINVAL and _names_a_symbolic_link(path):
        return StatProblem(LOOP, errno.errorcode[number], number)
    if (
        number == errno.EINVAL
        and winerror is not None
        and winerror != _ERROR_INVALID_NAME
    ):
        # Windows gives EINVAL to every error it has no errno for (a share's
        # logon failure, a network name deleted, a file the system cannot
        # access): the path may be there and cannot be read, so it is not the
        # "not found" that sends a scan to the default configuration.
        return StatProblem(UNREADABLE, errno.errorcode[number], number)
    if number in (errno.ENOENT, errno.ENOTDIR) or number in _CANNOT_TAKE:
        return StatProblem(MISSING, errno.errorcode[number], number)
    if number == errno.ELOOP:
        return StatProblem(LOOP, errno.errorcode[number], number)
    if isinstance(number, int):
        return StatProblem(UNREADABLE, errno.errorcode.get(number, str(number)), number)
    code = NO_ERROR_CODE if number is None else str(number)
    return StatProblem(UNREADABLE, code, None, strerror)


def _names_a_symbolic_link(path: Union[str, "os.PathLike[str]"]) -> bool:
    """Whether ``path`` is itself a symbolic link, read with ``os.lstat`` (the
    link, not what it points at). A path that cannot be lstat'ed is not one:
    a name the OS refuses is refused by lstat too, and stays MISSING."""
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except (OSError, ValueError):
        return False


def is_regular_file(result: Union[os.stat_result, StatProblem]) -> bool:
    """Whether ``result``, a stat_named_path answer, is a regular file (what
    ``Path.is_file()`` answers when it does not raise)."""
    return isinstance(result, os.stat_result) and stat.S_ISREG(result.st_mode)
