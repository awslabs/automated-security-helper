# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""One stat of a path a caller named, and what its failure means.

A config path the operator named is "not found" only when the stat says so:
ENOENT, ENOTDIR for a path through a non-directory, or a path the OS cannot
take at all (an embedded NUL). A symbolic link loop or a denied stat is not a
missing file, and falling back to the default configuration for one would run a
scan with settings the operator did not choose. ``Path.exists()`` and
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
#: ELOOP: a symbolic link loop.
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
    (``"EACCES"``), the errno as text when it has no name, NO_ERROR_CODE when
    the error carried none, and empty for a path the OS cannot take.
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
    fallback, which is the outcome the classification exists to rule out.
    """
    try:
        return os.stat(path)
    except OSError as error:
        number = error.errno
        strerror = error.strerror if isinstance(error.strerror, str) else ""
    except ValueError:
        return StatProblem(MISSING, "", None)
    if number in (errno.ENOENT, errno.ENOTDIR):
        return StatProblem(MISSING, errno.errorcode[number], number)
    if number == errno.ELOOP:
        return StatProblem(LOOP, errno.errorcode[number], number)
    if isinstance(number, int):
        return StatProblem(UNREADABLE, errno.errorcode.get(number, str(number)), number)
    code = NO_ERROR_CODE if number is None else str(number)
    return StatProblem(UNREADABLE, code, None, strerror)


def is_regular_file(result: Union[os.stat_result, StatProblem]) -> bool:
    """Whether ``result``, a stat_named_path answer, is a regular file (what
    ``Path.is_file()`` answers when it does not raise)."""
    return isinstance(result, os.stat_result) and stat.S_ISREG(result.st_mode)
