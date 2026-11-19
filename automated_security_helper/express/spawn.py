# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one place the express daemon's own process is started.

``ash express start`` launches the daemon as a fresh, detached interpreter, and
that launch cannot go through ``utils.subprocess_utils``: those helpers run a
tool to completion inside a scan's process-group bookkeeping, and the daemon is
the opposite shape -- it outlives the command that started it, in a session of
its own, with no scan to cancel it. The sandbox choke point
(``tests/unit/utils/test_sandbox_choke_point.py``) lists this module as its
documented exemption: the process started here is ASH itself, never a scanner,
so there is nothing for ``--sandbox`` to wrap.

Keeping the call in a module of its own, rather than in ``express/client.py``,
keeps the exemption exactly as wide as the one call: the client stays under the
choke point's check like the rest of the package.

Standard library only (``subprocess`` is imported inside the function, so the
thin client's import stays light): only ``ash express start`` reaches here.
"""

from __future__ import annotations

import os
from typing import Mapping, Sequence


def start_detached(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    cwd: str,
    log_fd: int,
    keep_fd: int,
) -> None:
    """Start ``argv`` detached, with stdout and stderr on ``log_fd``.

    The child gets a null stdin, a session of its own (so a Ctrl-C or a closed
    terminal in the starting shell never reaches it), ``cwd`` as its working
    directory, exactly ``env`` as its environment, and no inherited descriptor
    but ``keep_fd`` (the readiness pipe's write end). The caller owns ``log_fd``
    and ``keep_fd`` and closes its copies afterwards. Raises ``OSError`` or
    ``ValueError`` when the process cannot be started; it is not waited for.
    """
    import subprocess  # nosec B404 - starts ASH itself, never a scanner; see the module docstring

    with open(os.devnull, "rb") as devnull:
        subprocess.Popen(  # nosec B603 - argv is ASH's own interpreter and a fixed bootstrap
            list(argv),
            stdin=devnull,
            stdout=log_fd,
            stderr=log_fd,
            cwd=cwd,
            env=dict(env),
            start_new_session=True,
            close_fds=True,
            pass_fds=(keep_fd,),
        )
