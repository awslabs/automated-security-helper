# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Process helpers for tests that start and stop real child processes."""

from __future__ import annotations

import os
import subprocess  # nosec B404 - ps, to read a test child's state
import sys
from pathlib import Path


def process_running(pid: int, *, proc_root: Path = Path("/proc")) -> bool:
    """Whether ``pid`` is running, as opposed to gone or a zombie not yet reaped.

    /proc where there is one (Linux). Elsewhere (macOS) the kernel, with signal
    0, and then ``ps`` for the state, because signal 0 reaches a zombie too.
    A test that reads /proc alone answers "not running" whenever the file is
    missing, so on macOS a check that a process has been stopped would pass
    whatever the process was doing. POSIX only: on Windows signal 0
    terminates the process.

    A process that goes while its stat is read isn't running either: the read
    then raises ProcessLookupError (ESRCH), not FileNotFoundError, or comes back
    without the state field.
    """
    if sys.platform == "win32":
        raise NotImplementedError("process_running is POSIX only")
    if (proc_root / "self").exists():
        try:
            stat = (proc_root / str(pid) / "stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            return False
        # The state is the first field after the name, which is in parentheses
        # and may itself hold ")".
        _, paren, rest = stat.rpartition(")")
        fields = rest.split()
        return bool(paren) and bool(fields) and fields[0] != "Z"
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    state = subprocess.run(  # nosec B603 B607 - fixed argv
        ["ps", "-o", "stat=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    # Empty: the process went between the two checks.
    return bool(state) and not state.startswith("Z")


def forget_running_groups() -> None:
    """Kill every process group subprocess_utils still records, then forget them.

    A cancellable spawn's child is recorded until it is reaped, for the MCP
    server's kill_running_groups. A test whose child outlives it would hand the
    entry to the next test in the same worker. The autouse fixture in
    tests/conftest.py calls this after every test. Only this process's own
    children are ever recorded, so nothing else is signalled.

    kill_running_groups also marks the server as stopping, after which no
    cancellable spawn starts its child. A server exits right after; a test
    process goes on, so the mark is cleared here, whoever set it.

    The registry is mirrored into core/cancellation._TOOL_GROUPS for the
    SIGTERM handler's die-now kill, so the mirror is reset with it: a mirror
    entry surviving its forgotten child would aim a later die-now cell's
    killpg(SIGKILL) at a reaped pid, which on a shared host can have been
    reused by another process group of the same user. The plain-pid mirror
    (cancellation._TOOL_PIDS, for launcher children that lead no group) is
    reset for the same reason, and the hazard is sharper there: a single pid
    is reused faster than a pgid.
    """
    from automated_security_helper.core import cancellation
    from automated_security_helper.utils import subprocess_utils

    if subprocess_utils._RUNNING_GROUPS:
        subprocess_utils.kill_running_groups()
    with subprocess_utils._RUNNING_GROUPS_LOCK:
        subprocess_utils._RUNNING_GROUPS.clear()
        subprocess_utils._STOPPING = False
    for pgid in cancellation._TOOL_GROUPS:
        cancellation.discard_tool_group(pgid)
    for pid in cancellation._TOOL_PIDS:
        cancellation.discard_tool_pid(pid)
