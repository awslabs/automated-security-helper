# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Forgetting a test's children clears the SIGTERM handler's group mirror too.

The subprocess registry (utils/subprocess_utils._RUNNING_GROUPS) is mirrored
into core/cancellation._TOOL_GROUPS for the SIGTERM handler's die-now kill,
which cannot take the registry's lock. The product's own reap path drops both
together. The test cleanup helper (tests/utils/processes.forget_running_groups)
clears the registry directly, and a mirror entry that survives it aims a later
die-now cell's ``os.killpg(..., SIGKILL)`` at a reaped pid -- which on a shared
host can have been reused by another process group of the same user.
"""

from __future__ import annotations

import subprocess  # nosec B404 - the children here are fixed-argv sleepers
import sys

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.utils import subprocess_utils
from tests.utils.processes import forget_running_groups

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32",
        reason="the registry records nothing on Windows: see _RUNNING_GROUPS",
    ),
]


def _registered_sleeper() -> subprocess.Popen:
    """A real child of this process, registered the way a cancellable spawn is."""
    process = subprocess.Popen(  # nosec B603 - our own sleeper, fixed argv
        [sys.executable, "-c", "import time; time.sleep(60)"],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess_utils._register_group(process)
    return process


def test_forget_running_groups_leaves_no_entry_in_the_handlers_mirror():
    """The cleanup helper forgets a child from the registry AND the mirror.

    Only its own real child is ever spawned or signalled here: the helper kills
    the sleeper, and the assert reads the mirror after the kill.
    """
    process = _registered_sleeper()
    try:
        assert process.pid in cancellation._TOOL_GROUPS, (
            "the spawn did not reach the mirror; the cell is not measuring it"
        )
        forget_running_groups()
        assert process.pid not in cancellation._TOOL_GROUPS, (
            "the forgotten child's group is still in the SIGTERM handler's "
            "mirror: a later die-now kill would killpg its reused pid"
        )
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)


def test_a_reaped_child_leaves_no_entry_in_the_handlers_mirror():
    """The control: the registry's own reap path already drops both records."""
    process = subprocess.Popen(  # nosec B603 - our own child, fixed argv
        [sys.executable, "-c", "pass"],
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess_utils._register_group(process)
    process.wait(timeout=30)
    # The registry reaps on its next registration; the product calls this
    # under the lock on every spawn.
    with subprocess_utils._RUNNING_GROUPS_LOCK:
        subprocess_utils._forget_exited_groups()
    assert process.pid not in cancellation._TOOL_GROUPS
    assert process.pid not in subprocess_utils._RUNNING_GROUPS
