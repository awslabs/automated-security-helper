# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The firejail probe against a real firejail, on a host.

firejail runs a command with no sandbox when it finds no kernel threads among PIDs
1-10, which is what it sees inside a container with its own PID namespace. On a host
it sees them, builds a sandbox, and the probe has to find the test command in a mount
namespace of its own. The container answer is covered with a stand-in firejail in
tests/unit/utils/test_sandbox_firejail_probe.py.

Skipped where firejail is not installed, unless ASH_REQUIRE_SANDBOX_BACKENDS names it,
which the sandbox CI job does.
"""

import os
import shutil
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox.backends import FirejailBackend

pytestmark = pytest.mark.integration

#: The names firejail looks for (check_kernel_procs in src/firejail/no_sandbox.c).
KERNEL_THREADS = ("kthreadd", "ksoftirqd", "kworker", "rcu_sched", "rcu_bh")


def _kernel_threads_visible() -> bool:
    for pid in range(1, 11):
        try:
            name = Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError:
            continue
        if name.startswith(KERNEL_THREADS):
            return True
    return False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="firejail is Linux")
def test_a_real_firejail_on_a_host_is_found_to_confine():
    if shutil.which("firejail") is None:
        required = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "").split(",")
        if "firejail" in [name.strip() for name in required]:
            pytest.fail(
                "firejail is required (ASH_REQUIRE_SANDBOX_BACKENDS) but absent"
            )
        pytest.skip("firejail is not installed")
    if not _kernel_threads_visible():
        pytest.skip(
            "no kernel threads among PIDs 1-10, so firejail would not build a sandbox "
            "here; the unit tests cover that answer"
        )
    assert FirejailBackend().probe() is None
