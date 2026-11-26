# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A forked scan must reach its hard exit even though the daemon warmed polars.

Importing polars starts native threads (a spill-file cleaner among them) and
registers an exit hook, built in Rust, that sends the cleaner a request and
waits for the answer. ``os.fork`` carries only the forking thread into the
child, so in a forked scan nobody answers: ``atexit._run_exitfuncs()`` in the
child blocks forever, after the scan has already printed its report, and the
client waits on a socket for an exit code that never arrives (the arm64
``e2e-express`` job timed out at 600 s on exactly this).

``threading.active_count()`` cannot see the native threads, so the daemon's
single-threaded check passes; the cure is to leave out, in the child, the exit
hooks a warm import registered through a Rust extension. The first test pins
the premise (the hook does hang without the cure) so that a polars release that
fixes it turns the cure into dead code loudly instead of silently.

The premise is a Linux measurement: the hang was found on the ubuntu-24.04-arm
``e2e-express`` leg and reproduced on x86_64 Linux. On macOS the naive forked
child exits (every macOS unit leg read ``EXITED`` here), so there is no hang to
pin and the first test runs on Linux only. The cure is applied on every
platform express runs on, and the second test holds it everywhere.
"""

import subprocess
import sys
import textwrap

import pytest

from automated_security_helper.express import runtime
from tests.utils.helpers import importing_this_checkout

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        not runtime.express_supported(), reason="express mode is unix-only"
    ),
]

# The scenario runs in its own interpreter: it forks, and the polars import must
# happen in a process whose threads this test does not share.
_SCENARIO = textwrap.dedent(
    """
    import os, sys, time

    mode = sys.argv[1]
    if mode == "cured":
        from automated_security_helper.express import daemon

        with daemon._recording_native_exit_hooks():
            import polars  # noqa: F401  (starts its native threads, registers its hook)
    else:
        import polars  # noqa: F401

    pid = os.fork()
    if pid == 0:
        if mode == "cured":
            daemon._run_exit_hooks_in_child()
        else:
            import atexit

            atexit._run_exitfuncs()
        os._exit(0)

    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done:
            print("EXITED")
            break
        time.sleep(0.05)
    else:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        print("HUNG")
    """
)


def _run(mode: str) -> str:
    proc = subprocess.run(  # nosec B603 - fixed interpreter, fixed scenario, no shell
        [sys.executable, "-I", "-B", "-c", importing_this_checkout(_SCENARIO), mode],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="the hang is a Linux measurement; on macOS the naive forked child exits",
)
def test_the_exit_hooks_of_a_forked_child_hang_without_the_cure():
    assert _run("naive") == "HUNG"


def test_a_forked_child_reaches_its_exit_with_the_cure():
    assert _run("cured") == "EXITED"
