# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The SIGTERM default-kill arms, run where their kill can only reach their own.

These two cells drive the handler's real die-now branch: no killpg recorder,
no raise_signal stand-in. That branch SIGKILLs every pid in the module's
tool-group mirror, and in a shared pytest worker that mirror is process-wide
state: an entry another test recorded and reaped would aim the SIGKILL at
whatever process holds the reused pid now (measured with a planted sleeper:
the branch killed it, exit -9). A fixture pin to () narrows the window but
still shares the process. In a fresh interpreter the mirrors can hold only
what the cell itself put there, so each cell runs its scenario in a child and
reads the verdict from the child's wait status: dying by SIGTERM is the
default disposition observed, not stood in for.
"""

from __future__ import annotations

import signal
import subprocess  # nosec B404 - cells run the scenario in a child interpreter
import sys
from pathlib import Path

import pytest

from tests.utils.helpers import checkout_env

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="dying by a re-raised SIGTERM under SIG_DFL is POSIX",
)


def _run_probe(tmp_path, source: str) -> subprocess.CompletedProcess:
    probe = tmp_path / "probe.py"
    probe.write_text(source)
    return subprocess.run(  # nosec B603 - fixed argv, the running interpreter
        [sys.executable, str(probe)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        cwd=Path(__file__).resolve().parents[3],
        env=checkout_env(),
    )


def test_a_second_sigterm_takes_the_default_disposition(tmp_path):
    """The first SIGTERM is cooperative; the second ends the process.

    The child registers a scan scope, survives the first signal with the
    scope cancelled, and dies of the second: the handler puts SIG_DFL back
    and re-raises, so the wait status reads SIGTERM, which is the default
    kill observed end to end rather than a recorded raise_signal call.
    """
    result = _run_probe(
        tmp_path,
        "import signal\n"
        "from automated_security_helper.core import cancellation\n"
        "from automated_security_helper.core.cancellation import CancelEvent\n"
        "cancellation.install_sigterm_shutdown()\n"
        "event = CancelEvent()\n"
        "with cancellation.shutdown_cancels(event):\n"
        "    signal.raise_signal(signal.SIGTERM)\n"
        "    assert event.is_set(), 'the first SIGTERM must be cooperative'\n"
        "    assert cancellation.shutdown_requested()\n"
        "    print('survived the first signal', flush=True)\n"
        "    signal.raise_signal(signal.SIGTERM)\n"
        "print('past the second signal', flush=True)\n",
    )
    assert "survived the first signal" in result.stdout, (
        "the first SIGTERM must be cooperative, not a kill.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "past the second signal" not in result.stdout, (
        "the second SIGTERM must end the process, not re-enter the "
        "cooperative path or go unanswered"
    )
    assert result.returncode == -signal.SIGTERM, (
        "the second SIGTERM must fall back to the default kill, so the child "
        f"dies by SIGTERM; it exited {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_a_sigterm_with_no_scan_registered_keeps_the_default_kill(tmp_path):
    """With nothing to stop cooperatively, the first signal is the kill.

    Leaving the process unkillable would strand operators whose SIGTERM
    arrives outside any scan; the handler delivers the default disposition
    at once, and the child's wait status reads SIGTERM.
    """
    result = _run_probe(
        tmp_path,
        "import signal\n"
        "from automated_security_helper.core import cancellation\n"
        "cancellation.install_sigterm_shutdown()\n"
        "print('installed', flush=True)\n"
        "signal.raise_signal(signal.SIGTERM)\n"
        "print('past the signal', flush=True)\n",
    )
    assert "installed" in result.stdout, (
        f"the probe never installed the handler.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "past the signal" not in result.stdout, (
        "with nothing to stop cooperatively, the handler must deliver the "
        "default kill rather than leave the process unkillable"
    )
    assert result.returncode == -signal.SIGTERM, (
        f"the child must die by SIGTERM; it exited {result.returncode}.\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
