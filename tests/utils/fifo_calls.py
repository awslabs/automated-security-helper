# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run a call that may block opening a FIFO, and fail the test instead of hanging it.

A config path that is a FIFO, opened for reading, waits for a writer. A test of
the refusal that must come before that open runs the call on a thread and waits
a bounded time, so a regression of the refusal fails the test instead of
stalling the suite to the CI timeout. Test modules used to import this from
another test module; it lives here, as the wizard helper does
(``wizard_script``), so a test module imports nothing from a sibling.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Callable


def returns_promptly(call: Callable[[], object], fifo: Path) -> BaseException | None:
    """Run ``call`` in a thread; fail when it is still running after 10 seconds.

    A call blocked opening ``fifo`` for reading is released by opening its write
    end, so a failing test does not leave a thread behind. Returns what ``call``
    raised, or None.
    """
    outcome: dict = {}

    def _run() -> None:
        try:
            outcome["value"] = call()
        except BaseException as exc:  # recorded for the assertion below
            outcome["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(10)
    blocked = thread.is_alive()
    if blocked:
        os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
        thread.join(10)
    assert not blocked, f"reading {fifo.name} blocked"
    return outcome.get("error")
