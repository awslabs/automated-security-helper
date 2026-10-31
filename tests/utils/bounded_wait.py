# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Run a call that could wait forever, and fail the test instead of hanging it.

A test of a lock, a hold or a handshake that is wrong does not fail: it waits,
and the run it belongs to ends only when its own budget does, with nothing
printed for the test that waited. ``finishes_within`` runs the call on a daemon
thread and gives the caller the answer, or a failure that names the wait.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict

import pytest


def finishes_within(seconds: float, work: Callable[[], Any]) -> Any:
    """Return what ``work()`` returns, or fail when it has not returned in ``seconds``.

    ``work`` runs on a daemon thread, so a call that never returns is left
    behind when the test fails and does not hold the interpreter open. An
    exception ``work`` raises is raised again here, on the caller's thread.
    """
    outcome: Dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["value"] = work()
        except BaseException as exc:  # noqa: BLE001 - handed to the caller below
            outcome["error"] = exc

    worker = threading.Thread(target=run, name="finishes-within", daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        pytest.fail(
            f"the call had not returned after {seconds} s: it is waiting on "
            "something that never lets it through"
        )
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")
