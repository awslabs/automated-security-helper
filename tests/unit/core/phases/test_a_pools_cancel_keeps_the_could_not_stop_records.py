# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The cancel the scanner pool re-raises keeps every could-not-stop record.

Workers' cancels land in finish order, and the first to land is not the
informative one: a cancel whose stop could not end its tool carries the
(tool, pid) records the exit line prints, and a clean cancel that finished
first used to win the re-raise. The recording loop never hands a
ScanCancelled-holding future over either -- another cancel adds no new
ending -- so a record held only there was dropped with it. Either way the
operator read a clean-looking ending while the tool kept running.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.cancellation import ScanCancelled, cancel_scope
from automated_security_helper.core.phases import scanner_executor as module
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor

WAIT_BOUND_SECONDS = 5.0

#: Past the kernel's pid space, so the record can never name a real process.
_SURVIVOR = ("sometool", 2**30 + 77)


def _tasks(tmp_path: Path, count: int):
    return [
        (f"s{i}", MagicMock(), [{"path": str(tmp_path), "type": "source"}])
        for i in range(count)
    ]


def test_the_raised_cancel_carries_a_later_cancels_records(tmp_path, monkeypatch):
    """A clean cancel lands first; the flagged one lands during the pool's
    shutdown. The cancel the pool re-raises carries the flagged one's
    (tool, pid) record, or the exit line prints a clean-looking ending while
    the tool the stop could not end keeps running."""
    started = {"s0": threading.Event(), "s1": threading.Event()}
    release = threading.Event()

    def fake_execute(scanner_name, scanner_plugin, scan_targets):
        started[scanner_name].set()
        if scanner_name == "s0":
            # The clean cancel, raised only once both workers run, so the
            # flagged scanner is a running future, not a queued one the
            # shutdown cancels unraised.
            for event in started.values():
                assert event.wait(timeout=WAIT_BOUND_SECONDS)
            raise ScanCancelled("the scan was cancelled")
        # The flagged cancel, raised once the pool starts shutting down, so
        # it lands after the clean one was recorded.
        assert release.wait(timeout=WAIT_BOUND_SECONDS), (
            "the pool never shut down, so the flagged cancel never landed"
        )
        raise ScanCancelled(
            f"the scan was cancelled; ASH could not stop {_SURVIVOR[0]} "
            f"(pid {_SURVIVOR[1]}), which may still be running",
            could_not_stop=(_SURVIVOR,),
        )

    class _ReleasesWorkersOnShutdown(ThreadPoolExecutor):
        def shutdown(self, *args, **kwargs):
            release.set()
            return super().shutdown(*args, **kwargs)

    monkeypatch.setattr(module, "ThreadPoolExecutor", _ReleasesWorkersOnShutdown)

    executor = ScannerExecutor(
        plugin_context=MagicMock(),
        progress_display=MagicMock(),
        scanner_tasks=_tasks(tmp_path, 2),
        max_workers=2,
    )
    monkeypatch.setattr(executor, "_execute_scanner", fake_execute)

    with cancel_scope(threading.Event()):
        with pytest.raises(ScanCancelled) as caught:
            executor.run_parallel(MagicMock())

    records = getattr(caught.value, "could_not_stop", ())
    assert _SURVIVOR in records, (
        "the raised cancel dropped a later cancel's could-not-stop record, "
        f"so the exit line cannot name the surviving tool: {records!r}"
    )
