# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A mark added while another mark is being retired is not lost.

``_forget_processed`` rebuilt the list of marks as a filtered copy and wrote it
back with a slice assignment. A thread that marked a different response between
the two steps had its mark dropped by the write-back, so the uv path found that
response unprocessed and folded it into exit_code and errors a second time: its
stdout and stderr lines were reported twice.

The three mark methods now share one lock. The first test places the other
thread's mark exactly between the copy and the write-back, so it does not
depend on thread timing; the second repeats the race for real as a control.
"""

from __future__ import annotations

import threading

import pytest

from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit


class _SwitchingList(list):
    """A list that gives another thread a turn after its pass is over.

    The pass copies the items first and runs the hook once the last one has been
    handed out, which is where a rebuild-and-write-back has finished reading
    and has not yet written.
    """

    def __init__(self):
        super().__init__()
        self.hook = None

    def __iter__(self):
        snapshot = list(super().__iter__())
        yield from snapshot
        hook, self.hook = self.hook, None
        if hook is not None:
            hook()


def _response(returncode: int = 0) -> dict:
    return {"stdout": "", "stderr": "", "returncode": returncode}


def test_a_mark_added_between_the_copy_and_the_write_back_survives(plugin_context):
    scanner = _scanner(plugin_context)
    retired, added = _response(), _response()
    marks = _SwitchingList()
    scanner._processed_responses = marks
    scanner._mark_processed(retired)

    other = threading.Thread(target=scanner._mark_processed, args=(added,))

    def let_the_other_thread_mark() -> None:
        other.start()
        # Unlocked, the other thread finishes at once. Locked, it waits for the
        # retirement to end, so this returns on the timeout.
        other.join(timeout=0.5)

    marks.hook = let_the_other_thread_mark
    scanner._forget_processed(retired)
    other.join(timeout=10)

    assert not other.is_alive()
    assert not scanner._was_processed(retired)
    assert scanner._was_processed(added), "the mark made during the retirement was lost"


def test_marks_made_and_retired_on_two_threads_all_land(plugin_context):
    scanner = _scanner(plugin_context)
    for _ in range(30):
        old, new = _response(), _response()
        scanner._mark_processed(old)
        barrier = threading.Barrier(2)

        def retire() -> None:
            barrier.wait()
            scanner._forget_processed(old)

        def mark() -> None:
            barrier.wait()
            scanner._mark_processed(new)

        threads = [threading.Thread(target=retire), threading.Thread(target=mark)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert not scanner._was_processed(old)
        assert scanner._was_processed(new)
        scanner._forget_processed(new)

    assert scanner._processed_responses == []
