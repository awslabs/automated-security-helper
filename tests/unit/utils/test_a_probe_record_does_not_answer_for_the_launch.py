# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A helper spawn's record never answers for the launch.

``spawn_run`` attaches its call's record to every exception it raises, and
``StartWatch.failure_after_the_start`` falls back to that carried record when
the watch holds none. The fallback takes only a record made under
``watched_launch``: a probe or install the same layer ran outside that scope
raised with its own record, and reading it as the launch said the tool ran
when the launch never started.
"""

from __future__ import annotations

import subprocess  # nosec B404 -- the cells spawn this Python with a known exit
import sys

import pytest

from automated_security_helper.utils.subprocess_utils import (
    StartWatch,
    spawn_run,
    watched_launch,
)

pytestmark = pytest.mark.integration

_EXITS_7 = [sys.executable, "-c", "import sys; sys.exit(7)"]


def _raised_by(run) -> subprocess.CalledProcessError:
    try:
        run()
    except subprocess.CalledProcessError as error:
        return error
    raise AssertionError("the spawn did not raise")


def test_a_probe_spawns_carried_record_does_not_answer_for_the_launch():
    """A spawn outside ``watched_launch`` (a version probe, say) raised; the
    watch held no start, and the probe's carried record is not the launch's."""
    watch = StartWatch()
    with watch.watching():
        error = _raised_by(lambda: spawn_run(_EXITS_7, check=True))
        after = watch.failure_after_the_start(error)

    assert watch.started is None, watch.started
    assert after is None, after


def test_the_launches_own_carried_record_still_answers():
    """The control: a record made under ``watched_launch`` and carried by the
    error answers for a watch that held no start itself."""
    with watched_launch():
        error = _raised_by(lambda: spawn_run(_EXITS_7, check=True))

    late_watch = StartWatch()
    after = late_watch.failure_after_the_start(error)

    assert after is not None
    assert after.get("returncode") == 7, after
