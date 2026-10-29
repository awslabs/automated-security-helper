# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The runner's fallback spawn is the launch a held watch answers for.

``run_tool`` with no ``results_dir`` runs its command through the fallback
``spawn_run``, under ``watched_launch`` like the primary branch: a watch held
around the call must see that spawn as the launch, or a failure after the
child started would read as a uv run that never started.
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from automated_security_helper.utils.subprocess_utils import StartWatch
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
)

pytestmark = pytest.mark.integration


def test_the_fallback_spawn_is_the_watched_launch(tmp_path, monkeypatch):
    """The fallback child started and exited non-zero: the watch saw the
    start, and the failure is answered as one after the start, with the
    child's own exit code."""
    # The child is "<python> tool run does-nothing", and Python runs a file
    # named "tool" from the child's cwd when one exists; an empty cwd keeps
    # the run on exit 2 (no such file) whatever sits in pytest's own cwd.
    monkeypatch.chdir(tmp_path)
    runner = UVToolRunner(uv_executable=sys.executable)

    watch = StartWatch()
    raised = None
    with patch.object(UVToolRunner, "is_uv_available", return_value=True):
        with watch.watching():
            try:
                # This Python exits 2 on the unknown "tool run ..." arguments:
                # a real child that started, ran and failed.
                runner.run_tool("does-nothing", args=[], check=True)
            except UVToolRunnerError as error:
                raised = error

    assert raised is not None, "the fallback run did not fail"
    assert watch.started is not None, "the fallback spawn was not the launch"
    after = watch.failure_after_the_start(raised)
    assert after is not None, "the failure did not read as after the start"
    assert after.get("post_run_error") is True, after
    assert after.get("returncode") == 2, after
