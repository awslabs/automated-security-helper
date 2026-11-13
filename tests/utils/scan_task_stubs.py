# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A stand-in for the MCP tools' scan-task start, for tests whose scan never runs.

The real ``_start_scan_task`` holds the scan's log scope until its task is
done (utils/log.py). A stand-in that only closes the runner coroutine leaves
the scope the tool opened active for the rest of the process -- while it is,
a line no run owns reaches no run's handlers -- and the suite's scope-leak
guard fails such a test. This stand-in ends the scope the way the real task's
completion does: it takes the hold the task would and lets it go at once.
"""

from typing import Any, Callable, List, Optional
from unittest.mock import MagicMock

from automated_security_helper.utils.log import (
    current_run_log_scope,
    hold_run_log_scope,
    release_run_log_scope,
)


def end_the_scans_scope_as_its_task_would() -> None:
    """End the current scan's log scope as a started-and-finished task does.

    For a ``_start_scan_task`` stand-in, which runs in the tool's context: the
    real start holds the scope and the task's completion lets go.
    """
    scope = current_run_log_scope()
    hold_run_log_scope(scope)
    release_run_log_scope(scope)


def completed_task_create() -> Callable[[Any], MagicMock]:
    """An ``asyncio.create_task`` stand-in whose task is already done.

    Closes the coroutine and fires every done callback at once, so production
    code that holds something until the task is done -- the scan's log scope,
    the task registry entry -- releases it the way a finished task does.
    """

    def create(coroutine: Any) -> MagicMock:
        coroutine.close()
        task = MagicMock()
        task.add_done_callback.side_effect = lambda callback: callback(task)
        return task

    return create


def closing_scan_task_start(
    started: Optional[List[str]] = None,
) -> Callable[[str, Any], None]:
    """A ``_start_scan_task`` stand-in: records, closes the runner, ends the scope.

    The real start also takes ``ran`` and ``if_never_run`` as keywords, the
    marker and the release for a task cancelled before its runner ran; a
    stand-in that never runs the scan has nothing to release through them, so
    they are accepted and left alone.
    """

    def start(scan_id: str, runner: Any, **_start_options: Any) -> None:
        if started is not None:
            started.append(scan_id)
        runner.close()
        end_the_scans_scope_as_its_task_would()

    return start
