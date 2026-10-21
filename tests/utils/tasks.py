# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Helpers for tests that wait on the event loop's other tasks."""

from __future__ import annotations

import asyncio
from typing import Any, Iterable, Optional


async def drain(
    timeout: Optional[float] = None, return_exceptions: bool = False
) -> None:
    """Wait for every other task to finish, bounded when *timeout* is given.

    By default the wait is fail-fast, like a bare ``asyncio.gather``: the first
    task that raises propagates its exception to the caller while the other
    tasks keep running, and a cancelled task surfaces as ``CancelledError``.
    Pass ``return_exceptions=True`` to wait for every task regardless and
    discard their outcomes, as the tests that cancel or fail a scan on purpose
    do.

    The task set must be read in the caller's own task, so the bound lives
    here, around the gather alone. Wrapping ``drain()`` itself in
    ``asyncio.wait_for`` reads it in a task of ``wait_for``'s own on
    Python < 3.12 (which runs the awaited coroutine as a separate task):
    "every task but me" then includes the caller, and the gather waits on
    its own awaiter until the bound expires. ``wait_for`` over the gather
    future adds no task on any version.
    """
    pending = _other_tasks()
    if not pending:
        return
    gathered = asyncio.gather(*pending, return_exceptions=return_exceptions)
    if timeout is None:
        await gathered
    else:
        await asyncio.wait_for(gathered, timeout=timeout)


def _other_tasks() -> list[asyncio.Task]:
    """Every task but the caller's own, read in the caller's task."""
    current = asyncio.current_task()
    return [t for t in asyncio.all_tasks() if t is not current]


def _unexpected(
    outcomes: list[Any], expected: tuple[type[BaseException], ...]
) -> list[str]:
    """The type names of the outcomes that are exceptions and not in *expected*."""
    return [
        type(o).__name__
        for o in outcomes
        if isinstance(o, BaseException) and not isinstance(o, expected)
    ]


async def drain_clean(
    tasks: Optional[Iterable[asyncio.Future]] = None,
    expected: tuple[type[BaseException], ...] = (),
) -> None:
    """Wait for tasks and fail if any of them ended with an unexpected exception.

    ``drain(return_exceptions=True)`` discards a task's exception, so a caller
    that uses it never sees one. A scan runner records its own failure in the
    scan registry and returns, so every task a scan test waits on should end
    with ``None``; an exception or a cancellation that escapes a task is then
    a change worth failing on, not a result to swallow.

    Without *tasks* it waits for every other task, then again for any task
    those created while they ran, until none is left, so a task started during
    the wait is checked too. With *tasks* it waits for exactly those, for a
    caller that owns a set (the scan tasks) and must not wait on the rest of
    the loop. A test that cancels a task or fails a scan on purpose names the
    exception types it expects in *expected*; any other one still fails.

    The failure is an ``AssertionError`` raised explicitly (an ``assert``
    statement is stripped under ``python -O``) and it carries the exception
    type names only. Nothing that holds an exception, which carries the task's
    message, stays in this frame when it raises, so a traceback that shows
    locals (``pytest -l``, ``--pdb``) does not print one either.
    """
    escaped: list[str] = []
    if tasks is None:
        while True:
            batch = _other_tasks()
            if not batch:
                break
            outcomes = await asyncio.gather(*batch, return_exceptions=True)
            escaped.extend(_unexpected(outcomes, expected))
            del outcomes, batch
    else:
        batch = list(tasks)
        del tasks
        if batch:
            outcomes = await asyncio.gather(*batch, return_exceptions=True)
            escaped.extend(_unexpected(outcomes, expected))
            del outcomes
        del batch
    if escaped:
        raise AssertionError(escaped)
