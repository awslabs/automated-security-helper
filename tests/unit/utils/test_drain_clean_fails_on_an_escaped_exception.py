# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pin what tests.utils.tasks.drain_clean does with the other tasks' outcomes."""

from __future__ import annotations

import ast
import asyncio
import traceback
from pathlib import Path

import pytest

from tests.utils import tasks as tasks_module

pytestmark = pytest.mark.unit


def test_drain_clean_passes_when_every_task_is_healthy():
    """Tasks that return ``None`` leave ``drain_clean`` quietly, and so does no task."""

    async def scenario() -> list[str]:
        done: list[str] = []

        async def healthy(name: str) -> None:
            await asyncio.sleep(0)
            done.append(name)

        await tasks_module.drain_clean()
        asyncio.create_task(healthy("a"))
        asyncio.create_task(healthy("b"))
        await tasks_module.drain_clean()
        return sorted(done)

    assert asyncio.run(scenario()) == ["a", "b"]


def test_drain_clean_names_the_type_of_a_raised_exception_and_not_its_value():
    """A task that raises fails the call; the failure carries the type name only.

    The value ``secret-ish`` is in the task's exception. It must not reach the
    failure text.
    """

    async def scenario() -> tuple[object, str]:
        async def fails() -> None:
            raise ValueError("secret-ish")

        asyncio.create_task(fails())
        with pytest.raises(AssertionError) as raised:
            await tasks_module.drain_clean()
        return raised.value.args[0], str(raised.value)

    names, text = asyncio.run(scenario())
    assert names == ["ValueError"]
    assert "secret-ish" not in text


def test_drain_clean_fails_on_a_cancelled_task():
    """``CancelledError`` is a ``BaseException``, not an ``Exception``.

    A check written as ``isinstance(outcome, Exception)`` would let a cancelled
    task through; this cell is the one that fails then.
    """

    async def scenario() -> object:
        async def waits_forever() -> None:
            await asyncio.Event().wait()

        task = asyncio.create_task(waits_forever())
        task.cancel()
        with pytest.raises(AssertionError) as raised:
            await tasks_module.drain_clean()
        return raised.value.args[0]

    assert asyncio.run(scenario()) == ["CancelledError"]


def test_drain_clean_checks_a_task_that_is_created_during_the_wait():
    """A task started by one being waited on is checked too, not left to shutdown."""

    async def scenario() -> object:
        async def late_failure() -> None:
            await asyncio.sleep(0.01)
            raise ValueError("late")

        async def starter() -> None:
            asyncio.create_task(late_failure())

        asyncio.create_task(starter())
        with pytest.raises(AssertionError) as raised:
            await tasks_module.drain_clean()
        return raised.value.args[0]

    assert asyncio.run(scenario()) == ["ValueError"]


def test_drain_clean_with_tasks_waits_for_exactly_those_tasks():
    """Given a set it neither waits on the rest of the loop nor misses a failure."""

    async def scenario() -> tuple[bool, object]:
        release = asyncio.Event()

        async def bystander() -> None:
            await release.wait()

        async def fails() -> None:
            raise ValueError("in the set")

        bystander_task = asyncio.create_task(bystander())
        await tasks_module.drain_clean(tasks=[asyncio.create_task(asyncio.sleep(0))])
        still_waiting = not bystander_task.done()
        with pytest.raises(AssertionError) as raised:
            await tasks_module.drain_clean(tasks=[asyncio.create_task(fails())])
        release.set()
        await bystander_task
        return still_waiting, raised.value.args[0]

    assert asyncio.run(scenario()) == (True, ["ValueError"])


def test_drain_clean_lets_through_only_the_expected_types():
    """A test that cancels on purpose names ``CancelledError``; a ValueError still fails."""

    async def scenario() -> object:
        async def waits_forever() -> None:
            await asyncio.Event().wait()

        async def fails() -> None:
            raise ValueError("not expected")

        cancelled = asyncio.create_task(waits_forever())
        cancelled.cancel()
        await tasks_module.drain_clean(expected=(asyncio.CancelledError,))
        asyncio.create_task(fails())
        with pytest.raises(AssertionError) as raised:
            await tasks_module.drain_clean(expected=(asyncio.CancelledError,))
        return raised.value.args[0]

    assert asyncio.run(scenario()) == ["ValueError"]


def test_drain_clean_failure_leaves_no_exception_in_a_frame_it_passes_through():
    """``pytest -l`` and ``--pdb`` print the locals of the frames of a failure.

    The value ``secret-ish`` is in the task's exception, and a frame that still
    holds that exception, or the task, shows it. The test's own frame is left
    out: it is not the helper's.
    """

    async def scenario() -> str:
        async def fails() -> None:
            raise ValueError("secret-ish")

        shown = ""
        for use_tasks in (False, True):
            task = asyncio.create_task(fails())
            with pytest.raises(AssertionError) as raised:
                await (
                    tasks_module.drain_clean(tasks=[task])
                    if use_tasks
                    else tasks_module.drain_clean()
                )
            del task
            shown += "".join(
                repr(frame.f_locals)
                for frame, _ in traceback.walk_tb(raised.value.__traceback__)
                if frame.f_code.co_name != "scenario"
            )
        return shown

    assert "secret-ish" not in asyncio.run(scenario())


def test_drain_clean_raises_its_failure_and_does_not_assert_it():
    """An ``assert`` statement is stripped under ``python -O``.

    The explicit ``raise`` is what makes the failure hold there. A normal pytest
    run cannot show that, because both spellings raise ``AssertionError`` when
    asserts are on, so this reads the helper's source: no ``assert`` statement
    in ``drain_clean`` or the function it calls to sort the outcomes.
    """
    module = ast.parse(Path(tasks_module.__file__).read_text(encoding="utf-8"))
    helpers = [
        node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in {"drain_clean", "_unexpected"}
    ]
    assert {node.name for node in helpers} == {"drain_clean", "_unexpected"}
    asserted = [
        node.name
        for node in helpers
        if any(isinstance(inner, ast.Assert) for inner in ast.walk(node))
    ]
    assert asserted == []
