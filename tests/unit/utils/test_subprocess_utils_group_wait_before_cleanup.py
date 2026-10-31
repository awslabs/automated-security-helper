"""The spawner waits for the child's process group before a plan's cleanup runs.

A sandbox plan's cleanup starts with sweep_writable. A wrapper that execs the
tool with no reaper can leave a grandchild running after the child has exited,
so the sweep ran while that grandchild still wrote. _wait_for_group_before_cleanup
reads the group with the module's own _group_survives, bounded by
_KILLED_GROUP_SETTLE_SECONDS, and the three sites that hold the Popen call it on
the line before run_cleanup. No process is spawned here: the probe, the clock
and the sleep are stood in for.
"""

import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.sandbox.backends import SpawnPlan

pytestmark = pytest.mark.unit

skip_on_windows = pytest.mark.skipif(
    os.name == "nt", reason="process groups are the POSIX arm of the spawner"
)


def _fake_process(pid: int = 4242) -> SimpleNamespace:
    return SimpleNamespace(pid=pid)


@skip_on_windows
def test_the_helper_polls_the_group_and_returns_before_the_cleanup_runs():
    order: list = []
    answers = iter([True, True, False])

    def survives(pgid: int) -> bool:
        order.append(("probe", pgid))
        return next(answers)

    def cleanup() -> None:
        order.append(("cleanup", None))

    plan = SpawnPlan(argv=["tool"], env={}, cleanup=[cleanup])
    with (
        patch.object(subprocess_utils, "_group_survives", side_effect=survives),
        patch.object(subprocess_utils.time, "sleep") as sleep,
    ):
        subprocess_utils._wait_for_group_before_cleanup(_fake_process())
        order.append(("returned", None))
        plan.run_cleanup()

    assert order == [
        ("probe", 4242),
        ("probe", 4242),
        ("probe", 4242),
        ("returned", None),
        ("cleanup", None),
    ]
    # One pause after each read that found the group, none after the last.
    assert sleep.call_count == 2
    sleep.assert_called_with(subprocess_utils._GROUP_WAIT_POLL_SECONDS)


@skip_on_windows
def test_a_group_that_outlives_the_bound_is_logged_and_the_helper_returns():
    clock = iter([100.0, 100.0, 100.1, 100.2, 100.3])
    with (
        patch.object(subprocess_utils, "_group_survives", return_value=True) as probe,
        patch.object(
            subprocess_utils.time, "monotonic", side_effect=lambda: next(clock)
        ),
        patch.object(subprocess_utils.time, "sleep") as sleep,
        patch.object(subprocess_utils.ASH_LOGGER, "debug") as debug,
    ):
        subprocess_utils._wait_for_group_before_cleanup(_fake_process(7))

    # Reads at 100.0, 100.1 and 100.2 are inside the 0.25 s bound; the read at
    # 100.3 is past it, so the helper logs once and returns without a kill.
    assert probe.call_count == 4
    assert sleep.call_count == 3
    debug.assert_called_once()
    assert "7" in debug.call_args.args[0]


@skip_on_windows
def test_a_child_that_is_not_a_group_leader_does_not_wait():
    with (
        patch.object(subprocess_utils, "_group_survives", return_value=False) as probe,
        patch.object(subprocess_utils.time, "sleep") as sleep,
    ):
        subprocess_utils._wait_for_group_before_cleanup(_fake_process(9))
    probe.assert_called_once_with(9)
    sleep.assert_not_called()


def test_no_child_means_nothing_is_read():
    with patch.object(subprocess_utils, "_group_survives") as probe:
        subprocess_utils._wait_for_group_before_cleanup(None)
    probe.assert_not_called()


@skip_on_windows
def test_spawn_run_waits_for_the_group_before_the_plans_cleanup():
    order: list = []
    plan = SpawnPlan(
        argv=["wrapper", "tool"], env={}, cleanup=[lambda: order.append("cleanup")]
    )

    def run(runner, args, kwargs, started):
        started.process = _fake_process(31)
        return SimpleNamespace(returncode=0)

    def wait(process):
        order.append(("wait", process.pid))

    with (
        patch.object(subprocess_utils, "_resolve_for_spawn", return_value=None),
        patch.object(subprocess_utils, "_prepare_spawn", return_value=plan),
        patch.object(subprocess_utils, "_run_recording_the_start", side_effect=run),
        patch.object(
            subprocess_utils, "_wait_for_group_before_cleanup", side_effect=wait
        ),
    ):
        result = subprocess_utils.spawn_run(["tool"])

    assert result.returncode == 0
    assert order == [("wait", 31), "cleanup"]
