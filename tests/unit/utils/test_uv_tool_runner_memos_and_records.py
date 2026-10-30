# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv runner remembers only what holds everywhere, and records what happened.

Each test pins one change in ``utils/uv_tool_runner.py``:

* ``UVToolRetryConfig`` normalizes a None, non-numeric, NaN or infinite knob to
  its default and bounds every delay, and ``_install_retry_delay`` is finite for
  any base and attempt; the wait between attempts stops at a cancel and hands
  the sleep chunks counted from the delay, never from a clock read back;
* a failure after the install's child started drops the memos, as a timeout
  does, and says the result is unknown; the broken-symlink removal runs only
  when an install may happen;
* the install's progress monitor reads its stop flag before each callback, so an
  attempt that has ended gets no further progress line;
* ``validate_cached_tool`` passes the caller's values to the version probe;
* ``run_tool`` passes the plugin's ``--with`` dependencies, disavows the
  argv-quoting chain of the fallback branch's errors, and records a refused stop
  on the fallback timeout as the result's own fields;
* the version probe lock is per tool, a probe that failed inside a sandbox scope
  is not remembered, and a program not found from inside a scope is not
  remembered as uv's absence;
* ``get_uv_tool_command`` decodes its probe with a fixed codec and shares the
  probe's answer across scanned trees;
* ``shown_uv_output`` with ``limit=0`` keeps nothing.
"""

from __future__ import annotations

import math
import os
import subprocess  # nosec B404
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRetryConfig,
    UVToolRunner,
    UVToolRunnerError,
    _install_retry_delay,
    _reset_uv_tool_runner_caches,
    _sleep_between_attempts,
    checking_only,
    get_uv_tool_command,
    shown_uv_output,
)

pytestmark = pytest.mark.unit

UV_PATH = os.path.abspath("/opt/uv/bin/uv")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    _reset_uv_tool_runner_caches()
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("UV_OFFLINE", raising=False)
    yield
    _reset_uv_tool_runner_caches()


@pytest.fixture
def spawn(monkeypatch):
    mock = MagicMock()
    mock.return_value = subprocess.CompletedProcess([], 1, "", "")
    monkeypatch.setattr(uv_tool_runner, "spawn_run", mock)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: UV_PATH)
    monkeypatch.setattr(uv_tool_runner, "find_executable", lambda name: None)
    return mock


@pytest.fixture
def runner():
    r = UVToolRunner(uv_executable=UV_PATH)
    r._uv_available_cache = True
    return r


class TestTheRetryScheduleNeverRaises:
    def test_a_knob_that_is_not_a_number_takes_its_default(self):
        config = UVToolRetryConfig(
            max_retries=None,
            base_delay="not a number",
            max_delay=float("inf"),
            exponential_base=float("nan"),
        )
        assert (config.max_retries, config.base_delay) == (3, 1.0)
        assert (config.max_delay, config.exponential_base) == (60.0, 2.0)

    def test_a_large_base_gives_a_finite_delay(self):
        config = UVToolRetryConfig(exponential_base=1e6, max_delay=5.0, jitter=False)
        assert _install_retry_delay(config, 100) == 5.0

    def test_knobs_assigned_after_construction_still_sleep(self):
        config = UVToolRetryConfig(jitter=False)
        config.exponential_base = 1e308
        config.max_delay = math.inf
        delay = _install_retry_delay(config, 3)
        assert math.isfinite(delay) and 0.0 <= delay <= 3600.0

    def test_the_ordinary_schedule_is_unchanged(self):
        """The control."""
        config = UVToolRetryConfig(base_delay=1.0, exponential_base=2.0, jitter=False)
        assert [_install_retry_delay(config, n) for n in range(4)] == [1, 2, 4, 8]


def test_the_wait_between_attempts_stops_at_a_cancel(monkeypatch):
    calls = {"n": 0}

    def _cancelled():
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("cancelled")

    monkeypatch.setattr(cancellation, "raise_if_cancelled", _cancelled)
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="cancelled"):
        _sleep_between_attempts(60.0)
    assert time.monotonic() - started < 5.0


def test_the_wait_hands_the_sleep_chunks_that_add_up_to_the_delay(monkeypatch):
    """A sleep that returns early (a stub, a coarse clock) gets no extra chunk.

    The wait used to re-read the clock after each sleep, so a stubbed sleep made
    it spin for the whole delay in real time, handing the stub one chunk per
    spin: millions of them for a one-second backoff.
    """
    handed: list = []
    monkeypatch.setattr(uv_tool_runner.time, "sleep", handed.append)
    started = time.monotonic()
    _sleep_between_attempts(1.0)
    assert time.monotonic() - started < 0.5
    poll = uv_tool_runner._UV_PROBE_CANCEL_POLL_SECONDS
    assert len(handed) == math.ceil(1.0 / poll)
    assert all(0.0 < chunk <= poll for chunk in handed), handed
    assert sum(handed) == pytest.approx(1.0)


def test_a_wait_of_nothing_sleeps_nothing(monkeypatch):
    handed: list = []
    monkeypatch.setattr(uv_tool_runner.time, "sleep", handed.append)
    _sleep_between_attempts(0.0)
    _sleep_between_attempts(-3.0)
    assert handed == []


def test_a_chunk_count_one_too_high_hands_the_sleep_nothing_negative(monkeypatch):
    """The last chunk is the delay minus the chunks before it; a count one too
    high would make it negative, and ``time.sleep`` raises on a negative.

    No pair of floats was found that rounds the division and the multiplication
    apart for the real poll (two million delays and every schedule shape were
    tried), so the count is forced one too high here to read the clamp.

    The delay must make the forced extra chunk NEGATIVE, not zero: with 1.0 and
    a poll of 0.2 both are exact in doubles (1.0 / 0.2 == 5.0, 5 * 0.2 == 1.0),
    so the extra chunk is 0.0 with or without the clamp and nothing is read.
    With 1.1 the extra chunk is 1.1 - 6 * 0.2, about -0.1 in doubles, so an
    unclamped wait hands the sleep a negative and the clamp hands it 0.0.
    """
    real_ceil = math.ceil
    monkeypatch.setattr(uv_tool_runner.math, "ceil", lambda value: real_ceil(value) + 1)
    handed: list = []
    monkeypatch.setattr(uv_tool_runner.time, "sleep", handed.append)
    poll = uv_tool_runner._UV_PROBE_CANCEL_POLL_SECONDS
    delay = 1.1
    assert delay - real_ceil(delay / poll) * poll < 0.0, "the delay must overshoot"
    _sleep_between_attempts(delay)
    assert len(handed) == real_ceil(delay / poll) + 1
    assert all(0.0 <= chunk <= poll for chunk in handed), handed
    assert handed[-1] == 0.0
    assert sum(handed) == pytest.approx(delay)


class TestTheInstallArms:
    def test_a_failure_after_the_child_started_drops_the_memos(
        self, runner, spawn, monkeypatch
    ):
        monkeypatch.setattr(runner, "is_tool_installed", lambda name: False)
        dropped: list = []
        monkeypatch.setattr(
            uv_tool_runner, "invalidate_tool_version_cache", dropped.append
        )
        error = RuntimeError("the wait broke")
        setattr(
            error,
            subprocess_utils._STARTED_CHILD_ATTRIBUTE,
            SimpleNamespace(process=object()),
        )
        spawn.side_effect = error
        with pytest.raises(UVToolRunnerError) as raised:
            runner.install_tool_with_version("bandit")
        assert "started but its result could not be read" in str(raised.value)
        assert dropped == ["bandit"]

    def test_a_child_that_never_started_keeps_the_memos(
        self, runner, spawn, monkeypatch
    ):
        """The control."""
        monkeypatch.setattr(runner, "is_tool_installed", lambda name: False)
        dropped: list = []
        monkeypatch.setattr(
            uv_tool_runner, "invalidate_tool_version_cache", dropped.append
        )
        spawn.side_effect = RuntimeError("never started")
        with pytest.raises(UVToolRunnerError, match="Unexpected error"):
            runner.install_tool_with_version("bandit")
        assert dropped == []

    def test_a_dependency_question_removes_no_file(self, runner, spawn, monkeypatch):
        monkeypatch.setattr(runner, "is_tool_installed", lambda name: False)
        monkeypatch.setattr(
            uv_tool_runner, "find_executable", lambda name: "/opt/tools/bandit"
        )
        monkeypatch.setattr(
            subprocess_utils, "find_executable", lambda name: "/opt/tools/bandit"
        )
        monkeypatch.setattr(os.path, "exists", lambda path: False)
        removed: list = []
        monkeypatch.setattr(os, "remove", removed.append)
        with checking_only():
            assert runner.install_tool_with_version("bandit") is False
        assert removed == []

    def test_the_cached_tool_check_passes_the_callers_values(self, runner):
        runner.get_tool_version = MagicMock(return_value="1.2.3")
        result = runner.validate_cached_tool("bandit", "bandit[sarif]", values=("v",))
        assert result["is_functional"] is True
        assert runner.get_tool_version.call_args.kwargs["values"] == ("v",)


class TestTheProgressMonitor:
    """The monitor reads its stop flag before each callback.

    The monitor thread is replaced by a stand-in that only records its target,
    so the test runs the monitor's body itself AFTER the attempt ended (the
    attempt's finally set the stop flag): a monitor that reads the flag first
    calls back nothing, one that does not calls back once more.
    """

    def _install_with_a_recorded_monitor(self, runner, spawn, monkeypatch):
        from automated_security_helper.utils import threads

        monitors: list = []

        class _RecordedThread:
            def __init__(self, target, daemon=False):
                monitors.append(target)

            def start(self):
                pass

            def join(self, timeout=None):
                pass

        monkeypatch.setattr(
            threads, "ash_thread", lambda target, daemon=False: _RecordedThread(target)
        )
        monkeypatch.setattr(runner, "is_tool_installed", lambda name: False)
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
        lines: list = []
        assert (
            runner.install_tool_with_version(
                "bandit", timeout=120, progress_callback=lines.append
            )
            is True
        )
        assert len(monitors) == 1, "the install started no progress monitor"
        return monitors[0], lines

    def test_an_ended_attempt_gets_no_further_line(self, runner, spawn, monkeypatch):
        monitor, lines = self._install_with_a_recorded_monitor(
            runner, spawn, monkeypatch
        )
        monitor()
        assert lines == [], lines

    def test_a_live_attempt_reports_progress(self, runner, spawn, monkeypatch):
        """The control: with the stop flag clear the monitor calls back. The
        monitor's body is run from inside the (stand-in) uv install, while the
        attempt is live; the callback ends the loop by raising, since the body
        otherwise loops until the attempt's timeout."""
        from automated_security_helper.utils import threads

        class _Stop(BaseException):
            pass

        monitors: list = []

        class _RecordedThread:
            def __init__(self, target, daemon=False):
                monitors.append(target)

            def start(self):
                pass

            def join(self, timeout=None):
                pass

        monkeypatch.setattr(
            threads, "ash_thread", lambda target, daemon=False: _RecordedThread(target)
        )
        monkeypatch.setattr(runner, "is_tool_installed", lambda name: False)
        lines: list = []

        def _callback(line):
            lines.append(line)
            raise _Stop

        def _spawn(*args, **kwargs):
            monitors[0]()
            return subprocess.CompletedProcess([], 0, "", "")

        spawn.side_effect = _spawn
        with pytest.raises(_Stop):
            runner.install_tool_with_version(
                "bandit", timeout=120, progress_callback=_callback
            )
        assert len(lines) == 1 and "Installation in progress" in lines[0], lines


class TestRunTool:
    def test_the_with_dependencies_ride_the_run(self, runner, spawn):
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
        runner.run_tool(
            "jupyter-nbconvert",
            package_name="nbconvert",
            with_dependencies=["jupyter", "nbformat>=5"],
        )
        argv = spawn.call_args.args[0]
        assert argv[argv.index("--with") :][:4] == [
            "--with",
            "jupyter",
            "--with",
            "nbformat>=5",
        ]
        assert argv.index("--with") < argv.index("jupyter-nbconvert")

    def test_a_dependency_that_is_not_a_requirement_is_refused(self, runner, spawn):
        with pytest.raises(UVToolRunnerError, match="--with dependency 1"):
            runner.run_tool("bandit", with_dependencies=["bandit @ file:///x"])
        assert spawn.call_count == 0

    def test_the_fallback_exit_error_disavows_its_chain(self, runner, spawn):
        spawn.side_effect = subprocess.CalledProcessError(2, ["uv", "secret-arg"])
        with pytest.raises(UVToolRunnerError) as raised:
            runner.run_tool("bandit", check=True)
        assert raised.value.__suppress_context__ is True
        assert raised.value.__cause__ is None

    def test_the_fallback_timeout_records_a_refused_stop(self, runner, spawn):
        error = subprocess.TimeoutExpired(["uv"], 5, output="", stderr="")
        child = SimpleNamespace(
            process=SimpleNamespace(pid=4242, poll=lambda: None),
            not_stopped=lambda: "the stop was refused (pid 4242)",
            not_stopped_pid=lambda: 4242,
        )
        setattr(error, subprocess_utils._STARTED_CHILD_ATTRIBUTE, child)
        spawn.side_effect = error
        result = runner.run_tool("bandit", timeout=5)
        assert result.timed_out is True
        assert result.returncode is None
        assert result.could_not_stop is True
        assert result.could_not_stop_pid == 4242

    def test_a_stop_that_worked_keeps_the_timeout_code(self, runner, spawn):
        """The control."""
        error = subprocess.TimeoutExpired(["uv"], 5, output="", stderr="")
        child = SimpleNamespace(
            process=SimpleNamespace(pid=4242, poll=lambda: 0),
            not_stopped=lambda: None,
            not_stopped_pid=lambda: 4242,
        )
        setattr(error, subprocess_utils._STARTED_CHILD_ATTRIBUTE, child)
        spawn.side_effect = error
        result = runner.run_tool("bandit", timeout=5)
        assert result.returncode == subprocess_utils.TIMEOUT_RETURNCODE
        assert getattr(result, "could_not_stop", False) is False


class TestTheVersionProbe:
    def test_the_probe_lock_is_per_tool(self, runner, spawn, monkeypatch):
        keys: list = []
        real = uv_tool_runner._get_or_create_probe_lock

        def _lock(key):
            keys.append(key)
            return real(key)

        monkeypatch.setattr(uv_tool_runner, "_get_or_create_probe_lock", _lock)
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.7.0\n", "")
        runner.get_tool_version("bandit", "bandit[sarif]")
        assert "version::bandit" in keys
        assert not any("bandit[sarif]" in key for key in keys)

    def test_a_probe_that_failed_inside_a_scope_is_not_remembered(
        self, runner, spawn, monkeypatch
    ):
        monkeypatch.setattr(
            uv_tool_runner, "_probe_scope_key", lambda: ("backend", "x")
        )
        assert runner.get_tool_version("bandit") is None
        with uv_tool_runner._uv_tool_runner_cache_lock:
            assert "bandit::" not in uv_tool_runner._uv_tool_version_cache

    def test_a_probe_that_failed_outside_any_scope_is_remembered(
        self, runner, spawn, monkeypatch
    ):
        """The control: the memo of a failure keeps the concurrent-probe window shut."""
        monkeypatch.setattr(uv_tool_runner, "_probe_scope_key", lambda: None)
        assert runner.get_tool_version("bandit") is None
        with uv_tool_runner._uv_tool_runner_cache_lock:
            assert "bandit::" in uv_tool_runner._uv_tool_version_cache


class TestTheAvailabilityProbe:
    def test_a_program_not_found_inside_a_scope_is_not_uv_s_absence(
        self, spawn, monkeypatch
    ):
        monkeypatch.setattr(
            uv_tool_runner, "_probe_scope_key", lambda: ("backend", "x")
        )
        monkeypatch.setattr(subprocess_utils, "in_tree_refusal", lambda path: None)
        spawn.side_effect = FileNotFoundError(2, "No such file", UV_PATH)
        probed = UVToolRunner(uv_executable=UV_PATH)
        available, failure = probed.uv_availability()
        assert available is False
        assert "sandbox scope" in (failure or "")
        assert probed._uv_available_cache is None

    def test_a_program_not_found_outside_any_scope_is(self, spawn, monkeypatch):
        """The control."""
        monkeypatch.setattr(uv_tool_runner, "_probe_scope_key", lambda: None)
        monkeypatch.setattr(subprocess_utils, "in_tree_refusal", lambda path: None)
        spawn.side_effect = FileNotFoundError(2, "No such file", UV_PATH)
        probed = UVToolRunner(uv_executable=UV_PATH)
        assert probed.uv_availability() == (False, None)
        assert probed._uv_available_cache is False


class TestGetUvToolCommand:
    def test_the_probe_decodes_with_a_fixed_codec(self, spawn):
        get_uv_tool_command("bandit")
        kwargs = spawn.call_args.kwargs
        assert kwargs["encoding"] == "utf-8" and kwargs["errors"] == "replace"

    def test_the_probes_answer_is_shared_across_scanned_trees(self, spawn, monkeypatch):
        scopes = iter([("tree", "a"), ("tree", "b")])
        monkeypatch.setattr(subprocess_utils, "tree_scope_key", lambda: next(scopes))
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.0\n", "")
        first = get_uv_tool_command("bandit")
        second = get_uv_tool_command("bandit")
        assert first == second == ["uv", "tool", "run", "bandit"]
        assert spawn.call_count == 1, spawn.call_args_list


def test_a_limit_of_zero_keeps_nothing():
    assert shown_uv_output("abc", (), limit=0) == "(first 3 characters not shown) "


def test_the_probe_lock_helper_still_serializes():
    """The control for the lock-key change: one key, one lock object."""
    with uv_tool_runner._uv_tool_runner_cache_lock:
        first = uv_tool_runner._get_or_create_probe_lock("version::bandit")
        second = uv_tool_runner._get_or_create_probe_lock("version::bandit")
    assert first is second
    assert isinstance(first, type(threading.Lock()))


class TestARefusedCheckIsReportedAsTheSandboxRefusingUv:
    """The runner records a sandbox refusal on the check that it refused, and
    the mixin's words for that check name the refusal, not the failed spawn.

    This module keeps the real probes (``tests/unit/conftest.py``), so the
    refusal below reaches the runner the way it does in a scan: the spawn layer
    resolves the program (an existing one, this interpreter) and then asks the
    active scope, which refuses, and the runner's refused-spawn arm records it.
    """

    @staticmethod
    def _refused(runner):
        from automated_security_helper.base.uv_tool_mixin import _uv_available
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )

        with sandbox_scope(RefusingScope("jupyter", "firejail is not installed")):  # type: ignore[arg-type]
            return _uv_available(runner)

    def test_the_reporting_names_the_refusal_before_the_spawn_words(self):
        from automated_security_helper.base.uv_tool_mixin import _uv_unavailable

        runner = UVToolRunner(uv_executable=sys.executable)
        available, failure = self._refused(runner)
        assert available is False
        # The control: the refusal did reach the runner as a refused spawn, so
        # the probe's own words name the exception, and the recorded refusal
        # is what the mixin has to prefer.
        assert failure is not None and "SandboxUnavailable" in failure, failure
        text = _uv_unavailable(runner, failure)
        assert "scanner sandbox refused to run uv" in text, text
        assert "firejail is not installed" in text, text
        assert "SandboxUnavailable" not in text, text
        assert "UV is not available" not in text, text

    def test_the_version_check_logs_the_refusal(self):
        from tests.unit.base.test_uv_tool_mixin_guards_and_decisions import (
            FakePlugin,
        )
        from automated_security_helper.utils.sandbox.scope import (
            RefusingScope,
            sandbox_scope,
        )

        plugin = FakePlugin(command="jupyter-nbconvert", use_uv_tool=True)
        runner = UVToolRunner(uv_executable=sys.executable)
        with (
            patch(
                "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
                return_value=runner,
            ),
            sandbox_scope(RefusingScope("jupyter", "firejail is not installed")),  # type: ignore[arg-type]
        ):
            assert plugin._get_uv_tool_version("jupyter-nbconvert") is None
        ((message,), _level) = plugin._log_messages[-1]
        assert "scanner sandbox refused to run uv" in message, message
        assert "firejail is not installed" in message, message
        assert "jupyter-nbconvert version detection" in message, message
        assert "UV is not available" not in message, message

    def test_a_probe_failure_that_is_not_a_refusal_keeps_its_own_words(self):
        """The control for the order: with nothing recorded, the probe's words win."""
        from automated_security_helper.base.uv_tool_mixin import _uv_unavailable

        runner = UVToolRunner(uv_executable=sys.executable)
        text = _uv_unavailable(runner, "the probe timed out after 10 seconds")
        assert text == "uv is not available (the probe timed out after 10 seconds)"
        assert _uv_unavailable(runner, None) == "UV is not available"
