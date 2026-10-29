# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A post-run failure after a signal death keeps both facts, and only real ones.

Why this file exists
--------------------
A tool that ended on a signal ASH did not send keeps its negative code through a
post-run failure (``post_run_error`` with ``signaled`` and the signal's number).
Each fact can be lost on its own:

- the uv runner's conversion picks one type per response, so a response carrying
  both flags must convert to the type that holds both, not drop the post-run
  error for the signal;
- the failure-after-the-start builders assemble their responses themselves, so
  the signal has to ride their shapes too;
- on the paths where ASH's own wait raised, the server's final stop can be what
  killed the child, and ASH's own signal must never be reported as one it did
  not send;
- the typed results read ``signal`` beside ``signaled`` only, so an unsignaled
  instance answers None rather than raising, and a signaled one without a given
  number derives it from the kept negative code.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from unittest.mock import patch

import pytest

from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import (
    PostRunError,
    PostRunErrorProcess,
    StartWatch,
    run_command,
    run_command_with_output_handling,
    spawn_run,
    spawn_run_failure_after_the_start,
    watched_launch,
)
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    _reset_uv_tool_runner_caches,
)

from utils.test_a_failure_while_waiting_on_a_started_child_keeps_its_code import (
    _communicate_returns_then_raises,
    _tool_that_ends_by_its_own_signal,
)

_RCWOH = (
    "automated_security_helper.utils.subprocess_utils.run_command_with_output_handling"
)
_POSIX = pytest.mark.skipif(os.name != "posix", reason="a signal death is POSIX's case")

#: What a reported signal death says; absent whenever the signal could be ASH's.
NOT_ASHS_SIGNAL = "a signal ASH did not send"


class _Unprintable:
    def __str__(self):
        raise RuntimeError("the error cannot be shown")


@pytest.fixture
def uv_runner():
    _reset_uv_tool_runner_caches()
    runner = UVToolRunner(uv_executable="uv")
    runner._uv_available_cache = True
    yield runner
    _reset_uv_tool_runner_caches()


def _uv_result_for(uv_runner, tmp_path, response):
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    with patch(_RCWOH) as mock_run:
        mock_run.return_value = response
        return uv_runner.run_tool("bandit", args=[], results_dir=results_dir)


#: A readable error exercises the straight conversion; one whose str() raises
#: sends the conversion into its rebuilt (kept) branch.
_CONVERSION_ERRORS = pytest.mark.parametrize(
    "error", ["the run's reason", _Unprintable()], ids=["converted", "rebuilt"]
)


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_the_uv_runner_keeps_both_flags_of_a_signaled_post_run_failure(
    uv_runner, tmp_path, error
):
    """A response saying post_run_error AND signaled converts to the type that
    carries both. A conversion that kept only the signal would show ASH's own
    recording failure as nothing but the tool's ending."""
    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": -10,
            "stdout": "",
            "stderr": "",
            "post_run_error": True,
            "spawn_failed": False,
            "signaled": True,
            "signal": 10,
            "error": error,
        },
    )
    assert getattr(result, "post_run_error", False) is True, result
    assert getattr(result, "signaled", False) is True, result
    assert getattr(result, "signal", None) == 10, result
    assert result.returncode == -10, result


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_the_uv_runner_copies_the_signal_of_a_signaled_only_response(
    uv_runner, tmp_path, error
):
    """The control: a signal death with no post-run failure stays a signaled
    result, with the number as the typed result's own field."""
    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": -10,
            "stdout": "",
            "stderr": "",
            "signaled": True,
            "signal": 10,
            "error": error,
        },
    )
    assert getattr(result, "signaled", False) is True, result
    assert getattr(result, "signal", None) == 10, result
    assert getattr(result, "post_run_error", False) is False, result


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_a_timed_out_response_with_stray_flags_stays_a_timeout(
    uv_runner, tmp_path, error
):
    """A timeout is never turned into a post-run error, whatever else the
    response says: timed_out wins the typing even over the both-flags pair."""
    from automated_security_helper.utils.subprocess_utils import TimedOutProcess

    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": True,
            "post_run_error": True,
            "signaled": True,
            "signal": 9,
            "error": error,
        },
    )
    assert isinstance(result, TimedOutProcess), result
    assert getattr(result, "timed_out", False) is True, result


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_a_timed_out_response_does_not_take_a_signal_label(uv_runner, tmp_path, error):
    """The signal copy rides only the types that carry the ending (signaled and
    post-run results): a timed-out result keeps its class defaults, since a
    child ASH's timeout stopped has no ending of its own to report."""
    from automated_security_helper.utils.subprocess_utils import TimedOutProcess

    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": True,
            "signaled": True,
            "signal": 9,
            "error": error,
        },
    )
    assert isinstance(result, TimedOutProcess), result
    assert getattr(result, "signaled", False) is False, result
    assert getattr(result, "signal", None) is None, result


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_a_cancelled_response_with_stray_flags_stays_a_cancel(
    uv_runner, tmp_path, error
):
    """A cancel is never turned into a post-run error either: cancelled wins
    the typing over the both-flags pair, and the cancelled result takes no
    signal label, since ASH's cancel stopped the child."""
    from automated_security_helper.utils.subprocess_utils import CancelledProcess

    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": -9,
            "stdout": "",
            "stderr": "",
            "cancelled": True,
            "post_run_error": True,
            "signaled": True,
            "signal": 9,
            "error": error,
        },
    )
    assert isinstance(result, CancelledProcess), result
    assert getattr(result, "cancelled", False) is True, result
    assert getattr(result, "signaled", False) is False, result
    assert getattr(result, "signal", None) is None, result


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_a_rejected_result_with_a_stray_signal_stays_rejected(
    uv_runner, tmp_path, error
):
    """A rejected result's code is ASH's fixed one, never the code the result
    claimed, so a signal read from a code cannot be the tool's ending there:
    result_rejected wins the typing, and the result takes no signal label."""
    from automated_security_helper.utils.subprocess_utils import (
        ResultRejectedProcess,
    )

    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": -9,
            "stdout": "",
            "stderr": "",
            "result_rejected": True,
            "signaled": True,
            "signal": 9,
            "error": error,
        },
    )
    assert isinstance(result, ResultRejectedProcess), result
    assert getattr(result, "result_rejected", False) is True, result
    assert getattr(result, "signaled", False) is False, result
    assert getattr(result, "signal", None) is None, result


@pytest.mark.unit
@_CONVERSION_ERRORS
def test_a_rejected_result_with_stray_post_run_flags_stays_rejected(
    uv_runner, tmp_path, error
):
    """The same with the post-run pair beside it: the rejection is still the
    fact the result reports, ahead of the both-flags case."""
    from automated_security_helper.utils.subprocess_utils import (
        ResultRejectedProcess,
    )

    result = _uv_result_for(
        uv_runner,
        tmp_path,
        {
            "returncode": -9,
            "stdout": "",
            "stderr": "",
            "result_rejected": True,
            "post_run_error": True,
            "signaled": True,
            "signal": 9,
            "error": error,
        },
    )
    assert isinstance(result, ResultRejectedProcess), result
    assert getattr(result, "signaled", False) is False, result


@pytest.mark.integration
@_POSIX
def test_a_returned_signal_death_whose_result_cannot_be_built_is_logged_once(
    tmp_path, monkeypatch, caplog
):
    """The run returned a signal death and building its result then raised.
    The handler's failure line carries the death, so that line is its only
    record: logging the death before the result exists would report the same
    ending twice when the construction fails."""
    import logging

    def refuses(*args, **kwargs):
        raise RuntimeError("building the result failed")

    monkeypatch.setattr(subprocess_utils, "SignaledProcess", refuses)
    marker = tmp_path / "ran"
    with caplog.at_level(logging.DEBUG, logger="ash"):
        result = run_command(_tool_that_ends_by_its_own_signal(marker))
    assert marker.exists(), "the tool never started, so the cell shows nothing"
    assert getattr(result, "post_run_error", False) is True, result
    assert getattr(result, "signaled", False) is True, result
    assert result.error.count(NOT_ASHS_SIGNAL) == 1, result.error
    deaths = [r for r in caplog.records if NOT_ASHS_SIGNAL in r.getMessage()]
    assert len(deaths) == 1, [r.getMessage() for r in deaths]


@pytest.mark.integration
@_POSIX
def test_a_failed_wait_while_the_server_stops_reports_no_signal(tmp_path, monkeypatch):
    """Once the server's last stop has begun, a SIGKILL that ended a waited-on
    child can be ASH's own, so the failure is reported without the signal label.
    The post-run facts themselves (the flag, the kept code) stay."""
    first, second = tmp_path / "first", tmp_path / "second"
    monkeypatch.setattr(subprocess_utils, "_server_stopping", lambda: True)
    with _communicate_returns_then_raises():
        result = run_command(_tool_that_ends_by_its_own_signal(first, signal.SIGKILL))
        response = run_command_with_output_handling(
            _tool_that_ends_by_its_own_signal(second, signal.SIGKILL),
            results_dir=tmp_path / "results",
        )
    assert first.exists() and second.exists(), "the tool never started"
    assert getattr(result, "post_run_error", False) is True, result
    assert getattr(result, "signaled", False) is False, result
    assert NOT_ASHS_SIGNAL not in (getattr(result, "error", "") or ""), result
    assert response["post_run_error"] is True, response
    assert response.get("signaled") is not True, response
    assert NOT_ASHS_SIGNAL not in response["error"], response


@pytest.mark.integration
@_POSIX
def test_a_tools_own_signal_during_a_server_stop_keeps_the_label(tmp_path, monkeypatch):
    """Only the signals ASH's stops send (SIGKILL, SIGTERM) are withheld while
    the server stops: a tool that ended itself with SIGHUP keeps the flag, the
    number and the death text even then. The spawn record cannot say whether the
    server's final stop signaled this group, but that stop never sends SIGHUP."""
    first, second = tmp_path / "first", tmp_path / "second"
    monkeypatch.setattr(subprocess_utils, "_server_stopping", lambda: True)
    with _communicate_returns_then_raises():
        result = run_command(_tool_that_ends_by_its_own_signal(first, signal.SIGHUP))
        response = run_command_with_output_handling(
            _tool_that_ends_by_its_own_signal(second, signal.SIGHUP),
            results_dir=tmp_path / "results",
        )
    assert first.exists() and second.exists(), "the tool never started"
    assert getattr(result, "signaled", False) is True, result
    assert getattr(result, "signal", None) == int(signal.SIGHUP), result
    assert NOT_ASHS_SIGNAL in (getattr(result, "error", "") or ""), result
    assert response.get("signaled") is True, response
    assert response.get("signal") == int(signal.SIGHUP), response
    assert NOT_ASHS_SIGNAL in response["error"], response


@pytest.mark.integration
@_POSIX
def test_the_builders_keep_a_tools_own_signal_during_a_server_stop(
    tmp_path, monkeypatch
):
    """The same distinction in the failure-after-the-start builders: SIGUSR1 is
    not a signal ASH's stops send, so the label survives a stopping server."""
    signum = int(signal.SIGUSR1)
    args = _tool_that_ends_by_its_own_signal(tmp_path / "started", signum)
    watch = StartWatch()
    raised = None
    with _communicate_returns_then_raises(), watch.watching():
        try:
            # Under watched_launch, as the real runner holds it around the
            # launch's own spawn: only such a record answers for the launch.
            with watched_launch():
                spawn_run(args, capture_output=True, text=True)
        except Exception as error:
            raised = error
    assert raised is not None, "spawn_run returned, so the cell shows nothing"
    monkeypatch.setattr(subprocess_utils, "_server_stopping", lambda: True)
    after = spawn_run_failure_after_the_start(args, raised)
    assert after is not None and after.signaled is True, after
    assert after.signal == signum, after
    response = watch.failure_after_the_start(raised)
    assert response is not None and response.get("signaled") is True, response
    assert response.get("signal") == signum, response


@pytest.mark.integration
@_POSIX
def test_a_failed_wait_on_a_running_server_keeps_the_signal(tmp_path):
    """The same recipe with the server running: the SIGKILL was not ASH's, so
    the failure keeps the signal beside the post-run error."""
    marker = tmp_path / "started"
    with _communicate_returns_then_raises():
        result = run_command(_tool_that_ends_by_its_own_signal(marker, signal.SIGKILL))
    assert marker.exists(), "the tool never started"
    assert getattr(result, "post_run_error", False) is True, result
    assert getattr(result, "signaled", False) is True, result
    assert getattr(result, "signal", None) == int(signal.SIGKILL), result
    assert NOT_ASHS_SIGNAL in (getattr(result, "error", "") or ""), result


@pytest.mark.integration
@_POSIX
def test_the_failure_after_the_start_builders_keep_a_signal_death(tmp_path):
    """StartWatch.failure_after_the_start and spawn_run_failure_after_the_start
    build their responses themselves, so the signal has to ride their shapes:
    the flag, the number, and a reason that leads with the death."""
    signum = int(signal.SIGUSR1)
    args = _tool_that_ends_by_its_own_signal(tmp_path / "started", signum)
    watch = StartWatch()
    raised = None
    with _communicate_returns_then_raises(), watch.watching():
        try:
            # Under watched_launch, as the real runner holds it around the
            # launch's own spawn: only such a record answers for the launch.
            with watched_launch():
                spawn_run(args, capture_output=True, text=True)
        except Exception as error:  # the wait's own failure
            raised = error
    assert raised is not None, "spawn_run returned, so the cell shows nothing"
    after = spawn_run_failure_after_the_start(args, raised)
    assert after is not None, after
    assert after.signaled is True, after
    assert after.signal == signum, after
    assert after.post_run_error is True, after
    assert after.returncode == -signum, after
    assert NOT_ASHS_SIGNAL in after.error, after
    response = watch.failure_after_the_start(raised)
    assert response is not None, response
    assert response.get("signaled") is True, response
    assert response.get("signal") == signum, response
    assert response["post_run_error"] is True, response
    assert NOT_ASHS_SIGNAL in response["error"], response


@pytest.mark.integration
@_POSIX
def test_the_builders_report_no_signal_while_the_server_stops(tmp_path, monkeypatch):
    """The builders read a code from a wait that raised, so a stopping server's
    own kill must not be labeled: no flag, no number, no death wording."""
    args = _tool_that_ends_by_its_own_signal(tmp_path / "started", signal.SIGKILL)
    watch = StartWatch()
    raised = None
    with _communicate_returns_then_raises(), watch.watching():
        try:
            # Under watched_launch, as the real runner holds it around the
            # launch's own spawn: only such a record answers for the launch.
            with watched_launch():
                spawn_run(args, capture_output=True, text=True)
        except Exception as error:
            raised = error
    assert raised is not None, "spawn_run returned, so the cell shows nothing"
    monkeypatch.setattr(subprocess_utils, "_server_stopping", lambda: True)
    after = spawn_run_failure_after_the_start(args, raised)
    assert after is not None and after.signaled is False, after
    assert after.signal is None, after
    assert NOT_ASHS_SIGNAL not in after.error, after
    response = watch.failure_after_the_start(raised)
    assert response is not None and response.get("signaled") is not True, response
    assert NOT_ASHS_SIGNAL not in response["error"], response


@pytest.mark.integration
@_POSIX
def test_a_signal_death_on_a_failed_wait_is_logged_once(tmp_path, caplog):
    """The death appears in one log record: the failure line that carries the
    death-led reason. A second record saying the same ending is noise that
    doubles every signal death in a scan's log."""
    import logging

    first, second = tmp_path / "first", tmp_path / "second"
    with caplog.at_level(logging.ERROR, logger="ash"):
        with _communicate_returns_then_raises():
            result = run_command(_tool_that_ends_by_its_own_signal(first))
            response = run_command_with_output_handling(
                _tool_that_ends_by_its_own_signal(second),
                results_dir=tmp_path / "results",
            )
    assert first.exists() and second.exists(), "the tool never started"
    # The flag still rides both shapes: fewer records, not fewer facts.
    assert getattr(result, "signaled", False) is True, result
    assert response.get("signaled") is True, response
    deaths = [r for r in caplog.records if NOT_ASHS_SIGNAL in r.getMessage()]
    assert len(deaths) == 2, [r.getMessage() for r in deaths]
    # One per run: each record names its own command (the marker path rides in
    # the command text), so two records here means once per death, not twice.
    run_one = [r for r in deaths if str(first) in r.getMessage()]
    run_two = [r for r in deaths if str(second) in r.getMessage()]
    assert len(run_one) == 1, [r.getMessage() for r in deaths]
    assert len(run_two) == 1, [r.getMessage() for r in deaths]


@pytest.mark.integration
@_POSIX
@pytest.mark.parametrize("builder", ["spawn_run_builder", "start_watch"])
def test_the_builders_log_a_signal_death_once(tmp_path, caplog, builder):
    """The failure-after-the-start builders have no failure line of their own,
    so the death they read is logged by them, once. Their callers log ASH's own
    error at most, never the death, so without this the ending is never logged."""
    import logging

    signum = int(signal.SIGUSR1)
    args = _tool_that_ends_by_its_own_signal(tmp_path / "started", signum)
    watch = StartWatch()
    raised = None
    with _communicate_returns_then_raises(), watch.watching():
        try:
            # Under watched_launch, as the real runner holds it around the
            # launch's own spawn: only such a record answers for the launch.
            with watched_launch():
                spawn_run(args, capture_output=True, text=True)
        except Exception as error:
            raised = error
    assert raised is not None, "spawn_run returned, so the cell shows nothing"
    with caplog.at_level(logging.DEBUG, logger="ash"):
        if builder == "spawn_run_builder":
            out = spawn_run_failure_after_the_start(args, raised)
            assert out is not None and out.signaled is True, out
        else:
            response = watch.failure_after_the_start(raised)
            assert response is not None and response.get("signaled") is True, response
    deaths = [r for r in caplog.records if NOT_ASHS_SIGNAL in r.getMessage()]
    assert len(deaths) == 1, [r.getMessage() for r in deaths]


#: Writes a diagnostic, then ends itself by SIGUSR1 with the default action.
_WRITES_THEN_DIES = (
    "import os, signal, sys; signal.signal(signal.SIGUSR1, signal.SIG_DFL); "
    "sys.stderr.write('diag\\n'); sys.stderr.flush(); os.kill(os.getpid(), signal.SIGUSR1)"
)


@pytest.mark.integration
@_POSIX
def test_a_stream_log_write_after_the_death_logs_it_once(tmp_path, caplog):
    """A stream log that cannot be written fails after the run was read, so the
    response already carries the death. The late path adds ASH's own failure and
    reads the death no second time: the error holds it once, and one log record
    carries it. This is the only cell that tells the late path's dedup guard
    from one that always recomputes."""
    import logging

    with caplog.at_level(logging.DEBUG, logger="ash"):
        with patch.object(
            subprocess_utils, "_write_stream_log", side_effect=OSError("disk full")
        ):
            response = run_command_with_output_handling(
                [sys.executable, "-c", _WRITES_THEN_DIES],
                results_dir=tmp_path / "results",
            )
    assert response.get("post_run_error") is True, response
    assert response.get("signaled") is True, response
    assert response["error"].count(NOT_ASHS_SIGNAL) == 1, response["error"]
    deaths = [r for r in caplog.records if NOT_ASHS_SIGNAL in r.getMessage()]
    assert len(deaths) == 1, [r.getMessage() for r in deaths]


@pytest.mark.integration
@_POSIX
def test_a_cleanup_failure_before_the_run_was_read_logs_the_death_once(
    tmp_path, caplog
):
    """A failure before the response was built (the sandbox's first cleanup)
    leaves the late path to read the death: its one log record carries it, and
    the error holds it once."""
    import logging
    from types import SimpleNamespace

    calls = []

    def cleanup():
        calls.append(1)
        if len(calls) == 1:
            raise OSError("cleanup failed")

    def plan(command, env, cwd, shell):
        return SimpleNamespace(argv=command, env=env, run_cleanup=cleanup)

    with caplog.at_level(logging.DEBUG, logger="ash"):
        with patch.object(subprocess_utils, "_prepare_spawn", side_effect=plan):
            response = run_command_with_output_handling(
                [sys.executable, "-c", _WRITES_THEN_DIES],
                results_dir=tmp_path / "results",
            )
    assert calls, "the plan was not used"
    assert response.get("post_run_error") is True, response
    assert response.get("signaled") is True, response
    assert response["error"].count(NOT_ASHS_SIGNAL) == 1, response["error"]
    deaths = [r for r in caplog.records if NOT_ASHS_SIGNAL in r.getMessage()]
    assert len(deaths) == 1, [r.getMessage() for r in deaths]


@pytest.mark.unit
def test_an_unsignaled_post_run_result_reads_signal_none():
    """``signal`` is read only beside a True ``signaled``, and reading it on an
    unsignaled instance answers None rather than raising."""
    result = PostRunErrorProcess(
        args=[sys.executable], returncode=3, stdout="", stderr="", error="e"
    )
    assert result.signaled is False, result
    assert result.signal is None, result
    raised = PostRunError([sys.executable], 3, "e")
    assert raised.signaled is False, raised
    assert raised.signal is None, raised


@pytest.mark.unit
def test_a_signaled_post_run_result_derives_the_number_from_the_code():
    """A signaled instance built without the number derives it from the kept
    negative code, as SignaledProcess derives it."""
    result = PostRunErrorProcess(
        args=[sys.executable],
        returncode=-9,
        stdout="",
        stderr="",
        error="e",
        signaled=True,
    )
    assert result.signaled is True, result
    assert result.signal == 9, result
    raised = PostRunError([sys.executable], -9, "e", signaled=True)
    assert raised.signaled is True, raised
    assert raised.signal == 9, raised


@pytest.mark.unit
def test_a_negative_code_alone_does_not_mark_a_post_run_result_signaled():
    """The flag drives the derivation, never the code alone: a caller that kept
    a negative code without saying signaled gets neither flag nor number."""
    result = PostRunErrorProcess(
        args=[sys.executable], returncode=-9, stdout="", stderr="", error="e"
    )
    assert result.signaled is False, result
    assert result.signal is None, result
    # And none of it leaked onto the class: a later unsignaled instance of
    # either type still answers the defaults.
    flagged = PostRunErrorProcess(
        args=[sys.executable],
        returncode=-9,
        stdout="",
        stderr="",
        error="e",
        signaled=True,
    )
    assert flagged.signal == 9, flagged
    fresh = PostRunErrorProcess(
        args=[sys.executable], returncode=3, stdout="", stderr="", error="e"
    )
    assert fresh.signaled is False and fresh.signal is None, fresh


@pytest.mark.unit
def test_the_signal_flags_splat_into_every_keeper_without_translation():
    """The keepers' parameter names are the producer's dict keys.

    ``_signaled_failure`` answers ``{"signaled": True, "signal": N}``, every
    keeper exposes the number as ``.signal``, and each keeper's constructor
    takes the same names, so a producer's dict splats in with no per-site
    translation. This cell pins the constructors' parameter names, not the
    call sites: it builds each keeper from the dict itself. The sites are
    pinned one by one by the cells below, each driven through its own path."""
    from automated_security_helper.utils.subprocess_utils import (
        PostRunError,
        PostRunErrorProcess,
        SignaledProcess,
        _signaled_failure,
    )

    flags, _reason = _signaled_failure(-9, "tool", "e", log_the_death=False)
    assert flags == {"signaled": True, "signal": 9}, flags

    result = PostRunErrorProcess(
        args=[sys.executable], returncode=-9, stdout="", stderr="", error="e", **flags
    )
    assert result.signaled is True and result.signal == 9, result

    raised = PostRunError([sys.executable], -9, "e", **flags)
    assert raised.signaled is True and raised.signal == 9, raised

    kept = SignaledProcess(
        args=[sys.executable],
        returncode=-9,
        stdout="",
        stderr="",
        error="e",
        signal=flags["signal"],
    )
    assert kept.signaled is True and kept.signal == 9, kept

    empty, _reason = _signaled_failure(0, "tool", "e", log_the_death=False)
    assert empty == {}, empty
    plain = PostRunErrorProcess(
        args=[sys.executable], returncode=0, stdout="", stderr="", error="e", **empty
    )
    assert plain.signaled is False and plain.signal is None, plain


# -- Each post-run builder in run_command carries the flags through its own site.
# The pin above builds the keepers itself, so it cannot tell the sites apart: a
# hand-translation put back at one site would leave it green. Each cell below
# reaches exactly one site, and asserts the flag and the number the tool ended
# on, so a site that drops or mistranslates the flags turns its own cell red.

#: The signal a stand-in run ended on, and the kept code it implies.
_STAND_IN_SIGNAL = 10


def _a_returned_run_whose_record_then_raises(monkeypatch):
    """The runner returns a run that ended on a signal, and recording that
    ending raises, so run_command fails after the run returned (``ran`` set).

    Through the runner seam (``_run_plain`` is looked up at each call; see
    _runner), with no child started. The seam is needed for the check site
    only: every in-tree runner (_run_plain, _run_stoppable, _run_cancellable)
    raises CalledProcessError for a nonzero code under ``check`` before it
    returns, so no real run reaches the check site with a signaled code. At the
    result site (check=False) the stand-in matches a real run that ended on
    SIGUSR1 field for field, and that site is also reached with a real spawn by
    test_a_kept_signal_death_stays_signaled_after_the_run_returned
    (test_a_failure_while_waiting_on_a_started_child_keeps_its_code.py); the
    seam there only keeps the two returned-run cells on one shape."""

    def returns_a_signaled_run(args, **kwargs):
        return subprocess.CompletedProcess(args, -_STAND_IN_SIGNAL, "", "")

    def recording_the_ending_raises(*args, **kwargs):
        raise RuntimeError("recording the ending failed")

    monkeypatch.setattr(subprocess_utils, "_run_plain", returns_a_signaled_run)
    monkeypatch.setattr(
        subprocess_utils, "SignaledProcess", recording_the_ending_raises
    )


@pytest.mark.unit
def test_the_returned_run_check_site_raises_with_both_flags(monkeypatch):
    """check=True after a returned run: the PostRunError raised there.

    A defensive pin, for a runner that would return a nonzero code under
    ``check``. No in-tree runner does: each raises CalledProcessError first, so
    a real returned run at this site has code 0 and carries no flags. The cell
    is kept because it is the only one that sees this site drop its flags; a
    code-0 shape could not tell a dropped splat from a correct one."""
    _a_returned_run_whose_record_then_raises(monkeypatch)

    with pytest.raises(PostRunError) as raised:
        run_command([sys.executable, "-c", "pass"], check=True)

    assert raised.value.signaled is True, vars(raised.value)
    assert raised.value.signal == _STAND_IN_SIGNAL, vars(raised.value)
    assert raised.value.returncode == -_STAND_IN_SIGNAL, vars(raised.value)


@pytest.mark.unit
def test_the_returned_run_result_site_keeps_both_flags(monkeypatch):
    """check=False after a returned run: the PostRunErrorProcess returned there."""
    _a_returned_run_whose_record_then_raises(monkeypatch)

    result = run_command([sys.executable, "-c", "pass"], check=False)

    assert isinstance(result, PostRunErrorProcess), result
    assert result.signaled is True, result
    assert result.signal == _STAND_IN_SIGNAL, result
    assert result.returncode == -_STAND_IN_SIGNAL, result


@pytest.mark.integration
@_POSIX
def test_the_failed_wait_check_site_raises_with_both_flags(tmp_path):
    """check=True after the wait on a started child raised: the PostRunError
    raised there, for a real tool that ended itself with SIGUSR1."""
    marker = tmp_path / "started"

    with _communicate_returns_then_raises(), pytest.raises(PostRunError) as raised:
        run_command(_tool_that_ends_by_its_own_signal(marker), check=True)

    assert marker.exists(), "the tool never started, so the cell shows nothing"
    assert raised.value.signaled is True, vars(raised.value)
    assert raised.value.signal == int(signal.SIGUSR1), vars(raised.value)


@pytest.mark.integration
@_POSIX
def test_the_failed_wait_result_site_keeps_both_flags(tmp_path):
    """check=False after the wait on a started child raised: the
    PostRunErrorProcess built there."""
    marker = tmp_path / "started"

    with _communicate_returns_then_raises():
        result = run_command(_tool_that_ends_by_its_own_signal(marker), check=False)

    assert marker.exists(), "the tool never started, so the cell shows nothing"
    assert isinstance(result, PostRunErrorProcess), result
    assert result.signaled is True, result
    assert result.signal == int(signal.SIGUSR1), result
