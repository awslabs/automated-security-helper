# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed wait's response carries the stdout body only when the preference asks.

Why this file exists
--------------------
A completed uv run already honors ``stdout_preference``: under ``write`` the
stdout body goes to the results file and the run's record keeps none, so the
scanner response carries none. A failure while ASH waited on the started child
went through ``StartWatch.failure_after_the_start``, which mirrored whatever the
failed wait had read into the response unconditionally -- so the one path that
runs on an error was also the one that ignored the preference and put the tool's
stdout in the record. The stderr is kept whatever the preference says, as for a
failure after the run.

The reason of such a failure also named only the handler's own raise. The wait's
failure that the handler was handling (``__context__``) is the error that
explains the record, so the reason leads with it, then the handler's error. A
context the raise disavowed (``raise ... from None``) stays out, as it does in a
printed traceback.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Iterator, Optional
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import StartWatch

STDOUT_BODY = "tool output before the failure"
STDERR_BODY = "diag before the failure"
WAIT_FAILURE = "the wait on the child failed"
HANDLER_FAILURE = "the output handler failed"


def _exited_child() -> subprocess.Popen:
    """A real child that ran and exited 3 on its own."""
    process = subprocess.Popen([sys.executable, "-c", "import sys; sys.exit(3)"])
    process.wait()
    return process


def _record_of_a_failed_wait() -> "subprocess_utils._StartedChild":
    """The launch's record as a failed wait leaves it: a child that started,
    with the streams the wait had read before it failed."""
    record = subprocess_utils._StartedChild()
    record.process = _exited_child()
    record.stdout = STDOUT_BODY
    record.stderr = STDERR_BODY
    record.watched_launch = True
    return record


def _handler_error_with_context() -> BaseException:
    """The handler's raise, carrying the wait's failure as its __context__."""
    try:
        try:
            raise RuntimeError(WAIT_FAILURE)
        except RuntimeError:
            raise OSError(HANDLER_FAILURE)
    except OSError as error:
        return error


def _watch_of_a_failed_wait() -> StartWatch:
    watch = StartWatch()
    watch.started = _record_of_a_failed_wait()
    return watch


@pytest.mark.parametrize(
    ("preference", "mirrored"),
    [
        pytest.param("write", False, id="write-keeps-the-body-out"),
        pytest.param("return", True, id="return-admits"),
        pytest.param("both", True, id="both-admits"),
    ],
)
def test_the_mirror_honors_the_stdout_preference(preference: str, mirrored: bool):
    watch = _watch_of_a_failed_wait()

    after = watch.failure_after_the_start(
        _handler_error_with_context(), stdout_preference=preference
    )

    assert after is not None
    assert after.get("post_run_error") is True, after
    assert after.get("returncode") == 3, after
    # The stderr is kept whatever the preference says, as after a completed run.
    assert after.get("stderr") == STDERR_BODY, after
    if mirrored:
        assert after.get("stdout") == STDOUT_BODY, after
    else:
        assert "stdout" not in after, after


def test_the_reason_leads_with_the_failure_the_handler_was_handling():
    watch = _watch_of_a_failed_wait()

    after = watch.failure_after_the_start(
        _handler_error_with_context(), stdout_preference="write"
    )

    assert after is not None
    reason = after.get("error", "")
    assert WAIT_FAILURE in reason, reason
    assert HANDLER_FAILURE in reason, reason
    assert reason.index(WAIT_FAILURE) < reason.index(HANDLER_FAILURE), reason


def test_a_disavowed_context_stays_out_of_the_reason():
    """``raise ... from None`` disavows the context; the reason follows."""
    watch = _watch_of_a_failed_wait()
    try:
        try:
            raise RuntimeError(WAIT_FAILURE)
        except RuntimeError:
            raise OSError(HANDLER_FAILURE) from None
    except OSError as error:
        disavowed = error

    after = watch.failure_after_the_start(disavowed, stdout_preference="write")

    assert after is not None
    reason = after.get("error", "")
    assert WAIT_FAILURE not in reason, reason
    assert HANDLER_FAILURE in reason, reason


def test_an_explicit_cause_leads_the_reason():
    """``raise X from Y`` names Y deliberately, and Y is what broke the wait:
    the reason leads with it. The one-level context read dropped it, because a
    ``from`` clause suppresses the context whether it names a cause or None."""
    watch = _watch_of_a_failed_wait()
    try:
        raise OSError(HANDLER_FAILURE) from RuntimeError(WAIT_FAILURE)
    except OSError as error:
        chained = error

    after = watch.failure_after_the_start(chained, stdout_preference="write")

    assert after is not None
    reason = after.get("error", "")
    assert WAIT_FAILURE in reason, reason
    assert reason.index(WAIT_FAILURE) < reason.index(HANDLER_FAILURE), reason


def test_a_translated_error_that_quotes_its_cause_is_not_led_twice():
    """A handler that translates its failure quotes it (``X(f"...: {e}")``), as
    the uv runner's CalledProcessError translation does. Leading the reason
    with the context then prints the same text twice; a lead the error's own
    text already carries is skipped."""
    watch = _watch_of_a_failed_wait()
    try:
        try:
            raise RuntimeError(WAIT_FAILURE)
        except RuntimeError as cause:
            raise OSError(f"{HANDLER_FAILURE}: {cause}")
    except OSError as error:
        translated = error

    after = watch.failure_after_the_start(translated, stdout_preference="write")

    assert after is not None
    reason = after.get("error", "")
    assert reason.count(WAIT_FAILURE) == 1, reason
    assert HANDLER_FAILURE in reason, reason


def test_an_argv_quoting_raw_cause_leads_with_its_data_not_its_text():
    """``raise CleanMessage(...) from raw``: the raw subprocess errors quote
    the full argv in their str, and an argument can carry an environment-read
    value, so their text never leads the reason. Their data still does, as a
    fixed argv-free lead: of the three builders of this response only the
    timeout path sets ``timed_out``, and the recorded ``returncode`` is the
    launch's own, so dropping the lead entirely lost the exit code or the
    timeout -- the one fact that explains the record. The timeout's lead
    carries no number: the limit can be an environment-read value, and this
    walk holds no ``values`` to redact it with."""
    watch = _watch_of_a_failed_wait()
    raw = subprocess.CalledProcessError(
        2, ["tool", "--opt", "ARGV-SECRET-7421", "/some/dir"]
    )
    try:
        raise OSError(HANDLER_FAILURE) from raw
    except OSError as error:
        translated = error

    after = watch.failure_after_the_start(translated, stdout_preference="write")

    assert after is not None
    reason = after.get("error", "")
    assert "ARGV-SECRET-7421" not in reason, reason
    assert "the command exited 2" in reason, reason
    assert HANDLER_FAILURE in reason, reason
    assert reason.index("the command exited 2") < reason.index(HANDLER_FAILURE), reason

    timed = subprocess.TimeoutExpired(["tool", "ARGV-SECRET-7421"], 5)
    try:
        raise OSError(HANDLER_FAILURE) from timed
    except OSError as error:
        translated = error

    after = _watch_of_a_failed_wait().failure_after_the_start(
        translated, stdout_preference="write"
    )
    assert after is not None
    reason = after.get("error", "")
    assert "ARGV-SECRET-7421" not in reason, reason
    assert "the command timed out" in reason, reason
    # No limit in the lead: the walk holds no values to redact one with.
    assert "timed out after" not in reason, reason


def test_a_disavowing_refusal_keeps_a_carried_value_out_of_the_reason():
    """The env-blind refusals raise ``from None`` exactly so the failure they
    handled, which can quote an environment-read value, never reaches a
    reason. That hold must survive whatever the chain walk prefers."""
    watch = _watch_of_a_failed_wait()
    try:
        try:
            raise RuntimeError("read ENV-VALUE-7421 from the environment")
        except RuntimeError:
            raise OSError(HANDLER_FAILURE) from None
    except OSError as error:
        refusal = error

    after = watch.failure_after_the_start(refusal, stdout_preference="write")

    assert after is not None
    reason = after.get("error", "")
    assert "ENV-VALUE-7421" not in reason, reason
    assert HANDLER_FAILURE in reason, reason


# ---------------------------------------------------------------------------
# Through the uv mixin: the scanner response of a watched failed-wait launch
# ---------------------------------------------------------------------------


class _GuidedPlugin(UVToolMixin):
    """The attributes UVToolMixin reads from PluginBase, nothing else."""

    def __init__(self) -> None:
        self.command = "does-nothing"
        self.use_uv_tool = True
        self.uv_tool_package_name = None
        self.uv_tool_install_commands = []
        self._log_messages = []

    def _plugin_log(self, *args, **kwargs) -> None:
        self._log_messages.append(args)

    def _get_tool_package_extras(self) -> Optional[list]:
        return None

    def _get_tool_version_constraint(self) -> Optional[str]:
        return None


def _run_tool_fails_after_the_start(**_kwargs) -> Iterator[None]:
    """The runner's launch: its child starts under the held watch, then the
    wait's handler raises with the wait's failure as its context."""
    record = _record_of_a_failed_wait()
    for watch in subprocess_utils._START_WATCHES.get():
        if watch.started is None:
            watch.started = record
    try:
        raise RuntimeError(WAIT_FAILURE)
    except RuntimeError:
        raise OSError(HANDLER_FAILURE)


@pytest.mark.parametrize(
    ("preference", "mirrored"),
    [
        pytest.param("write", False, id="default-write-keeps-the-body-out"),
        pytest.param("return", True, id="return-admits"),
        pytest.param("both", True, id="both-admits"),
    ],
)
def test_the_uv_launchs_failed_wait_response_honors_the_preference(
    tmp_path, preference: str, mirrored: bool
):
    plugin = _GuidedPlugin()
    runner = MagicMock()
    runner.uv_availability.return_value = (True, None)
    runner.is_uv_available.return_value = True
    runner.run_tool.side_effect = _run_tool_fails_after_the_start

    with patch(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        return_value=runner,
    ):
        kwargs = {} if preference == "write" else {"stdout_preference": preference}
        response = plugin._try_uv_tool_execution(
            command=["does-nothing"], working_dir=tmp_path, **kwargs
        )

    assert response is not None, plugin._uv_run_failure
    assert response.get("post_run_error") is True, response
    assert response.get("returncode") == 3, response
    assert response.get("stderr") == STDERR_BODY, response
    if mirrored:
        assert response.get("stdout") == STDOUT_BODY, response
    else:
        assert "stdout" not in response, response
    reason = response.get("error", "")
    assert WAIT_FAILURE in reason and HANDLER_FAILURE in reason, reason
