"""Regression tests for run_ash_container bug fixes (batch 2).

Covers bugs: #94, #95, #96, #97
"""

import inspect

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Bug #94 -- custom_containerfile build command never invoked
# ---------------------------------------------------------------------------
class TestBug94CustomContainerfileSilentlyIgnored:
    """When custom_containerfile is provided, custom_build_cmd must be invoked."""

    def test_custom_build_cmd_is_executed(self):
        from automated_security_helper.interactions.run_ash_container import (
            _build_custom_image,
        )

        source = inspect.getsource(_build_custom_image)
        # The helper must call run_cmd_direct with the assembled command
        assert "run_cmd_direct(custom_build_cmd" in source, (
            "custom_build_cmd is constructed but never passed to run_cmd_direct"
        )


# ---------------------------------------------------------------------------
# Bug #95 -- --offline flag not forwarded into container env
# ---------------------------------------------------------------------------
class TestBug95OfflineFlagNotForwarded:
    """--offline should set ASH_OFFLINE=YES in the container environment."""

    def test_offline_env_var_set_in_run_cmd(self):
        from automated_security_helper.interactions.run_ash_container import (
            _assemble_run_command,
        )

        source = inspect.getsource(_assemble_run_command)
        assert "ASH_OFFLINE" in source, (
            "ASH_OFFLINE environment variable not forwarded to container"
        )


# ---------------------------------------------------------------------------
# Bug #96 -- StringIO.getvalue() called while worker thread may still write
# ---------------------------------------------------------------------------
class TestBug96StringIORace:
    """Threads must be joined before reading StringIO."""

    def test_threads_joined_before_getvalue(self):
        from automated_security_helper.interactions.run_ash_container import (
            run_cmd_direct,
        )

        source = inspect.getsource(run_cmd_direct)
        # The join calls must appear before getvalue() calls
        join_pos = source.find("stdout_thread.join(")
        getvalue_pos = source.find("stdout_buffer.getvalue()")
        assert join_pos < getvalue_pos, (
            "stdout_thread.join() must be called before stdout_buffer.getvalue()"
        )

        join_pos2 = source.find("stderr_thread.join(")
        getvalue_pos2 = source.find("stderr_buffer.getvalue()")
        assert join_pos2 < getvalue_pos2, (
            "stderr_thread.join() must be called before stderr_buffer.getvalue()"
        )


# ---------------------------------------------------------------------------
# Bug #97 -- process.terminate() without wait/SIGKILL escalation
# ---------------------------------------------------------------------------
class TestBug97TerminateWithoutWait:
    """After terminate(), must wait() and escalate to kill() if needed."""

    def test_terminate_has_wait_and_kill_escalation(self):
        """Since the interrupt is passed on rather than SIGTERMed, the stop lives in
        _stop_after_interrupt; TestRunCmdDirectInterruption checks it by behavior.

        The kill itself lives in the helper that logs a refused kill instead of
        letting the error replace the interrupt, and the reaping wait in the
        bounded wait after a kill. How the helper waits, kills and reaps is pinned
        by behavior in TestRunCmdDirectInterruption, so this reads only which
        function the wait loop ends the runtime through and where the kill and
        the wait are made.
        """
        from automated_security_helper.interactions import run_ash_container
        from automated_security_helper.interactions.run_ash_container import (
            run_cmd_direct,
        )
        from automated_security_helper.utils import subprocess_utils

        assert (
            run_ash_container._stop_after_interrupt
            is subprocess_utils.stop_after_interrupt
        )
        # The wait loop ends the runtime through the wrapper that adds a kill
        # when the helper itself is cut short.
        assert "_stop_the_runtime(" in inspect.getsource(run_cmd_direct)
        assert ".kill()" in inspect.getsource(subprocess_utils._kill_unless_refused), (
            "The kill helper is the one that calls process.kill()"
        )
        assert ".wait(" in inspect.getsource(subprocess_utils._wait_after_kill), (
            "The bounded wait is the one that calls process.wait()"
        )
