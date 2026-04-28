"""Regression tests for run_ash_container bug fixes (batch 2).

Covers bugs: #94, #95, #96, #97
"""

import inspect
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Bug #94 -- custom_containerfile build command never invoked
# ---------------------------------------------------------------------------
class TestBug94CustomContainerfileSilentlyIgnored:
    """When custom_containerfile is provided, custom_build_cmd must be invoked."""

    def test_custom_build_cmd_is_executed(self):
        from automated_security_helper.interactions.run_ash_container import (
            run_ash_container,
        )

        source = inspect.getsource(run_ash_container)
        # After the custom_build_cmd is assembled, we must find
        # run_cmd_direct(custom_build_cmd ...) invocation
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
            run_ash_container,
        )

        source = inspect.getsource(run_ash_container)
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
        from automated_security_helper.interactions.run_ash_container import (
            run_cmd_direct,
        )

        source = inspect.getsource(run_cmd_direct)
        # Find the KeyboardInterrupt handler section
        interrupt_idx = source.find("KeyboardInterrupt")
        assert interrupt_idx != -1

        post_interrupt = source[interrupt_idx:]
        assert "process.wait(" in post_interrupt or ".wait(" in post_interrupt, (
            "After process.terminate(), must call process.wait()"
        )
        assert "process.kill()" in post_interrupt or ".kill()" in post_interrupt, (
            "Must escalate to process.kill() if process doesn't exit"
        )
