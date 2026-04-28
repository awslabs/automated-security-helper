"""Regression tests for subprocess_utils bug fixes.

PR#274 Bug #3: TimeoutExpired returned as CompletedProcess from run_command
PR#274 Bug #4: CalledProcessError returned as CompletedProcess from run_command
PR#274 Bug #38: Popen orphaned on exception in run_command_stream_output
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest


class TestBug4TimeoutExpiredReturnType:
    """PR#274 Bug #3: run_command must return CompletedProcess when TimeoutExpired is caught."""

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_timeout_returns_completed_process(self, mock_run, _mock_find):
        """When subprocess.run raises TimeoutExpired, run_command should
        return a CompletedProcess, not the raw exception."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["sleep", "100"], timeout=5
        )

        result = run_command(["sleep", "100"], timeout=5)

        assert isinstance(result, subprocess.CompletedProcess), (
            f"Expected CompletedProcess, got {type(result).__name__}"
        )

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_timeout_has_returncode_attribute(self, mock_run, _mock_find):
        """The CompletedProcess from a timeout must expose .returncode
        so callers don't hit AttributeError."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["sleep", "100"], timeout=5
        )

        result = run_command(["sleep", "100"], timeout=5)

        assert hasattr(result, "returncode")
        assert result.returncode == -1

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_timeout_preserves_stderr_message(self, mock_run, _mock_find):
        """stderr should contain the timeout duration."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["sleep", "100"], timeout=5
        )

        result = run_command(["sleep", "100"], timeout=5)

        assert "5" in result.stderr

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_timeout_preserves_stdout_from_exception(self, mock_run, _mock_find):
        """If the TimeoutExpired has partial stdout, it should be carried over."""
        from automated_security_helper.utils.subprocess_utils import run_command

        exc = subprocess.TimeoutExpired(cmd=["cmd"], timeout=5)
        exc.stdout = "partial output"
        exc.stderr = "partial err"
        mock_run.side_effect = exc

        result = run_command(["cmd"], timeout=5)

        assert result.stdout == "partial output"
        assert result.stderr == "partial err"

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_timeout_still_raises_when_check_true(self, mock_run, _mock_find):
        """When check=True, TimeoutExpired should still propagate."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["sleep", "100"], timeout=5
        )

        with pytest.raises(subprocess.TimeoutExpired):
            run_command(["sleep", "100"], timeout=5, check=True)


class TestBug5CalledProcessErrorReturnType:
    """PR#274 Bug #4: run_command must return CompletedProcess when CalledProcessError is caught."""

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_called_process_error_returns_completed_process(self, mock_run, _mock_find):
        """When subprocess.run raises CalledProcessError and check=False,
        run_command should return a CompletedProcess."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=2, cmd=["false"], output="some out", stderr="some err"
        )

        result = run_command(["false"])

        assert isinstance(result, subprocess.CompletedProcess), (
            f"Expected CompletedProcess, got {type(result).__name__}"
        )

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_called_process_error_preserves_returncode(self, mock_run, _mock_find):
        """The returncode from the CalledProcessError should be preserved."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=42, cmd=["bad"], output="out", stderr="err"
        )

        result = run_command(["bad"])

        assert result.returncode == 42

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_called_process_error_preserves_output(self, mock_run, _mock_find):
        """stdout and stderr from the CalledProcessError should carry over."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["bad"], output="captured out", stderr="captured err"
        )

        result = run_command(["bad"])

        assert result.stdout == "captured out"
        assert result.stderr == "captured err"

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_called_process_error_handles_none_output(self, mock_run, _mock_find):
        """When output/stderr are None on the exception, use empty strings."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["bad"], output=None, stderr=None
        )

        result = run_command(["bad"])

        assert isinstance(result, subprocess.CompletedProcess)
        assert result.stdout == ""
        assert result.stderr == ""

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.run")
    def test_called_process_error_still_raises_when_check_true(self, mock_run, _mock_find):
        """When check=True, CalledProcessError should still propagate."""
        from automated_security_helper.utils.subprocess_utils import run_command

        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["false"]
        )

        with pytest.raises(subprocess.CalledProcessError):
            run_command(["false"], check=True)


class TestBug48PopenOrphanedOnException:
    """PR#274 Bug #38: Popen must be killed and waited on if an exception occurs
    during stream reading in run_command_stream_output."""

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.Popen")
    def test_popen_killed_on_exception_during_read(self, mock_popen_cls, _mock_find):
        """If an exception is raised while iterating stdout, the process
        must be killed and waited on."""
        from automated_security_helper.utils.subprocess_utils import run_command_stream_output

        mock_process = MagicMock()
        mock_process.stdout.__iter__ = MagicMock(side_effect=OSError("read failed"))
        mock_process.poll.return_value = None  # process still running
        mock_popen_cls.return_value = mock_process

        result = run_command_stream_output(["some", "cmd"])

        mock_process.kill.assert_called_once()
        mock_process.wait.assert_called()
        assert result == 1

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.Popen")
    def test_popen_not_killed_if_already_exited(self, mock_popen_cls, _mock_find):
        """If the process already exited before cleanup, kill should not be called."""
        from automated_security_helper.utils.subprocess_utils import run_command_stream_output

        mock_process = MagicMock()
        mock_process.stdout.__iter__ = MagicMock(side_effect=OSError("read failed"))
        mock_process.poll.return_value = 0  # already exited
        mock_popen_cls.return_value = mock_process

        result = run_command_stream_output(["some", "cmd"])

        mock_process.kill.assert_not_called()
        assert result == 1

    @patch("automated_security_helper.utils.subprocess_utils.find_executable", return_value=None)
    @patch("subprocess.Popen")
    def test_popen_cleaned_up_on_normal_exit(self, mock_popen_cls, _mock_find):
        """On a normal exit (no exception), the process should still be
        properly waited on via the finally block."""
        from automated_security_helper.utils.subprocess_utils import run_command_stream_output

        mock_process = MagicMock()
        mock_process.stdout.__iter__ = MagicMock(return_value=iter(["line1\n", "line2\n"]))
        mock_process.wait.return_value = None
        mock_process.returncode = 0
        mock_process.poll.return_value = 0  # already exited after normal iteration
        mock_popen_cls.return_value = mock_process

        result = run_command_stream_output(["echo", "hello"])

        assert result == 0


# ---------------------------------------------------------------------------
# Batch 2: subprocess_utils regression tests
# ---------------------------------------------------------------------------


class TestBug49ArgsNotMutated:
    """run_command must not mutate the caller's list."""

    def test_run_command_does_not_mutate_caller_list(self):
        original = ["echo", "hello"]
        caller_copy = original.copy()

        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value="/usr/bin/echo",
        ):
            with patch(
                "automated_security_helper.utils.subprocess_utils.subprocess.run"
            ) as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0, stdout="hello\n", stderr=""
                )
                from automated_security_helper.utils.subprocess_utils import (
                    run_command,
                )

                run_command(original)

        # The caller's list must not have been modified
        assert original == caller_copy, (
            f"run_command mutated caller's args list: {original} != {caller_copy}"
        )


class TestBug50SilentFallbackWarning:
    """get_host_uid / get_host_gid should log a warning when falling back."""

    def test_get_host_uid_logs_warning_on_fallback(self):
        from automated_security_helper.utils.subprocess_utils import get_host_uid

        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command",
            side_effect=Exception("not available"),
        ):
            with patch(
                "automated_security_helper.utils.subprocess_utils.ASH_LOGGER"
            ) as mock_logger:
                uid = get_host_uid()

        assert uid == 1000
        # Must have logged a warning (not just error)
        mock_logger.warning.assert_called()

    def test_get_host_gid_logs_warning_on_fallback(self):
        from automated_security_helper.utils.subprocess_utils import get_host_gid

        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command",
            side_effect=Exception("not available"),
        ):
            with patch(
                "automated_security_helper.utils.subprocess_utils.ASH_LOGGER"
            ) as mock_logger:
                gid = get_host_gid()

        assert gid == 1000
        mock_logger.warning.assert_called()
