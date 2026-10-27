"""Extended tests for subprocess_utils.py to increase coverage."""

import os
import subprocess  # nosec B404 — test exercises subprocess_utils module
from unittest.mock import patch, MagicMock

import pytest

from automated_security_helper.utils.subprocess_utils import (
    _executable_candidate_names,
    find_executable,
    clear_find_executable_cache,
    run_command,
    run_command_with_output_handling,
    run_command_get_output,
    run_command_stream_output,
    get_host_uid,
    get_host_gid,
    create_completed_process,
    raise_called_process_error,
    create_process_with_pipes,
    SPAWN_FAILURE_RETURNCODE,
)


@patch("shutil.which")
@patch("pathlib.Path.exists")
def test_find_executable_found_in_path(mock_exists, mock_which):
    clear_find_executable_cache()
    """Test finding an executable in PATH."""
    # Anchored: ASH answers only with a path that does not depend on the working
    # directory, and "/usr/bin/..." has no drive letter on Windows.
    on_path = os.path.abspath("/usr/bin/test_cmd")
    mock_which.return_value = on_path
    mock_exists.return_value = False

    result = find_executable("test_cmd")

    assert result == on_path
    mock_which.assert_called_once()


@patch("shutil.which")
def test_find_executable_found_in_ash_bin(mock_which, tmp_path, monkeypatch):
    """Test finding an executable in ASH_BIN_PATH.

    A real executable file: the directory probe counts only a file it may run, so a
    patched ``Path.exists`` no longer stands for one.
    """
    clear_find_executable_cache()
    mock_which.return_value = None
    tool = tmp_path / "test_cmd"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path))

    result = find_executable("test_cmd")

    assert result == tool.as_posix()
    # which() is asked once for each spelling of the name: one on POSIX, and
    # name.exe, name.bat, name.cmd and name on Windows.
    assert mock_which.call_count == len(_executable_candidate_names("test_cmd"))
    clear_find_executable_cache()


@patch("shutil.which")
@patch("pathlib.Path.exists")
def test_find_executable_not_found(mock_exists, mock_which):
    """Test when executable is not found."""
    clear_find_executable_cache()
    mock_which.return_value = None
    mock_exists.return_value = False

    result = find_executable("nonexistent_cmd")

    assert result is None
    assert mock_which.call_count >= 1


@patch("subprocess.run")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_success(mock_find_executable, mock_run):
    """Test running a command successfully."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = "test output"
    mock_process.stderr = ""
    mock_run.return_value = mock_process

    result = run_command(["test_cmd", "arg1"])

    assert result.returncode == 0
    assert result.stdout == "test output"
    mock_run.assert_called_once()


@patch("subprocess.run")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_failure(mock_find_executable, mock_run):
    """Test running a command that fails."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_process = MagicMock()
    mock_process.returncode = 1
    mock_process.stdout = ""
    mock_process.stderr = "error message"
    mock_run.return_value = mock_process

    result = run_command(["test_cmd", "arg1"])

    assert result.returncode == 1
    assert result.stderr == "error message"
    mock_run.assert_called_once()


@patch("subprocess.run")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_exception(mock_find_executable, mock_run):
    """The runner's own failure is not exit 1, which most scanners accept."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_run.side_effect = Exception("Test exception")

    result = run_command(["test_cmd", "arg1"])

    assert result.returncode == SPAWN_FAILURE_RETURNCODE
    assert "Test exception" in result.stderr
    mock_run.assert_called_once()


@patch("subprocess.run")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_timeout(mock_find_executable, mock_run):
    """Test handling timeout when running a command."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["test_cmd"], timeout=10)

    result = run_command(["test_cmd", "arg1"], timeout=10)

    assert isinstance(result, subprocess.CompletedProcess)
    assert result.returncode == -1
    assert "10" in result.stderr
    mock_run.assert_called_once()


@patch("subprocess.run")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_with_check_true(mock_find_executable, mock_run):
    """Test running a command with check=True."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1, cmd=["test_cmd"], output="", stderr="error"
    )

    with pytest.raises(subprocess.CalledProcessError):
        run_command(["test_cmd", "arg1"], check=True)

    mock_run.assert_called_once()


def test_run_command_with_output_handling_return():
    """Test running a command with output handling set to return."""
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = "test output"
    mock_process.stderr = "test error"

    # Directly mock subprocess.run at the module level
    with (
        patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value="/usr/bin/test_cmd",
        ),
        patch(
            "automated_security_helper.utils.subprocess_utils.subprocess.run",
            return_value=mock_process,
        ),
    ):
        result = run_command_with_output_handling(
            ["test_cmd", "arg1"], stdout_preference="return", stderr_preference="return"
        )

        assert result["returncode"] == 0
        assert result["stdout"] == "test output"
        assert result["stderr"] == "test error"


@patch("pathlib.Path.mkdir")
# The stream logs are written through open_for_write, which refuses to follow a
# symlink a sandboxed scanner left at the log's name (utils/sandbox/fs_guard.py).
@patch("automated_security_helper.utils.subprocess_utils.open_for_write")
def test_run_command_with_output_handling_write(mock_open, mock_mkdir, ash_temp_path):
    """Test running a command with output handling set to write."""
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = "test output"
    mock_process.stderr = "test error"

    # Reset mocks to ensure clean state
    mock_mkdir.reset_mock()
    mock_open.reset_mock()

    # Directly mock subprocess.run and find_executable at the module level
    with (
        patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value="/usr/bin/test_cmd",
        ),
        patch(
            "automated_security_helper.utils.subprocess_utils.subprocess.run",
            return_value=mock_process,
        ),
    ):
        result = run_command_with_output_handling(
            ["test_cmd", "arg1"],
            results_dir=f"{ash_temp_path}/results",
            stdout_preference="write",
            stderr_preference="write",
        )

        assert result["returncode"] == 0
        assert "stdout" not in result
        assert "stderr" not in result
        # mkdir is called twice (once for stdout, once for stderr)
        assert mock_mkdir.call_count == 2
        assert mock_open.call_count == 2


@patch("subprocess.run")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_with_output_handling_exception(mock_find_executable, mock_run):
    """The runner's own failure is not exit 1, which most scanners accept."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_run.side_effect = Exception("Test exception")

    result = run_command_with_output_handling(["test_cmd", "arg1"])

    assert result["returncode"] == SPAWN_FAILURE_RETURNCODE
    assert "error" in result
    assert "Test exception" in result["error"]
    mock_run.assert_called_once()


@patch("automated_security_helper.utils.subprocess_utils.run_command")
def test_run_command_get_output(mock_run_command):
    """Test run_command_get_output function."""
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_process.stdout = "test output"
    mock_process.stderr = "test error"
    mock_run_command.return_value = mock_process

    returncode, stdout, stderr = run_command_get_output(["test_cmd", "arg1"])

    assert returncode == 0
    assert stdout == "test output"
    assert stderr == "test error"
    mock_run_command.assert_called_once()


@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_stream_output(mock_find_executable, mock_popen):
    """Test run_command_stream_output function."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_process = MagicMock()
    mock_process.stdout = ["line1\n", "line2\n"]
    mock_process.returncode = 0
    mock_popen.return_value = mock_process

    returncode = run_command_stream_output(["test_cmd", "arg1"])

    assert returncode == 0
    mock_popen.assert_called_once()
    mock_process.wait.assert_called_once()


@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_stream_output_exception(mock_find_executable, mock_popen):
    """The runner's own failure is not exit 1, which most scanners accept."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_popen.side_effect = Exception("Test exception")

    returncode = run_command_stream_output(["test_cmd", "arg1"])

    assert returncode == SPAWN_FAILURE_RETURNCODE
    mock_popen.assert_called_once()


@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_run_command_stream_output_failing_to_read_is_not_exit_1(
    mock_find_executable, mock_popen
):
    """ASH failing while it reads the tool's output stops the tool; not exit 1."""

    def unreadable():
        yield "line1\n"
        raise ValueError("cannot decode the output")

    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_process = MagicMock()
    mock_process.stdout = unreadable()
    mock_process.poll.return_value = None
    mock_popen.return_value = mock_process

    returncode = run_command_stream_output(["test_cmd", "arg1"])

    assert returncode == SPAWN_FAILURE_RETURNCODE
    mock_process.kill.assert_called_once()


@patch("automated_security_helper.utils.subprocess_utils.run_command")
def test_get_host_uid_success(mock_run_command):
    """Test get_host_uid function success."""
    mock_process = MagicMock()
    mock_process.stdout = "1000\n"
    mock_run_command.return_value = mock_process

    uid = get_host_uid()

    assert uid == 1000
    mock_run_command.assert_called_once()


@patch("automated_security_helper.utils.subprocess_utils.run_command")
def test_get_host_uid_failure(mock_run_command):
    """Test get_host_uid function failure."""
    mock_run_command.side_effect = Exception("Test exception")

    uid = get_host_uid()

    assert uid == 1000  # Default fallback
    mock_run_command.assert_called_once()


@patch("automated_security_helper.utils.subprocess_utils.run_command")
def test_get_host_gid_success(mock_run_command):
    """Test get_host_gid function success."""
    mock_process = MagicMock()
    mock_process.stdout = "1000\n"
    mock_run_command.return_value = mock_process

    gid = get_host_gid()

    assert gid == 1000
    mock_run_command.assert_called_once()


@patch("automated_security_helper.utils.subprocess_utils.run_command")
def test_get_host_gid_failure(mock_run_command):
    """Test get_host_gid function failure."""
    mock_run_command.side_effect = Exception("Test exception")

    gid = get_host_gid()

    assert gid == 1000  # Default fallback
    mock_run_command.assert_called_once()


def test_create_completed_process():
    """Test create_completed_process function."""
    process = create_completed_process(
        args=["test_cmd", "arg1"],
        returncode=0,
        stdout="test output",
        stderr="test error",
    )

    assert process.args == ["test_cmd", "arg1"]
    assert process.returncode == 0
    assert process.stdout == "test output"
    assert process.stderr == "test error"


def test_raise_called_process_error():
    """Test raise_called_process_error function."""
    with pytest.raises(subprocess.CalledProcessError) as excinfo:
        raise_called_process_error(
            returncode=1,
            cmd=["test_cmd", "arg1"],
            output="test output",
            stderr="test error",
        )

    assert excinfo.value.returncode == 1
    assert excinfo.value.cmd == ["test_cmd", "arg1"]
    assert excinfo.value.output == "test output"
    assert excinfo.value.stderr == "test error"


@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_create_process_with_pipes(mock_find_executable, mock_popen):
    """Test create_process_with_pipes function."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_process = MagicMock()
    mock_popen.return_value = mock_process

    process = create_process_with_pipes(["test_cmd", "arg1"])

    assert process == mock_process
    mock_popen.assert_called_once()


@patch("subprocess.Popen")
@patch("automated_security_helper.utils.subprocess_utils.find_executable")
def test_create_process_with_pipes_exception(mock_find_executable, mock_popen):
    """Test handling exceptions in create_process_with_pipes."""
    mock_find_executable.return_value = "/usr/bin/test_cmd"
    mock_popen.side_effect = Exception("Test exception")

    with pytest.raises(Exception) as excinfo:
        create_process_with_pipes(["test_cmd", "arg1"])

    assert "Test exception" in str(excinfo.value)
    mock_popen.assert_called_once()
