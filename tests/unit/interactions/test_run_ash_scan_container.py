"""Unit tests for the run_ash_container functionality."""

from unittest.mock import patch, MagicMock

from automated_security_helper.interactions.run_ash_container import (
    run_ash_container,
)
from automated_security_helper.utils.subprocess_utils import (
    get_host_uid,
    get_host_gid,
)
from automated_security_helper.core.enums import BuildTarget, AshLogLevel


@patch("automated_security_helper.utils.subprocess_utils.run_command")
def test_get_host_uid_success(mock_run_command):
    """Test get_host_uid with successful command execution."""
    # Mock subprocess_utils.run_command to return successful result
    mock_result = MagicMock()
    mock_result.stdout = "1000\n"
    mock_run_command.return_value = mock_result

    # Call get_host_uid
    result = get_host_uid()

    # Verify result - get_host_uid returns an integer
    assert result == 1000

    # Verify subprocess_utils.run_command was called correctly
    mock_run_command.assert_called_once_with(
        ["id", "-u"], capture_output=True, text=True, check=True
    )


@patch("automated_security_helper.utils.subprocess_utils.run_command")
def test_get_host_gid_success(mock_run_command):
    """Test get_host_gid with successful command execution."""
    # Mock subprocess_utils.run_command to return successful result
    mock_result = MagicMock()
    mock_result.stdout = "1000\n"
    mock_run_command.return_value = mock_result

    # Call get_host_gid
    result = get_host_gid()

    # Verify result - get_host_gid returns an integer
    assert result == 1000

    # Verify subprocess_utils.run_command was called correctly
    mock_run_command.assert_called_once_with(
        ["id", "-g"], capture_output=True, text=True, check=True
    )


@patch("automated_security_helper.interactions.run_ash_container.Path.mkdir")
@patch("automated_security_helper.interactions.run_ash_container.validate_path")
@patch("automated_security_helper.interactions.run_ash_container.run_cmd_direct")
@patch("automated_security_helper.utils.subprocess_utils")
@patch("automated_security_helper.utils.subprocess_utils.get_host_uid")
@patch("automated_security_helper.utils.subprocess_utils.get_host_gid")
def test_run_ash_container_basic(
    mock_get_host_gid,
    mock_get_host_uid,
    mock_subprocess_utils,
    mock_run_cmd_direct,
    mock_validate_path,
    mock_mkdir,
):
    """Test run_ash_container with basic options."""
    # Mock get_host_uid and get_host_gid
    mock_get_host_uid.return_value = 1000
    mock_get_host_gid.return_value = 1000

    # Mock subprocess_utils.find_executable
    mock_subprocess_utils.find_executable.return_value = "/usr/bin/docker"

    # Mock run_cmd_direct to return successful result
    mock_build_result = MagicMock()
    mock_build_result.returncode = 0
    mock_run_cmd_direct.return_value = mock_build_result

    # Mock validate_path to return the path as-is
    mock_validate_path.return_value = "/test/source"

    # Mock Path.mkdir to prevent actual directory creation
    mock_mkdir.return_value = None

    # Mock subprocess_utils.run_command for the run phase
    mock_run_result = MagicMock()
    mock_run_result.returncode = 0
    mock_subprocess_utils.run_command.return_value = mock_run_result

    # Call run_ash_container
    result = run_ash_container(
        source_dir="/test/source", output_dir="/test/output", build=True, run=True
    )

    # Verify result
    assert result.returncode == 0

    # Verify run_cmd_direct was called twice (build and run)
    assert mock_run_cmd_direct.call_count == 2

    # Check first call was for build
    build_cmd = mock_run_cmd_direct.call_args_list[0][0][0]
    assert "build" in build_cmd

    # Check second call was for run
    run_cmd = mock_run_cmd_direct.call_args_list[1][0][0]
    assert "run" in run_cmd


@patch("automated_security_helper.interactions.run_ash_container.run_cmd_direct")
@patch("automated_security_helper.utils.subprocess_utils")
@patch("automated_security_helper.utils.subprocess_utils.get_host_uid")
@patch("automated_security_helper.utils.subprocess_utils.get_host_gid")
def test_run_ash_container_build_only(
    mock_get_host_gid, mock_get_host_uid, mock_subprocess_utils, mock_run_cmd_direct
):
    """Test run_ash_container with build only."""
    # Mock get_host_uid and get_host_gid
    mock_get_host_uid.return_value = 1000
    mock_get_host_gid.return_value = 1000

    # Mock subprocess_utils.find_executable
    mock_subprocess_utils.find_executable.return_value = "/usr/bin/docker"

    # Mock run_cmd_direct to return successful result
    mock_build_result = MagicMock()
    mock_build_result.returncode = 0
    mock_run_cmd_direct.return_value = mock_build_result

    # Call run_ash_container with build only
    result = run_ash_container(
        source_dir="/test/source", output_dir="/test/output", build=True, run=False
    )

    # Verify result
    assert result.returncode == 0

    # Verify run_cmd_direct was called only for build
    mock_run_cmd_direct.assert_called_once()

    # Check for build command
    build_cmd = mock_run_cmd_direct.call_args[0][0]
    assert "build" in build_cmd

    # Verify subprocess_utils.run_command was not called (no run phase)
    mock_subprocess_utils.run_command.assert_not_called()


@patch("automated_security_helper.interactions.run_ash_container.Path.mkdir")
@patch("automated_security_helper.interactions.run_ash_container.validate_path")
@patch("automated_security_helper.interactions.run_ash_container.run_cmd_direct")
@patch("automated_security_helper.utils.subprocess_utils")
@patch("automated_security_helper.utils.subprocess_utils.get_host_uid")
@patch("automated_security_helper.utils.subprocess_utils.get_host_gid")
def test_run_ash_container_run_only(
    mock_get_host_gid,
    mock_get_host_uid,
    mock_subprocess_utils,
    mock_run_cmd_direct,
    mock_validate_path,
    mock_mkdir,
):
    """Test run_ash_container with run only."""
    # Mock get_host_uid and get_host_gid
    mock_get_host_uid.return_value = 1000
    mock_get_host_gid.return_value = 1000

    # Mock subprocess_utils.find_executable
    mock_subprocess_utils.find_executable.return_value = "/usr/bin/docker"

    # Mock validate_path to return the path as-is
    mock_validate_path.return_value = "/test/source"

    # Mock Path.mkdir to prevent actual directory creation
    mock_mkdir.return_value = None

    # Mock run_cmd_direct for the run phase
    mock_run_result = MagicMock()
    mock_run_result.returncode = 0
    mock_run_cmd_direct.return_value = mock_run_result

    # Call run_ash_container with run only
    result = run_ash_container(
        source_dir="/test/source", output_dir="/test/output", build=False, run=True
    )

    # Verify result
    assert result.returncode == 0

    # Verify run_cmd_direct was called only once for run
    mock_run_cmd_direct.assert_called_once()

    # Check for run command
    run_cmd = mock_run_cmd_direct.call_args[0][0]
    assert "run" in run_cmd


@patch("automated_security_helper.interactions.run_ash_container.Path.mkdir")
@patch("automated_security_helper.interactions.run_ash_container.validate_path")
@patch("automated_security_helper.interactions.run_ash_container.run_cmd_direct")
@patch("automated_security_helper.utils.subprocess_utils")
@patch("automated_security_helper.utils.subprocess_utils.get_host_uid")
@patch("automated_security_helper.utils.subprocess_utils.get_host_gid")
def test_run_ash_container_with_custom_options(
    mock_get_host_gid,
    mock_get_host_uid,
    mock_subprocess_utils,
    mock_run_cmd_direct,
    mock_validate_path,
    mock_mkdir,
):
    """Test run_ash_container with custom options."""
    # Mock get_host_uid and get_host_gid
    mock_get_host_uid.return_value = 1000
    mock_get_host_gid.return_value = 1000

    # Mock subprocess_utils.find_executable
    mock_subprocess_utils.find_executable.return_value = "/usr/bin/podman"

    # Mock run_cmd_direct to return successful result
    mock_build_result = MagicMock()
    mock_build_result.returncode = 0
    mock_run_cmd_direct.return_value = mock_build_result

    # Mock validate_path to return the path as-is
    mock_validate_path.return_value = "/test/source"

    # Mock Path.mkdir to prevent actual directory creation
    mock_mkdir.return_value = None

    # Mock subprocess_utils.run_command for the run phase
    mock_run_result = MagicMock()
    mock_run_result.returncode = 0
    mock_subprocess_utils.run_command.return_value = mock_run_result

    # Call run_ash_container with custom options
    result = run_ash_container(
        source_dir="/test/source",
        output_dir="/test/output",
        build=True,
        run=True,
        oci_runner="podman",
        build_target=BuildTarget.CI,
        container_uid="2000",
        container_gid="2000",
        offline=True,
        log_level=AshLogLevel.DEBUG,
        config_overrides=["reporters.html.enabled=true"],
    )

    # Verify result
    assert result.returncode == 0

    # Verify run_cmd_direct was called twice (build and run)
    assert mock_run_cmd_direct.call_count == 2

    # Check first call was for build
    build_cmd = mock_run_cmd_direct.call_args_list[0][0][0]
    assert "build" in build_cmd
    assert "--target" in build_cmd
    assert "ci" in build_cmd

    # Check second call was for run
    run_cmd = mock_run_cmd_direct.call_args_list[1][0][0]
    assert "run" in run_cmd

    # Check for environment variables in run command
    assert "-e" in run_cmd
    # Find the environment variable arguments
    env_args = []
    for i, arg in enumerate(run_cmd):
        if arg == "-e" and i + 1 < len(run_cmd):
            env_args.append(run_cmd[i + 1])

    # Check that some expected environment variables are present
    assert any("ASH_ACTUAL_SOURCE_DIR" in env_arg for env_arg in env_args)
    assert any("ASH_ACTUAL_OUTPUT_DIR" in env_arg for env_arg in env_args)
