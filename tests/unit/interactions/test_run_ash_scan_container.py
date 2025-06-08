"""Unit tests for the run_ash_container functionality."""

from unittest.mock import patch, MagicMock

from automated_security_helper.interactions.run_ash_container import (
    run_ash_container,
    get_host_uid,
    get_host_gid,
)
from automated_security_helper.core.enums import BuildTarget, AshLogLevel


@patch("automated_security_helper.interactions.run_ash_container.subprocess_utils")
def test_get_host_uid_success(mock_subprocess_utils):
    """Test get_host_uid with successful command execution."""
    # Mock subprocess_utils.run_command_get_output to return successful result
    mock_subprocess_utils.run_command_get_output.return_value = (0, "1000\n", "")

    # Call get_host_uid
    result = get_host_uid()

    # Verify result
    assert result == "1000"

    # Verify subprocess_utils.run_command_get_output was called correctly
    mock_subprocess_utils.run_command_get_output.assert_called_once_with(["id", "-u"])


@patch("automated_security_helper.interactions.run_ash_container.subprocess_utils")
def test_get_host_gid_success(mock_subprocess_utils):
    """Test get_host_gid with successful command execution."""
    # Mock subprocess_utils.run_command_get_output to return successful result
    mock_subprocess_utils.run_command_get_output.return_value = (0, "1000\n", "")

    # Call get_host_gid
    result = get_host_gid()

    # Verify result
    assert result == "1000"

    # Verify subprocess_utils.run_command_get_output was called correctly
    mock_subprocess_utils.run_command_get_output.assert_called_once_with(["id", "-g"])


@patch("automated_security_helper.interactions.run_ash_container.subprocess_utils")
@patch("automated_security_helper.interactions.run_ash_container.get_host_uid")
@patch("automated_security_helper.interactions.run_ash_container.get_host_gid")
def test_run_ash_container_basic(
    mock_get_host_gid, mock_get_host_uid, mock_subprocess_utils
):
    """Test run_ash_container with basic options."""
    # Mock get_host_uid and get_host_gid
    mock_get_host_uid.return_value = "1000"
    mock_get_host_gid.return_value = "1000"

    # Mock subprocess_utils.find_executable
    mock_subprocess_utils.find_executable.return_value = "/usr/bin/docker"

    # Mock subprocess_utils.run_command
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_subprocess_utils.run_command.return_value = mock_process

    # Call run_ash_container
    result = run_ash_container(
        source_dir="/test/source", output_dir="/test/output", build=True, run=True
    )

    # Verify result
    assert result.returncode == 0

    # Verify subprocess_utils.run_command was called for both build and run
    assert mock_subprocess_utils.run_command.call_count >= 2

    # Check for build command
    build_call = mock_subprocess_utils.run_command.call_args_list[0]
    build_cmd = build_call[0][0]
    assert "build" in build_cmd

    # Check for run command
    run_call = mock_subprocess_utils.run_command.call_args_list[1]
    run_cmd = run_call[0][0]
    assert "run" in run_cmd


@patch("automated_security_helper.interactions.run_ash_container.subprocess_utils")
@patch("automated_security_helper.interactions.run_ash_container.get_host_uid")
@patch("automated_security_helper.interactions.run_ash_container.get_host_gid")
def test_run_ash_container_build_only(
    mock_get_host_gid, mock_get_host_uid, mock_subprocess_utils
):
    """Test run_ash_container with build only."""
    # Mock get_host_uid and get_host_gid
    mock_get_host_uid.return_value = "1000"
    mock_get_host_gid.return_value = "1000"

    # Mock subprocess_utils.find_executable
    mock_subprocess_utils.find_executable.return_value = "/usr/bin/docker"

    # Mock subprocess_utils.run_command
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_subprocess_utils.run_command.return_value = mock_process

    # Call run_ash_container with build only
    result = run_ash_container(
        source_dir="/test/source", output_dir="/test/output", build=True, run=False
    )

    # Verify result
    assert result.returncode == 0

    # Verify subprocess_utils.run_command was called only for build
    mock_subprocess_utils.run_command.assert_called_once()

    # Check for build command
    build_call = mock_subprocess_utils.run_command.call_args
    build_cmd = build_call[0][0]
    assert "build" in build_cmd


@patch("automated_security_helper.interactions.run_ash_container.subprocess_utils")
@patch("automated_security_helper.interactions.run_ash_container.get_host_uid")
@patch("automated_security_helper.interactions.run_ash_container.get_host_gid")
def test_run_ash_container_run_only(
    mock_get_host_gid, mock_get_host_uid, mock_subprocess_utils
):
    """Test run_ash_container with run only."""
    # Mock get_host_uid and get_host_gid
    mock_get_host_uid.return_value = "1000"
    mock_get_host_gid.return_value = "1000"

    # Mock subprocess_utils.find_executable
    mock_subprocess_utils.find_executable.return_value = "/usr/bin/docker"

    # Mock subprocess_utils.run_command
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_subprocess_utils.run_command.return_value = mock_process

    # Call run_ash_container with run only
    result = run_ash_container(
        source_dir="/test/source", output_dir="/test/output", build=False, run=True
    )

    # Verify result
    assert result.returncode == 0

    # Verify subprocess_utils.run_command was called only for run
    mock_subprocess_utils.run_command.assert_called_once()

    # Check for run command
    run_call = mock_subprocess_utils.run_command.call_args
    run_cmd = run_call[0][0]
    assert "run" in run_cmd


@patch("automated_security_helper.interactions.run_ash_container.subprocess_utils")
@patch("automated_security_helper.interactions.run_ash_container.get_host_uid")
@patch("automated_security_helper.interactions.run_ash_container.get_host_gid")
def test_run_ash_container_with_custom_options(
    mock_get_host_gid, mock_get_host_uid, mock_subprocess_utils
):
    """Test run_ash_container with custom options."""
    # Mock get_host_uid and get_host_gid
    mock_get_host_uid.return_value = "1000"
    mock_get_host_gid.return_value = "1000"

    # Mock subprocess_utils.find_executable
    mock_subprocess_utils.find_executable.return_value = "/usr/bin/podman"

    # Mock subprocess_utils.run_command
    mock_process = MagicMock()
    mock_process.returncode = 0
    mock_subprocess_utils.run_command.return_value = mock_process

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

    # Verify subprocess_utils.find_executable was called with podman
    mock_subprocess_utils.find_executable.assert_called_with("podman")

    # Check for build command with CI target
    build_call = mock_subprocess_utils.run_command.call_args_list[0]
    build_cmd = build_call[0][0]
    assert "build" in build_cmd
    assert "--target" in build_cmd
    assert "ci" in build_cmd

    # Check for run command with custom UID/GID
    run_call = mock_subprocess_utils.run_command.call_args_list[1]
    run_cmd = run_call[0][0]
    assert "run" in run_cmd
    assert "-u" in run_cmd
    assert "2000:2000" in run_cmd

    # Check for environment variables
    assert "-e" in run_cmd
    assert "ASH_OFFLINE=YES" in run_cmd
    assert "ASH_LOG_LEVEL=DEBUG" in run_cmd
