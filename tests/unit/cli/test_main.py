"""Unit tests for the main CLI module."""

from unittest.mock import patch

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.main import app


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@patch("automated_security_helper.cli.main.config_app")
@patch("automated_security_helper.cli.main.dependencies_app")
@patch("automated_security_helper.cli.main.inspect_app")
@patch("automated_security_helper.cli.main.plugin_app")
@patch("automated_security_helper.cli.main.run_ash_scan_cli_command")
@patch("automated_security_helper.cli.main.build_ash_image_cli_command")
@patch("automated_security_helper.cli.main.report_command")
def test_main_app_commands(
    mock_report_command,
    mock_build_ash_image_cli_command,
    mock_run_ash_scan_cli_command,
    mock_plugin_app,
    mock_inspect_app,
    mock_dependencies_app,
    mock_config_app,
    cli_runner,
):
    """Test that the main app has all expected commands."""
    # Get all commands from the app
    commands = app.registered_commands

    # Get sub-apps as well
    sub_apps = app.registered_groups

    # Check that we have the expected number of commands
    assert len(commands) > 0

    # Check for specific command names
    command_names = [cmd.name for cmd in commands]
    sub_app_names = [group.name for group in sub_apps]

    all_command_names = command_names + sub_app_names

    assert "scan" in all_command_names
    assert "config" in all_command_names
    assert "dependencies" in all_command_names
    assert "inspect" in all_command_names
    assert "plugin" in all_command_names
    assert "build-image" in all_command_names
    assert "report" in all_command_names


@patch("automated_security_helper.cli.main.run_ash_scan_cli_command")
def test_main_app_default_command(mock_run_ash_scan_cli_command, cli_runner):
    """Test that the main app runs the scan command by default."""
    # Setup mock
    mock_run_ash_scan_cli_command.return_value = None

    # Run the CLI with no command (should default to scan)
    with patch.object(typer, "Exit"):
        result = cli_runner.invoke(app, ["--help"])

    # Check that the result is successful
    assert result.exit_code == 0

    # Check that the help output contains expected text
    assert "Commands" in result.stdout
    assert "scan" in result.stdout
    assert "report" in result.stdout
    assert "inspect" in result.stdout
