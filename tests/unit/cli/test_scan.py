"""Unit tests for the scan CLI module."""

from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.scan import run_ash_scan_cli_command
from automated_security_helper.core.enums import RunMode, Phases


@pytest.fixture
def cli_runner():
    """Create a CLI runner for testing."""
    return CliRunner()


@patch("automated_security_helper.cli.scan.run_ash_scan")
def test_run_ash_scan_cli_command_basic(mock_run_ash_scan, cli_runner):
    """Test the basic functionality of run_ash_scan_cli_command."""
    # Setup mock
    mock_run_ash_scan.return_value = None

    # Create a mock context
    mock_context = MagicMock()
    mock_context.resilient_parsing = False
    mock_context.invoked_subcommand = None

    # Call the function
    run_ash_scan_cli_command(mock_context, source_dir="./source", output_dir="./output")

    # Verify run_ash_scan was called with expected parameters
    mock_run_ash_scan.assert_called_once()
    args, kwargs = mock_run_ash_scan.call_args
    assert kwargs["source_dir"] == "./source"
    assert kwargs["output_dir"] == "./output"
    assert kwargs["mode"] == RunMode.local


@patch("automated_security_helper.cli.scan.run_ash_scan")
def test_run_ash_scan_cli_command_with_container_mode(mock_run_ash_scan, cli_runner):
    """Test run_ash_scan_cli_command with container mode."""
    # Setup mock
    mock_run_ash_scan.return_value = None

    # Create a mock context
    mock_context = MagicMock()
    mock_context.resilient_parsing = False
    mock_context.invoked_subcommand = None

    # Call the function with container mode
    run_ash_scan_cli_command(
        mock_context,
        source_dir="./source",
        output_dir="./output",
        mode=RunMode.container,
    )

    # Verify run_ash_scan was called with expected parameters
    mock_run_ash_scan.assert_called_once()
    args, kwargs = mock_run_ash_scan.call_args
    assert kwargs["source_dir"] == "./source"
    assert kwargs["output_dir"] == "./output"
    assert kwargs["mode"] == RunMode.container


@patch("automated_security_helper.cli.scan.run_ash_scan")
def test_run_ash_scan_cli_command_with_custom_phases(mock_run_ash_scan, cli_runner):
    """Test run_ash_scan_cli_command with custom phases."""
    # Setup mock
    mock_run_ash_scan.return_value = None

    # Create a mock context
    mock_context = MagicMock()
    mock_context.resilient_parsing = False
    mock_context.invoked_subcommand = None

    # Call the function with custom phases
    run_ash_scan_cli_command(
        mock_context,
        source_dir="./source",
        output_dir="./output",
        phases=[Phases.convert, Phases.report],
    )

    # Verify run_ash_scan was called with expected parameters
    mock_run_ash_scan.assert_called_once()
    args, kwargs = mock_run_ash_scan.call_args
    assert kwargs["source_dir"] == "./source"
    assert kwargs["output_dir"] == "./output"
    assert kwargs["phases"] == [Phases.convert, Phases.report]


@patch("automated_security_helper.cli.scan.run_ash_scan")
def test_run_ash_scan_cli_command_with_resilient_parsing(mock_run_ash_scan, cli_runner):
    """Test run_ash_scan_cli_command with resilient parsing."""
    # Setup mock
    mock_run_ash_scan.return_value = None

    # Create a mock context with resilient_parsing=True
    mock_context = MagicMock()
    mock_context.resilient_parsing = True

    # Call the function
    run_ash_scan_cli_command(mock_context, source_dir="./source", output_dir="./output")

    # Verify run_ash_scan was not called
    mock_run_ash_scan.assert_not_called()
