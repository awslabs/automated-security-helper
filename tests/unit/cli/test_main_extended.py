"""Extended unit tests for the CLI main module."""

import pytest
from unittest.mock import patch
from typer.testing import CliRunner

from automated_security_helper.cli.main import app


@patch("automated_security_helper.cli.main.run_ash_scan_cli_command")
def test_main_cli_help(mock_run_ash_scan):
    """Test main CLI help command."""
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])

    # Verify help was displayed
    assert result.exit_code == 0
    assert "Usage:" in result.stdout

    # Verify run_ash_scan was not called
    mock_run_ash_scan.assert_not_called()


@patch("automated_security_helper.cli.scan.get_ash_version", return_value="1.0.0")
@patch("automated_security_helper.cli.main.run_ash_scan_cli_command")
def test_main_cli_version(mock_run_ash_scan, mock_get_ash_version):
    """Test main CLI version command."""
    runner = CliRunner()

    result = runner.invoke(app, ["--version"])

    # Verify version was displayed
    assert result.exit_code == 0
    assert "1.0.0" in result.stdout

    # Verify get_ash_version was called
    mock_get_ash_version.assert_called_once()


@pytest.mark.skip(reason="Working on fixing mocks")
@patch("automated_security_helper.interactions.run_ash_scan.run_ash_scan")
def test_main_cli_default_command(mock_run_ash_scan):
    """Test main CLI default command (scan)."""
    runner = CliRunner()
    result = runner.invoke(app, [])

    # Verify run_ash_scan was called
    mock_run_ash_scan.assert_called_once()

    # Verify exit code
    assert result.exit_code == 0


@pytest.mark.skip(reason="Working on fixing mocks")
@patch("automated_security_helper.interactions.run_ash_scan.run_ash_scan")
def test_main_cli_with_source_dir(mock_run_ash_scan):
    """Test main CLI with source directory."""
    runner = CliRunner()
    result = runner.invoke(app, ["--source-dir", "/test/source"])

    # Verify run_ash_scan was called with correct source_dir
    mock_run_ash_scan.assert_called_once()
    assert mock_run_ash_scan.call_args[1]["source_dir"] == "/test/source"

    # Verify exit code
    assert result.exit_code == 0


@pytest.mark.skip(reason="Working on fixing mocks")
@patch("automated_security_helper.interactions.run_ash_scan.run_ash_scan")
def test_main_cli_with_output_dir(mock_run_ash_scan):
    """Test main CLI with output directory."""
    runner = CliRunner()
    result = runner.invoke(app, ["--output-dir", "/test/output"])

    # Verify run_ash_scan was called with correct output_dir
    mock_run_ash_scan.assert_called_once()
    assert mock_run_ash_scan.call_args[1]["output_dir"] == "/test/output"

    # Verify exit code
    assert result.exit_code == 0


@pytest.mark.skip(reason="Working on fixing mocks")
@patch("automated_security_helper.interactions.run_ash_scan.run_ash_scan")
def test_main_cli_with_multiple_options(mock_run_ash_scan):
    """Test main CLI with multiple options."""
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "--source-dir",
            "/test/source",
            "--output-dir",
            "/test/output",
            "--config",
            "custom-config.yaml",
            "--verbose",
            "--debug",
            "--offline",
        ],
    )

    # Verify run_ash_scan was called with correct parameters
    mock_run_ash_scan.assert_called_once()
    call_args = mock_run_ash_scan.call_args[1]
    assert call_args["source_dir"] == "/test/source"
    assert call_args["output_dir"] == "/test/output"
    assert call_args["config"] == "custom-config.yaml"
    assert call_args["verbose"] is True
    assert call_args["debug"] is True
    assert call_args["offline"] is True

    # Verify exit code
    assert result.exit_code == 0
