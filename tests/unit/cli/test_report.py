# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from unittest.mock import MagicMock, patch

import typer
from automated_security_helper.cli.report import report_command
import pytest


@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.AshAggregatedResults")
@patch("automated_security_helper.cli.report.print")
def test_report_command_basic(
    mock_print,
    mock_results_class,
    mock_plugin_context,
    mock_plugin_manager,
    mock_load_plugins,
):
    """Test report command with basic options."""
    # Mock PluginContext
    mock_context_instance = MagicMock()
    mock_plugin_context.return_value = mock_context_instance

    # Mock reporter plugin
    mock_reporter_plugin = MagicMock()
    mock_reporter_plugin.config.name = "markdown"
    mock_reporter_plugin.report.return_value = (
        "# Test Report\n\nThis is a test markdown report."
    )

    # Mock plugin manager to return the reporter plugin
    mock_plugin_class = MagicMock()
    mock_plugin_class.__name__ = "MockReporterPlugin"  # Add __name__ attribute
    mock_plugin_class.return_value = mock_reporter_plugin
    mock_plugin_manager.plugin_modules.return_value = [mock_plugin_class]

    # Mock open to return a file with JSON content
    mock_file = MagicMock()
    mock_file.__enter__.return_value.read.return_value = (
        '{"metadata": {"summary_stats": {"actionable": 5}}}'
    )

    # Mock AshAggregatedResults
    mock_results_instance = MagicMock()
    mock_results_instance.metadata.summary_stats.actionable = 5
    mock_results_instance.metadata.summary_stats.total = 10
    mock_results_instance.metadata.summary_stats.suppressed = 2
    mock_results_instance.metadata.summary_stats.by_severity = {"HIGH": 3, "MEDIUM": 2}
    mock_results_class.model_validate_json.return_value = mock_results_instance

    # Mock Path.exists to return True for results file
    with patch("automated_security_helper.cli.report.Path") as mock_path:
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Call report_command with basic options
        with patch("builtins.open", return_value=mock_file):
            report_command(
                report_format="markdown",
                output_dir="/test/output",
                verbose=False,
                debug=False,
                color=True,
            )

    # Verify AshAggregatedResults.model_validate_json was called
    mock_results_class.model_validate_json.assert_called_once()
    # Verify reporter plugin was called
    mock_reporter_plugin.report.assert_called_once()


def test_report_command_with_resilient_parsing():
    """Test report command with resilient parsing."""
    # Call report_command with no arguments (resilient parsing)
    report_command()


@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.print")
def test_report_command_with_nonexistent_file(mock_print, mock_plugin_context):
    """Test report command with nonexistent results file."""
    # Mock PluginContext
    mock_context_instance = MagicMock()
    mock_plugin_context.return_value = mock_context_instance

    # Mock Path.exists to return False for results file
    with patch("automated_security_helper.cli.report.Path") as mock_path:
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path_instance.as_posix.return_value = (
            "/test/output/ash_aggregated_results.json"
        )
        mock_path.return_value = mock_path_instance

        with pytest.raises(typer.Exit) as pytest_wrapped_e:
            report_command(
                report_format="markdown",
                output_dir="/test/output",
            )
        assert pytest_wrapped_e.type is typer.Exit

    # Verify error message was printed
    mock_print.assert_called()


@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.AshAggregatedResults")
@patch("automated_security_helper.cli.report.print")
def test_report_command_with_verbose(
    mock_print,
    mock_results_class,
    mock_plugin_context,
    mock_plugin_manager,
    mock_load_plugins,
):
    """Test report command with verbose option."""
    # Mock PluginContext
    mock_context_instance = MagicMock()
    mock_plugin_context.return_value = mock_context_instance

    # Mock reporter plugin
    mock_reporter_plugin = MagicMock()
    mock_reporter_plugin.config.name = "markdown"
    mock_reporter_plugin.report.return_value = (
        "# Test Report\n\nThis is a test markdown report."
    )

    # Mock plugin manager to return the reporter plugin
    mock_plugin_class = MagicMock()
    mock_plugin_class.__name__ = "MockReporterPlugin"  # Add __name__ attribute
    mock_plugin_class.return_value = mock_reporter_plugin
    mock_plugin_manager.plugin_modules.return_value = [mock_plugin_class]

    # Mock open to return a file with JSON content
    mock_file = MagicMock()
    mock_file.__enter__.return_value.read.return_value = (
        '{"metadata": {"summary_stats": {"actionable": 5}}}'
    )

    # Mock AshAggregatedResults
    mock_results_instance = MagicMock()
    mock_results_instance.metadata.scan_metadata.source_dir = "/test/source"
    mock_results_instance.metadata.scan_metadata.output_dir = "/test/output"
    mock_results_class.model_validate_json.return_value = mock_results_instance

    # Mock Path.exists to return True for results file
    with patch("automated_security_helper.cli.report.Path") as mock_path:
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Call report_command with verbose option
        with patch("builtins.open", return_value=mock_file):
            report_command(
                report_format="markdown",
                output_dir="/test/output",
                verbose=True,
            )

    # Verify AshAggregatedResults.model_validate_json was called
    mock_results_class.model_validate_json.assert_called_once()
    # Verify reporter plugin was called
    mock_reporter_plugin.report.assert_called_once()
