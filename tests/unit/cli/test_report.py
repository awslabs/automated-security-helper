# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import typer
from automated_security_helper.cli.report import report_command
import pytest

pytestmark = pytest.mark.unit


def _squeezed(text: str) -> str:
    """*text* without its whitespace: rich folds a long line at the console width, so
    a message is compared as the characters it holds, not by where a line broke."""
    return "".join(text.split())


def _results_file_only_in_the_directory_itself(mock_output_dir: MagicMock) -> None:
    """The three places an --output-dir is searched, as a mocked Path: a results
    file is there only in the directory itself, since more than one is refused."""

    def joinpath(*parts):
        candidate = MagicMock()
        candidate.exists.return_value = parts == ("ash_aggregated_results.json",)
        return candidate

    mock_output_dir.joinpath.side_effect = joinpath


def _declares_name(mock_plugin_class: MagicMock, name: str) -> None:
    """Give the mock reporter class the name the command looks ``--format`` up by.

    The command matches the format against each reporter class's declared name
    (base/plugin_config.declared_plugin_name: the ``name`` default of the class
    its ``config`` field is typed with) without building the class, and falls
    back to the lowercased class name only when none is declared. A bare
    MagicMock declares none, so it answered to ``mockreporterplugin`` and the
    command refused the requested format as unknown before it read anything.

    The reporter the class builds declares no companion files. A MagicMock is an
    ``os.PathLike`` (it answers ``__fspath__``), so the one its
    ``companion_file_names()`` returned was read as a file named
    ``MagicMock/mock().companion_file_names()/...``, which the pre-write check
    refused as a name outside the reports directory before ``report`` ran.
    """
    config_class = MagicMock()
    config_class.model_fields = {"name": SimpleNamespace(default=name)}
    mock_plugin_class.model_fields = {
        "config": SimpleNamespace(annotation=config_class)
    }
    mock_plugin_class.return_value.companion_file_names.return_value = ()


@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.AshAggregatedResults")
def test_report_command_basic(
    mock_results_class,
    mock_plugin_context,
    mock_plugin_manager,
    mock_load_plugins,
    capfd,
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
    _declares_name(mock_plugin_class, mock_reporter_plugin.config.name)
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
        _results_file_only_in_the_directory_itself(mock_path_instance)
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
    # The report is what stdout holds, and the command printed no error about it.
    out, err = capfd.readouterr()
    assert "This is a test markdown report." in out, out
    assert "Error" not in err, err


@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.AshAggregatedResults")
def test_a_reporter_that_returns_none_exits_non_zero(
    mock_results_class,
    mock_plugin_context,
    mock_plugin_manager,
    mock_load_plugins,
    capfd,
):
    """``report`` is ``-> str | None``, and None must not be printed as text.

    Without the guard the None falls through to ``print(report_content)``, so the
    command writes the literal "None" to stdout and exits 0. A caller redirecting
    stdout to a file then has a four-byte report and a success status, which is
    the same silent-clean-report failure the reporters themselves were fixed for.
    """
    mock_plugin_context.return_value = MagicMock()

    mock_reporter_plugin = MagicMock()
    mock_reporter_plugin.config.name = "github-ghas"
    mock_reporter_plugin.report.return_value = None

    mock_plugin_class = MagicMock()
    mock_plugin_class.__name__ = "MockReporterPlugin"
    mock_plugin_class.return_value = mock_reporter_plugin
    _declares_name(mock_plugin_class, mock_reporter_plugin.config.name)
    mock_plugin_manager.plugin_modules.return_value = [mock_plugin_class]

    mock_file = MagicMock()
    mock_file.__enter__.return_value.read.return_value = "{}"
    mock_results_class.model_validate_json.return_value = MagicMock()

    with patch("automated_security_helper.cli.report.Path") as mock_path:
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        _results_file_only_in_the_directory_itself(mock_path_instance)
        mock_path.return_value = mock_path_instance

        with patch("builtins.open", return_value=mock_file):
            with pytest.raises(typer.Exit) as exit_info:
                report_command(
                    report_format="github-ghas",
                    output_dir="/test/output",
                )

    assert exit_info.value.exit_code == 1
    out, err = capfd.readouterr()
    # Nothing on stdout, so no "None" in place of a report.
    assert out == "", out
    assert _squeezed("Error: reporter 'github-ghas' produced no report.") in _squeezed(
        err
    ), err
    # The deliberate exit must not be relabelled by the generic handler, which
    # catches Exception and typer.Exit subclasses RuntimeError.
    assert "Error generating report" not in err, err


def test_report_command_with_resilient_parsing(tmp_path, monkeypatch):
    """With no arguments and no results file, the command refuses with exit 1.

    This test used to patch builtins.open so that open(None) -- what the command
    called when it found no results file -- returned a mock, and it passed only
    because of that. The command now refuses a missing results file before it
    opens anything, so the no-argument call is asserted to do exactly that.
    """
    monkeypatch.chdir(tmp_path)
    mock_file = MagicMock()
    mock_file.__enter__.return_value.read.return_value = (
        '{"metadata": {"summary_stats": {"actionable": 5}}}'
    )
    with patch("builtins.open", return_value=mock_file) as mock_open:
        with pytest.raises(typer.Exit) as exit_info:
            report_command()

    assert exit_info.value.exit_code == 1
    mock_open.assert_not_called()


def test_report_command_with_nonexistent_file(tmp_path, monkeypatch, capfd):
    """An --output-dir that holds no results file is refused, and the message names
    where the command looked.

    A real, empty directory rather than a mocked PluginContext and Path: with the
    context mocked no reporter can be built, so the command stops at its unknown
    --format refusal before it looks for a results file at all.
    """
    monkeypatch.chdir(tmp_path)
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    with pytest.raises(typer.Exit) as exit_info:
        report_command(report_format="markdown", output_dir=output_dir.as_posix())

    assert exit_info.value.exit_code != 0
    _out, err = capfd.readouterr()
    assert _squeezed("No scan results found: none of") in _squeezed(err), err
    assert _squeezed(
        output_dir.joinpath("ash_aggregated_results.json").as_posix()
    ) in _squeezed(err), err


@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.AshAggregatedResults")
def test_report_command_with_verbose(
    mock_results_class,
    mock_plugin_context,
    mock_plugin_manager,
    mock_load_plugins,
    capfd,
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
    _declares_name(mock_plugin_class, mock_reporter_plugin.config.name)
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
        _results_file_only_in_the_directory_itself(mock_path_instance)
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
    # The report is what stdout holds, and the command printed no error about it.
    out, err = capfd.readouterr()
    assert "This is a test markdown report." in out, out
    assert "Error" not in err, err


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="creating symlinks needs privileges on Windows",
)
@pytest.mark.parametrize("linked", ["output", "reports"])
@patch("automated_security_helper.cli.report.load_plugins")
@patch("automated_security_helper.cli.report.resolve_config")
@patch("automated_security_helper.cli.report.ash_plugin_manager")
@patch("automated_security_helper.cli.report.PluginContext")
@patch("automated_security_helper.cli.report.AshAggregatedResults")
def test_a_linked_output_or_reports_directory_is_refused(
    _mock_results_class,
    _mock_plugin_context,
    mock_plugin_manager,
    _mock_resolve_config,
    _mock_load_plugins,
    linked,
    tmp_path,
    monkeypatch,
    capfd,
):
    """Reporters write into reports/ here without a scan's clean-up first.

    The refusal is on stderr, where the command prints its errors, and stdout
    holds no part of it.
    """
    host = tmp_path / "host"
    host.mkdir()
    results = {"metadata": {"summary_stats": {"actionable": 0}}}
    output_dir = tmp_path / "out"
    if linked == "output":
        output_dir.symlink_to(host, target_is_directory=True)
        (host / "ash_aggregated_results.json").write_text(json.dumps(results))
    else:
        output_dir.mkdir()
        (output_dir / "ash_aggregated_results.json").write_text(json.dumps(results))
        (output_dir / "reports").symlink_to(host, target_is_directory=True)
    plugin = MagicMock()
    plugin.config.name = "text"
    plugin.report.return_value = "rendered"
    plugin_class = MagicMock(return_value=plugin)
    plugin_class.__name__ = "MockTextReporter"
    mock_plugin_manager.plugin_modules.return_value = [plugin_class]
    monkeypatch.chdir(tmp_path)

    with pytest.raises(typer.Exit) as exited:
        report_command(report_format="text", output_dir=str(output_dir))

    assert exited.value.exit_code == 3
    out, err = capfd.readouterr()
    refusal = _squeezed(err)
    assert _squeezed("is a symlink") in refusal and "--output-dir" in refusal, err
    assert "is a symlink" not in out, out
    assert "[red]" not in out + err and "[/red]" not in out + err
    plugin.report.assert_not_called()
